import { useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';
import { SessionManager } from '../../offscreen/SessionManager';
import { logger } from '@tlsn/common';
import { getStoredLogLevel } from '../../utils/logLevelStorage';
import type { OffscreenMessage } from '../../types/messages';
import { prepareBuiltInRun, readPackagedFile } from '../../offscreen/builtinRun';
import { runSessionData } from '../../offscreen/pluginHash';

const OffscreenApp: React.FC = () => {
  useEffect(() => {
    // Initialize logger with stored log level
    getStoredLogLevel().then((level) => {
      logger.init(level);
      logger.info('Offscreen document loaded');
    });

    // Initialize SessionManager
    const sessionManager = new SessionManager();
    logger.debug('SessionManager initialized in Offscreen');

    // Listen for messages from background script
    browser.runtime.onMessage.addListener((msg: unknown, sender: browser.Runtime.MessageSender) => {
      const request = msg as OffscreenMessage;
      // Example message handling
      if (request.type === 'PROCESS_DATA') {
        return Promise.resolve({
          success: true,
          data: 'Processed in offscreen',
        });
      }

      // Relay: inbound MPC bytes from the verifier (forwarded by the
      // background under a distinct type so each chunk is delivered exactly once
      // — the content script's runtime.sendMessage is ALSO broadcast directly to
      // this offscreen, so we must NOT also handle the raw RELAY_IN here).
      if (request.type === 'RELAY_DELIVER') {
        sessionManager.handleRelayIn(request.data as string);
        return;
      }
      if (request.type === 'RELAY_DELIVER_CLOSED') {
        sessionManager.handleRelayClosed();
        return;
      }

      // Run one of the built-in plugins. The
      // message carries the plugin id, fingerprint and values, never code; the
      // code is read from the package here (offscreen/builtinRun.ts). No
      // handler runs code taken from a message (the stock code-execution and
      // plugin-stats handlers are gone).
      if (request.type === 'RUN_BUILTIN_OFFSCREEN') {
        return prepareBuiltInRun(request, sender, {
          extensionId: browser.runtime.id,
          backgroundUrl: browser.runtime.getURL('background.bundle.js'),
          readPackaged: readPackagedFile,
        }).then(async (prepared) => {
          if ('error' in prepared) {
            logger.warn('RUN_BUILTIN_OFFSCREEN refused:', prepared.error);
            return { success: false, error: prepared.error, requestId: request.requestId };
          }
          try {
            const sm = await sessionManager.awaitInit();
            const result = await sm.executePlugin(
              prepared.code,
              request.requestId ?? undefined,
              // The runner reports the sha256 of the packaged plugin it runs.
              runSessionData(request.sessionData, prepared.sha256),
            );
            logger.debug('Plugin execution result:', result);
            return { success: true, result, requestId: request.requestId };
          } catch (error) {
            logger.error('Plugin execution error:', error);
            return {
              success: false,
              error: error instanceof Error ? error.message : String(error),
              requestId: request.requestId,
            };
          }
        });
      }
    });
  }, []);

  return (
    <div className="offscreen-container">
      <h1>Offscreen Document</h1>
      <p>This document runs in the background for processing tasks.</p>
    </div>
  );
};

const container = document.getElementById('app-container');
if (container) {
  const root = createRoot(container);
  root.render(<OffscreenApp />);
}
