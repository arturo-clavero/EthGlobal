import { useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';
import { SessionManager } from '../../offscreen/SessionManager';
import { logger } from '@tlsn/common';
import { getStoredLogLevel } from '../../utils/logLevelStorage';
import type { OffscreenMessage } from '../../types/messages';
import { prepareBuiltInRun, readPackagedFile } from '../../offscreen/builtinRun';
import { runSessionData } from '../../offscreen/pluginHash';
import { createGcpPrivateModule } from '../../gcp-private/browser-client.mjs';
import { gcpPrivateDiagnostic } from '../../offscreen/gcpPrivateWitness';

const OffscreenApp: React.FC = () => {
  useEffect(() => {
    // Initialize logger with stored log level
    getStoredLogLevel().then((level) => {
      logger.init(level);
      logger.info('Offscreen document loaded');
    });

    // Initialize SessionManager
    const sessionManager = new SessionManager();
    let privateGcpRunning = false;
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
          const execute = async (privateModule?: ReturnType<typeof createGcpPrivateModule>) => {
            const sm = await sessionManager.awaitInit();
            return sm.executePlugin(prepared.code, request.requestId ?? undefined,
              runSessionData(request.sessionData, prepared.sha256), privateModule);
          };
          if (request.pluginId === 'gcp-work') {
            if (privateGcpRunning || !request.requestId) {
              gcpPrivateDiagnostic(privateGcpRunning ? 'RUN_BUSY' : 'RUN_ID_MISSING');
              return { success: false, error: 'GCP_PRIVATE_PROVING_FAILED' };
            }
            let privateModule: ReturnType<typeof createGcpPrivateModule>;
            try {
              const params = JSON.parse(request.values.params);
              if (!params || typeof params !== 'object' || !params.privateInput ||
                  Object.keys(params.privateInput).length !== 1 || typeof params.privateInput.projectId !== 'string') throw new Error();
              privateModule = createGcpPrivateModule({
                projectId: params.privateInput.projectId,
                policy: { cutoff: params.cutoff, windowDays: params.windowDays },
                workerUrl: browser.runtime.getURL('gcp-private/browser-worker.js'),
                onProgress: ({ completedProofs }) => {
                  browser.runtime.sendMessage({ type: 'PLUGIN_PROGRESS', requestId: request.requestId,
                    progress: { method: 'GCP_WORK', status: 'busy', index: completedProofs, total: 128 } }).catch(() => {});
                },
              });
            } catch {
              gcpPrivateDiagnostic('MODULE_FAILED');
              return { success: false, error: 'GCP_PRIVATE_PROVING_FAILED' };
            }
            privateGcpRunning = true;
            const heartbeat = setInterval(() => {
              browser.runtime.sendMessage({ type: 'GCP_PRIVATE_HEARTBEAT', requestId: request.requestId })
                .then(reply => {
                  if (!reply || typeof reply !== 'object' || !('ok' in reply) || reply.ok !== true) {
                    gcpPrivateDiagnostic('HEARTBEAT_NOT_OK'); privateModule.clear();
                  }
                }).catch(() => { gcpPrivateDiagnostic('HEARTBEAT_REJECTED'); privateModule.clear(); });
            }, 20_000);
            // Return the acknowledgement before awaiting capture/proving: one
            // service-worker request must not remain open past Chrome's five minutes.
            void (async () => {
              try {
                const result = await execute(privateModule);
                await browser.runtime.sendMessage({ type: 'GCP_PRIVATE_COMPLETE', requestId: request.requestId, success: true, result });
              } catch {
                gcpPrivateDiagnostic('EXECUTE_FAILED');
                await browser.runtime.sendMessage({ type: 'GCP_PRIVATE_COMPLETE', requestId: request.requestId,
                  success: false, error: 'GCP_PRIVATE_PROVING_FAILED' }).catch(() => {});
              } finally { clearInterval(heartbeat); privateModule.clear(); privateGcpRunning = false; }
            })();
            return { success: true, pending: true, requestId: request.requestId };
          }
          try {
            const result = await execute();
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
