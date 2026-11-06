/**
 * Type definitions for extension message passing.
 *
 * Each entry point handles a subset of these messages via
 * browser.runtime.onMessage / sendMessage.
 */

import type { DomJson } from '@tlsn/plugin-sdk';

/**
 * Controls how reveal approvals are handled during a plugin execution.
 * - `'manual'`      — user approves each `prove()` call before data is sent
 * - `'all-session'` — all reveals in this session are auto-approved
 * - `'rejected'`    — user denied the plugin; it does not run
 */
export type ApprovalMode = 'manual' | 'all-session' | 'rejected';

// ---------------------------------------------------------------------------
// Incoming messages (received by onMessage listeners)
// ---------------------------------------------------------------------------

/** Messages handled by the Background service worker */
export type BackgroundMessage =
  | { type: 'CONTENT_SCRIPT_READY' }
  | { type: 'PING' }
  | { type: 'RENDER_PLUGIN_UI'; json: DomJson; windowId: number }
  | { type: 'GET_PLUGIN_CODE'; requestId: string }
  | { type: 'PLUGIN_CONFIRM_RESPONSE'; requestId: string; mode: ApprovalMode }
  | {
      type: 'PROVE_PROGRESS';
      requestId: string;
      step: string;
      progress: number;
      message: string;
      source: string;
    }
  // Offscreen → background, auto-approved runs only.
  | { type: 'PLUGIN_PROGRESS'; requestId: string; progress: unknown }
  // Offscreen → background, auto-approved runs only (exact GitHub URLs).
  | { type: 'PLUGIN_NAVIGATE'; requestId: string; windowId: number; url: string }
  // Content script → background. Names one of
  // the extension's built-in plugins (id + fingerprint) and the run's values; no
  // code. Checked in the background from Chrome's sender (background/autoApproval.ts).
  | {
      type: 'RUN_BUILTIN';
      pluginId: unknown;
      fingerprint: unknown;
      verifierUrl: unknown;
      proxyUrl: unknown;
      params: unknown;
      // {<METHOD>: {verifierUrl, proxyUrl}}, one pair per proof in the window.
      methodUrls: unknown;
      requestId: unknown;
      sessionData: unknown;
    }
  | { type: 'CLOSE_WINDOW'; windowId: number }
  | {
      type: 'OPEN_WINDOW';
      url: string;
      width?: number;
      height?: number;
      showOverlay?: boolean;
    }
  | { type: 'TO_BG_RE_RENDER_PLUGIN_UI'; windowId: number }
  // Relay: page→extension inbound MPC bytes, and offscreen→tab outbound.
  | { type: 'RELAY_IN'; requestId: string; data: string }
  | { type: 'RELAY_OUT'; requestId: string; data: string }
  | { type: 'RELAY_CLOSED'; requestId: string };

/** Messages handled by the Content script */
export type ContentMessage =
  | { type: 'OFFSCREEN_LOG'; level: string; message: string }
  | {
      type: 'PROVE_PROGRESS';
      requestId: string;
      step: string;
      progress: number;
      message: string;
      source: string;
    }
  // Background → the run's own tab; posted to the page on allowed origins only.
  | { type: 'PLUGIN_PROGRESS'; requestId: string; progress: unknown }
  | { type: 'GET_PAGE_INFO' }
  | { type: 'RENDER_PLUGIN_UI'; json: DomJson; windowId: number }
  | { type: 'RELAY_OUT'; requestId: string; data: string };

/** Messages handled by the Offscreen document */
export type OffscreenMessage =
  | { type: 'PROCESS_DATA' }
  // Background → offscreen; the code is read from the
  // package in the offscreen document (offscreen/builtinRun.ts).
  | {
      type: 'RUN_BUILTIN_OFFSCREEN';
      azureDiscoverySelection?: unknown;
      pluginId: string;
      fingerprint: string;
      values: {
        verifierUrl: string;
        proxyUrl: string;
        params: string;
        methodUrls?: Record<string, { verifierUrl: string; proxyUrl: string }>;
      };
      requestId: string | null;
      sessionData: Record<string, string>;
    }
  // Forwarded by the background (distinct type so the offscreen handles each
  // inbound chunk exactly once — a content script's runtime.sendMessage is also
  // broadcast directly to the offscreen, which would otherwise double-deliver).
  | { type: 'RELAY_DELIVER'; data: string }
  | { type: 'RELAY_DELIVER_CLOSED' };

// ---------------------------------------------------------------------------
// Responses returned from sendMessage calls
// ---------------------------------------------------------------------------

export interface ExecCodeResponse {
  success: boolean;
  result?: unknown;
  error?: string;
  requestId?: string;
}

export interface PluginCodeResponse {
  code: string | null;
}
