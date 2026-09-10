/**
 * Keyboard-interactive authentication (RFC 4256).
 *
 * Servers configured with `AuthenticationMethods keyboard-interactive` — the
 * usual shape of a Google Authenticator / PAM two-factor setup — offer neither
 * `password` nor `publickey`. Instead the server drives a conversation: it
 * sends one or more prompts, the client answers, and the server may ask again
 * (typically a verification code, then a password).
 *
 * Nothing here is persisted. A TOTP code is valid for about 30 seconds, so the
 * answers are typed by the user at connection time and never stored.
 */

import type { SessionInfo } from '../stores/sessionStore';

/** A single question asked by the server. */
export interface KeyboardInteractivePrompt {
  /** Label to display, e.g. `"Verification code: "`. */
  prompt: string;
  /**
   * When `false`, the answer must be masked in the UI (passwords, PINs).
   * The server sets this per prompt; it is not a guess on our side.
   */
  echo: boolean;
}

/** Authentication succeeded; the session is connected and ready to attach. */
export interface KeyboardInteractiveAuthenticated {
  kind: 'authenticated';
  authId: string;
  session: SessionInfo;
}

/**
 * The server refused the answers. The backend has already discarded the
 * connection, so retrying means starting a brand new exchange.
 */
export interface KeyboardInteractiveRejected {
  kind: 'rejected';
  authId: string;
}

/** The server is asking for input. One answer per prompt, in order. */
export interface KeyboardInteractivePrompts {
  kind: 'prompts';
  authId: string;
  /** Optional title supplied by the server (often empty). */
  name: string;
  /** Optional instructions supplied by the server (often empty). */
  instructions: string;
  prompts: KeyboardInteractivePrompt[];
}

/** One step of a keyboard-interactive conversation. */
export type KeyboardInteractiveStep =
  | KeyboardInteractiveAuthenticated
  | KeyboardInteractiveRejected
  | KeyboardInteractivePrompts;
