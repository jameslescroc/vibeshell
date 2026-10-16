import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { needsKeyboardInteractive, preferKeyboardInteractive } from './ConnectDialog';

describe('ConnectDialog keyboard-interactive preference', () => {
  beforeEach(() => {
    const store = new Map<string, string>();
    vi.stubGlobal('localStorage', {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => store.set(key, value),
      removeItem: (key: string) => store.delete(key),
      clear: () => store.clear(),
    });
  });
  afterEach(() => vi.unstubAllGlobals());

  it('recognises the backend error from a saved-password connect to a 2FA server', () => {
    expect(
      needsKeyboardInteractive(
        'Server requires interactive authentication not supported by saved-password login'
      )
    ).toBe(true);
  });

  it('ignores ordinary connection failures', () => {
    expect(
      needsKeyboardInteractive("Authentication failed: server rejected credentials for user 'root'")
    ).toBe(false);
    expect(needsKeyboardInteractive(null)).toBe(false);
  });

  it('remembers the server so the dialog reopens in the 2FA flow', () => {
    preferKeyboardInteractive('backup');
    expect(window.localStorage.getItem('vibeshell.auth-method.backup')).toBe('keyboard-interactive');
  });
});
