import { beforeEach, describe, expect, it, vi } from 'vitest';

const { safeInvokeMock } = vi.hoisted(() => ({
  safeInvokeMock: vi.fn(),
}));

vi.mock('../lib/tauri', () => ({
  safeInvoke: safeInvokeMock,
  sendInputBatched: vi.fn(),
  fireAndForgetInvoke: vi.fn(),
  TauriError: class TauriError extends Error {},
}));

vi.mock('./notificationStore', () => ({
  useNotificationStore: {
    getState: () => ({
      error: vi.fn(),
      warning: vi.fn(),
    }),
  },
}));

import { useSessionStore } from './sessionStore';
import { useFingerprintStore } from './fingerprintStore';

const HOST_KEY_UNKNOWN =
  'HOST_KEY_UNKNOWN: the host key for 10.0.0.5:22 is not trusted; connection refused before authentication.\n' +
  'host: 10.0.0.5\nport: 22\npresented-fingerprint: SHA256:abc\npresented-key-type: ssh-ed25519';

const prompts = {
  kind: 'prompts',
  authId: 'auth-1',
  name: '',
  instructions: '',
  prompts: [{ prompt: 'Verification code: ', echo: false }],
  autoAnswered: [],
};

describe('sessionStore.startKeyboardInteractive host-key approval', () => {
  beforeEach(() => {
    safeInvokeMock.mockReset();
    useSessionStore.setState({ sessions: [], activeSessionId: null, loading: false, error: null });
  });

  it('asks to trust an unknown host key, then retries the exchange', async () => {
    const approval = vi.fn().mockResolvedValue(true);
    useFingerprintStore.setState({ requestHostKeyApproval: approval });
    safeInvokeMock
      .mockResolvedValueOnce({ success: false, error: { message: HOST_KEY_UNKNOWN } })
      .mockResolvedValueOnce({ success: true, data: prompts });

    const step = await useSessionStore.getState().startKeyboardInteractive('backup');

    expect(approval).toHaveBeenCalledWith(
      expect.objectContaining({ host: '10.0.0.5', port: 22, fingerprint: 'SHA256:abc' })
    );
    expect(safeInvokeMock).toHaveBeenCalledTimes(2);
    expect(step).toEqual(prompts);
  });

  it('does not retry when the host key is refused', async () => {
    useFingerprintStore.setState({ requestHostKeyApproval: vi.fn().mockResolvedValue(false) });
    safeInvokeMock.mockResolvedValueOnce({ success: false, error: { message: HOST_KEY_UNKNOWN } });

    const step = await useSessionStore.getState().startKeyboardInteractive('backup');

    expect(step).toBeNull();
    expect(safeInvokeMock).toHaveBeenCalledTimes(1);
    expect(useSessionStore.getState().error).toContain('host key not trusted');
  });
});
