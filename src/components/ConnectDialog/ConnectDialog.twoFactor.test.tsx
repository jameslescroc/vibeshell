import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useSessionStore } from '../../stores/sessionStore';
import type { Server } from '../../stores/serverStore';
import { ConnectDialog } from './ConnectDialog';

const safeInvokeMock = vi.hoisted(() => vi.fn());

vi.mock('../../lib/tauri', () => ({
  safeInvoke: safeInvokeMock,
}));

vi.mock('../KeyboardInteractiveDialog', () => ({
  KeyboardInteractiveDialog: () => <div data-testid="two-factor-dialog" />,
}));

const twoFactorServer: Server = {
  id: 'backup-id',
  name: 'backup',
  host: 'example.test',
  port: 22,
  username: 'root',
  auth_type: 'password',
  tags: [],
  created_at: 1,
  updated_at: 1,
};

describe('ConnectDialog password connect to a 2FA server', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
    });
    safeInvokeMock.mockReset().mockResolvedValue({ success: true, data: null });
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('continues in the 2FA dialog when the server asks for a code', async () => {
    const connectWithCredentials = vi.fn(async () => {
      useSessionStore.setState({
        error: 'Server requires interactive authentication not supported by saved-password login',
      });
      return null;
    });
    useSessionStore.setState({ connectWithCredentials });

    render(
      <ConnectDialog isOpen server={twoFactorServer} onClose={() => {}} onConnected={() => {}} />
    );

    fireEvent.change(await screen.findByPlaceholderText('Enter password...'), {
      target: { value: 'secret' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));

    await waitFor(() => expect(screen.getByTestId('two-factor-dialog')).toBeInTheDocument());
    expect(connectWithCredentials).toHaveBeenCalledOnce();
  });

  it('shows the error for an ordinary authentication failure', async () => {
    useSessionStore.setState({
      connectWithCredentials: vi.fn(async () => {
        useSessionStore.setState({ error: "Authentication failed: server rejected credentials for user 'root'" });
        return null;
      }),
    });

    render(
      <ConnectDialog isOpen server={twoFactorServer} onClose={() => {}} onConnected={() => {}} />
    );

    fireEvent.change(await screen.findByPlaceholderText('Enter password...'), {
      target: { value: 'wrong' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));

    await waitFor(() =>
      expect(screen.getByText('Failed to connect. Check your credentials and try again.')).toBeInTheDocument()
    );
    expect(screen.queryByTestId('two-factor-dialog')).not.toBeInTheDocument();
  });
});
