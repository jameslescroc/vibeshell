import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Server } from '../../stores/serverStore';
import { useSessionStore } from '../../stores/sessionStore';
import type { KeyboardInteractiveStep } from '../../types/keyboardInteractive';
import { KeyboardInteractiveDialog } from './KeyboardInteractiveDialog';

const twoFactorServer: Server = {
  id: 'two-factor-server',
  name: 'backup',
  host: '203.0.113.10',
  port: 22,
  username: 'root',
  auth_type: 'password',
  tags: [],
  created_at: 1,
  updated_at: 1,
};

const startKeyboardInteractive = vi.fn();
const respondKeyboardInteractive = vi.fn();
const cancelKeyboardInteractive = vi.fn();

function promptsStep(
  authId: string,
  prompts: { prompt: string; echo: boolean }[],
  instructions = '',
  autoAnswered: string[] = []
): KeyboardInteractiveStep {
  return { kind: 'prompts', authId, name: '', instructions, prompts, autoAnswered };
}

describe('KeyboardInteractiveDialog', () => {
  beforeEach(() => {
    startKeyboardInteractive.mockReset();
    respondKeyboardInteractive.mockReset();
    cancelKeyboardInteractive.mockReset().mockResolvedValue(undefined);

    useSessionStore.setState({
      startKeyboardInteractive,
      respondKeyboardInteractive,
      cancelKeyboardInteractive,
    });
  });

  afterEach(cleanup);

  it('masks answers the server marks as non-echoing and shows the others', async () => {
    startKeyboardInteractive.mockResolvedValue(
      promptsStep('auth-1', [
        { prompt: 'Verification code: ', echo: true },
        { prompt: 'Password: ', echo: false },
      ])
    );

    render(
      <KeyboardInteractiveDialog
        isOpen
        server={twoFactorServer}
        onClose={() => {}}
        onConnected={() => {}}
      />
    );

    const code = await screen.findByLabelText('Verification code:');
    const password = await screen.findByLabelText('Password:');

    // echo === true means the server explicitly allows showing the answer.
    expect(code).toHaveAttribute('type', 'text');
    // echo === false is the server telling us to mask it.
    expect(password).toHaveAttribute('type', 'password');
  });

  it('lets a masked answer be revealed on demand', async () => {
    startKeyboardInteractive.mockResolvedValue(
      promptsStep('auth-1', [{ prompt: 'Password: ', echo: false }])
    );

    render(
      <KeyboardInteractiveDialog
        isOpen
        server={twoFactorServer}
        onClose={() => {}}
        onConnected={() => {}}
      />
    );

    const password = await screen.findByLabelText('Password:');
    expect(password).toHaveAttribute('type', 'password');

    fireEvent.click(screen.getByRole('button', { name: 'Show answer' }));
    expect(password).toHaveAttribute('type', 'text');
  });

  it('sends the answers in prompt order and follows a second round', async () => {
    startKeyboardInteractive.mockResolvedValue(
      promptsStep('auth-1', [{ prompt: 'Verification code: ', echo: true }])
    );
    respondKeyboardInteractive.mockResolvedValue(
      promptsStep('auth-1', [{ prompt: 'Password: ', echo: false }])
    );

    render(
      <KeyboardInteractiveDialog
        isOpen
        server={twoFactorServer}
        onClose={() => {}}
        onConnected={() => {}}
      />
    );

    const code = await screen.findByLabelText('Verification code:');
    fireEvent.change(code, { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Submit' }));

    await waitFor(() => {
      expect(respondKeyboardInteractive).toHaveBeenCalledWith('auth-1', ['123456']);
    });

    // The second round replaces the fields instead of stacking them.
    expect(await screen.findByLabelText('Password:')).toBeInTheDocument();
    expect(screen.queryByLabelText('Verification code:')).not.toBeInTheDocument();
  });

  it('reports the session and closes once the server accepts', async () => {
    const onConnected = vi.fn();
    const onClose = vi.fn();

    startKeyboardInteractive.mockResolvedValue(
      promptsStep('auth-1', [{ prompt: 'Verification code: ', echo: true }])
    );
    respondKeyboardInteractive.mockResolvedValue({
      kind: 'authenticated',
      authId: 'auth-1',
      session: {
        id: 'session-42',
        server_id: 'two-factor-server',
        server_name: 'backup',
        state: 'connected',
        created_at: 1,
        clients: 1,
      },
    } satisfies KeyboardInteractiveStep);

    render(
      <KeyboardInteractiveDialog
        isOpen
        server={twoFactorServer}
        onClose={onClose}
        onConnected={onConnected}
      />
    );

    fireEvent.change(await screen.findByLabelText('Verification code:'), {
      target: { value: '123456' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Submit' }));

    await waitFor(() => {
      expect(onConnected).toHaveBeenCalledWith('session-42');
    });
    expect(onClose).toHaveBeenCalled();
  });

  it('explains a rejection instead of leaving stale prompts on screen', async () => {
    startKeyboardInteractive.mockResolvedValue(
      promptsStep('auth-1', [{ prompt: 'Verification code: ', echo: true }])
    );
    respondKeyboardInteractive.mockResolvedValue({
      kind: 'rejected',
      authId: 'auth-1',
    } satisfies KeyboardInteractiveStep);

    render(
      <KeyboardInteractiveDialog
        isOpen
        server={twoFactorServer}
        onClose={() => {}}
        onConnected={() => {}}
      />
    );

    fireEvent.change(await screen.findByLabelText('Verification code:'), {
      target: { value: '000000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Submit' }));

    expect(await screen.findByText(/rejected the code or password/i)).toBeInTheDocument();
    expect(screen.queryByLabelText('Verification code:')).not.toBeInTheDocument();
  });

  it('says which prompts were answered from the saved credentials', async () => {
    startKeyboardInteractive.mockResolvedValue(
      promptsStep('auth-1', [{ prompt: 'Verification code: ', echo: true }], '', ['Password:'])
    );

    render(
      <KeyboardInteractiveDialog
        isOpen
        server={twoFactorServer}
        onClose={() => {}}
        onConnected={() => {}}
      />
    );

    // Otherwise the password step silently vanishing looks like a bug.
    expect(await screen.findByText(/Password: answered from your saved credentials/i))
      .toBeInTheDocument();
  });

  it('cancels the half-authenticated exchange when the user backs out', async () => {
    startKeyboardInteractive.mockResolvedValue(
      promptsStep('auth-1', [{ prompt: 'Verification code: ', echo: true }])
    );

    render(
      <KeyboardInteractiveDialog
        isOpen
        server={twoFactorServer}
        onClose={() => {}}
        onConnected={() => {}}
      />
    );

    await screen.findByLabelText('Verification code:');
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    await waitFor(() => {
      expect(cancelKeyboardInteractive).toHaveBeenCalledWith('auth-1');
    });
  });

  it('starts exactly one exchange even though StrictMode double-invokes effects', async () => {
    startKeyboardInteractive.mockResolvedValue(
      promptsStep('auth-1', [{ prompt: 'Verification code: ', echo: true }])
    );

    const { rerender } = render(
      <KeyboardInteractiveDialog
        isOpen
        server={twoFactorServer}
        onClose={() => {}}
        onConnected={() => {}}
      />
    );

    rerender(
      <KeyboardInteractiveDialog
        isOpen
        server={twoFactorServer}
        onClose={() => {}}
        onConnected={() => {}}
      />
    );

    await screen.findByLabelText('Verification code:');
    // A second start would burn a second one-time code.
    expect(startKeyboardInteractive).toHaveBeenCalledTimes(1);
  });
});
