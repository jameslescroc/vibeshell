import { useCallback, useEffect, useRef, useState } from 'react';
import { X, ShieldCheck, Eye, EyeOff } from 'lucide-react';
import { cn } from '../../lib/utils';
import { useSessionStore } from '../../stores/sessionStore';
import type { Server } from '../../stores/serverStore';
import type {
  KeyboardInteractivePrompt,
  KeyboardInteractiveStep,
} from '../../types/keyboardInteractive';

interface KeyboardInteractiveDialogProps {
  isOpen: boolean;
  server: Server | null;
  onClose: () => void;
  onConnected: (sessionId: string) => void;
}

/**
 * Two-factor / keyboard-interactive (RFC 4256) authentication dialog.
 *
 * The server drives this exchange: it sends a batch of prompts, we answer, and
 * it may send another batch (the usual "verification code", then "password"
 * sequence). The dialog therefore renders whatever the server asked for rather
 * than a fixed set of fields, and re-renders on every round.
 *
 * Answers are never stored: a TOTP code expires in about 30 seconds.
 */
export function KeyboardInteractiveDialog({
  isOpen,
  server,
  onClose,
  onConnected,
}: KeyboardInteractiveDialogProps) {
  const { startKeyboardInteractive, respondKeyboardInteractive, cancelKeyboardInteractive } =
    useSessionStore();

  const [authId, setAuthId] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [instructions, setInstructions] = useState('');
  const [prompts, setPrompts] = useState<KeyboardInteractivePrompt[]>([]);
  const [answers, setAnswers] = useState<string[]>([]);
  const [revealed, setRevealed] = useState<boolean[]>([]);
  const [isBusy, setIsBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // React StrictMode runs effects twice in development. Starting the exchange
  // twice would open two SSH connections and consume two one-time codes, so
  // the start is guarded by a ref rather than by state.
  const startedForRef = useRef<string | null>(null);
  // Kept in a ref so the unmount cleanup can cancel without re-running.
  const authIdRef = useRef<string | null>(null);

  const applyStep = useCallback(
    (step: KeyboardInteractiveStep): void => {
      setAuthId(step.authId);
      authIdRef.current = step.authId;

      if (step.kind === 'authenticated') {
        setPrompts([]);
        setAnswers([]);
        setRevealed([]);
        authIdRef.current = null;
        onConnected(step.session.id);
        onClose();
        return;
      }

      if (step.kind === 'rejected') {
        // The backend has already dropped the connection; a retry has to open
        // a fresh exchange, so no authId is kept.
        authIdRef.current = null;
        setAuthId(null);
        setPrompts([]);
        setAnswers([]);
        setRevealed([]);
        setError('The server rejected the code or password. Close and try again.');
        return;
      }

      setName(step.name);
      setInstructions(step.instructions);

      if (step.prompts.length === 0) {
        // The backend answers message-only rounds (RFC 4256 allows an info
        // request with no prompts) on its own, so this should be unreachable.
        // Fail visibly rather than render a dialog with no fields and a
        // permanently disabled button, which is indistinguishable from a hang.
        setPrompts([]);
        setAnswers([]);
        setRevealed([]);
        setError('The server sent nothing to answer. Close the dialog and try again.');
        return;
      }

      setPrompts(step.prompts);
      setAnswers(step.prompts.map(() => ''));
      setRevealed(step.prompts.map(() => false));
    },
    [onClose, onConnected]
  );

  // Start the exchange when the dialog opens.
  useEffect(() => {
    if (!isOpen || !server) {
      return;
    }

    if (startedForRef.current === server.name) {
      return;
    }
    startedForRef.current = server.name;

    setAuthId(null);
    authIdRef.current = null;
    setName('');
    setInstructions('');
    setPrompts([]);
    setAnswers([]);
    setRevealed([]);
    setError(null);
    setIsBusy(true);

    void (async () => {
      const step = await startKeyboardInteractive(server.name);
      setIsBusy(false);
      if (!step) {
        setError('Could not start two-factor authentication. Check the server and try again.');
        return;
      }
      applyStep(step);
    })();
  }, [isOpen, server, startKeyboardInteractive, applyStep]);

  // Allow a fresh start the next time the dialog is opened.
  useEffect(() => {
    if (!isOpen) {
      startedForRef.current = null;
    }
  }, [isOpen]);

  // Never leave a half-authenticated connection behind.
  useEffect(() => {
    return () => {
      const pending = authIdRef.current;
      if (pending) {
        authIdRef.current = null;
        void cancelKeyboardInteractive(pending);
      }
    };
  }, [cancelKeyboardInteractive]);

  const handleCancel = useCallback(() => {
    const pending = authIdRef.current;
    if (pending) {
      authIdRef.current = null;
      void cancelKeyboardInteractive(pending);
    }
    onClose();
  }, [cancelKeyboardInteractive, onClose]);

  const handleSubmit = useCallback(async () => {
    if (!authId || isBusy || prompts.length === 0) {
      return;
    }

    setIsBusy(true);
    setError(null);

    const step = await respondKeyboardInteractive(authId, answers);

    setIsBusy(false);
    if (!step) {
      setError('Authentication failed. Close and try again.');
      return;
    }
    applyStep(step);
  }, [authId, answers, isBusy, prompts.length, respondKeyboardInteractive, applyStep]);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      if (event.key === 'Enter' && !isBusy) {
        void handleSubmit();
      }
    },
    [handleSubmit, isBusy]
  );

  if (!isOpen || !server) return null;

  const canSubmit = prompts.length > 0 && !isBusy;

  return (
    <div className="responsive-dialog-layer fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60" onClick={handleCancel} />

      {/* Dialog */}
      <div className="responsive-dialog-panel relative min-w-0 bg-tokyo-bg-dark border border-tokyo-bg-hl rounded-lg shadow-xl w-full max-w-md mx-3 sm:mx-4">
        {/* Header */}
        <div className="responsive-dialog-header flex items-center justify-between gap-3 px-4 py-3 border-b border-tokyo-bg-hl">
          <div className="flex min-w-0 items-center gap-3">
            <ShieldCheck className="w-5 h-5 text-tokyo-purple" />
            <h2 className="min-w-0 text-lg font-semibold text-tokyo-fg">
              Two-Factor Authentication
            </h2>
          </div>
          <button
            className="p-1 rounded-md text-tokyo-comment hover:text-tokyo-fg hover:bg-tokyo-bg-hl transition-colors"
            onClick={handleCancel}
            aria-label="Close two-factor dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4">
          {/* Server info */}
          <div className="p-3 rounded-md bg-tokyo-bg border border-tokyo-bg-hl">
            <div className="text-sm text-tokyo-comment">Connecting to</div>
            <div className="break-words text-tokyo-fg font-medium">{server.name}</div>
            <div className="break-all text-sm text-tokyo-comment mt-1">
              {server.username}@{server.host}:{server.port}
            </div>
          </div>

          {/* Server-supplied title and instructions */}
          {name.trim() !== '' && (
            <div className="text-sm font-medium text-tokyo-fg break-words">{name}</div>
          )}
          {instructions.trim() !== '' && (
            <div className="p-3 rounded-md bg-tokyo-blue/10 border border-tokyo-blue/30 text-tokyo-blue text-sm whitespace-pre-wrap break-words">
              {instructions}
            </div>
          )}

          {error && (
            <div className="p-3 rounded-md bg-tokyo-red/10 border border-tokyo-red/30 text-tokyo-red text-sm">
              {error}
            </div>
          )}

          {isBusy && prompts.length === 0 && (
            <div className="p-3 rounded-md bg-tokyo-bg border border-tokyo-bg-hl text-tokyo-comment text-sm">
              Waiting for the server...
            </div>
          )}

          {/* One field per prompt, in the order the server sent them */}
          {prompts.map((item, index) => {
            const fieldId = `keyboard-interactive-${index}`;
            const isSecret = !item.echo;
            const isRevealed = revealed[index] ?? false;

            return (
              <div key={fieldId}>
                <label
                  htmlFor={fieldId}
                  className="block text-sm font-medium text-tokyo-fg mb-1 break-words"
                >
                  {item.prompt.trim() === '' ? `Answer ${index + 1}` : item.prompt.trim()}
                </label>
                <div className="relative">
                  <input
                    id={fieldId}
                    type={isSecret && !isRevealed ? 'password' : 'text'}
                    value={answers[index] ?? ''}
                    onChange={(event) => {
                      const next = event.target.value;
                      setAnswers((current) =>
                        current.map((value, position) => (position === index ? next : value))
                      );
                      setError(null);
                    }}
                    onKeyDown={handleKeyDown}
                    autoFocus={index === 0}
                    autoComplete="off"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    disabled={isBusy}
                    className={cn(
                      'w-full px-3 py-2 rounded-md',
                      isSecret ? 'pr-10' : '',
                      'bg-tokyo-bg border border-tokyo-bg-hl',
                      'text-tokyo-fg placeholder-tokyo-comment',
                      'focus:outline-none focus:ring-1 focus:ring-tokyo-blue focus:border-tokyo-blue',
                      'disabled:opacity-50'
                    )}
                  />
                  {isSecret && (
                    <button
                      type="button"
                      onClick={() =>
                        setRevealed((current) =>
                          current.map((value, position) =>
                            position === index ? !value : value
                          )
                        )
                      }
                      aria-label={isRevealed ? 'Hide answer' : 'Show answer'}
                      className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-tokyo-comment hover:text-tokyo-fg"
                    >
                      {isRevealed ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  )}
                </div>
              </div>
            );
          })}

          {/* Actions */}
          <div className="responsive-dialog-actions flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={handleCancel}
              className={cn(
                'px-4 py-2 rounded-md',
                'bg-tokyo-bg-hl text-tokyo-fg',
                'hover:bg-tokyo-bg hover:text-tokyo-fg',
                'transition-colors'
              )}
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => void handleSubmit()}
              disabled={!canSubmit}
              className={cn(
                'px-4 py-2 rounded-md',
                'bg-tokyo-blue text-tokyo-on-accent',
                'hover:bg-tokyo-blue/80',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                'transition-colors'
              )}
            >
              {isBusy ? 'Verifying...' : 'Submit'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
