//! Terminal-side of keyboard-interactive (RFC 4256) authentication.
//!
//! Servers configured with `AuthenticationMethods keyboard-interactive` — the
//! usual shape of a Google Authenticator / PAM two-factor setup — offer neither
//! `password` nor `publickey`. There is nothing to store for them either: the
//! answer is a code that expires in about 30 seconds.
//!
//! So the exchange is driven here, with a human at the keyboard, exactly like
//! `ssh` does it. Once it succeeds the session belongs to the background
//! service like any other, which means an agent can reuse it afterwards by
//! alias without ever handling the second factor itself.

use std::io::{self, BufRead, IsTerminal, Write};

use anyhow::{bail, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use vibeshell_core::ipc::IpcMessage;
use vibeshell_core::ssh::KeyboardInteractivePrompt;

use crate::ipc_support;

/// Run the whole conversation for `server_name` and return the session id.
///
/// Returns `Ok(None)` when the server does not offer keyboard-interactive at
/// all, so the caller can report its original error instead of this one.
pub fn authenticate(server_name: &str) -> Result<Option<String>> {
    if !io::stdin().is_terminal() {
        // No human to answer the prompts. Say so plainly rather than hanging
        // on a read that will never be satisfied.
        return Ok(None);
    }

    let mut response = ipc_support::send(&IpcMessage::StartKeyboardInteractive {
        server_name: server_name.to_string(),
        cols: Some(80),
        rows: Some(24),
    })?;

    let mut announced = false;

    loop {
        match response {
            IpcMessage::SessionCreated { session_id } => return Ok(Some(session_id)),
            IpcMessage::KeyboardInteractiveRejected => {
                bail!(
                    "Server '{}' rejected the code or password. Nothing was saved; run the \
                     command again to retry.",
                    server_name
                )
            }
            IpcMessage::KeyboardInteractivePrompts {
                auth_id,
                name,
                instructions,
                prompts,
                auto_answered,
            } => {
                if !announced {
                    eprintln!(
                        "Server '{}' requires two-factor authentication (keyboard-interactive).",
                        server_name
                    );
                    announced = true;
                }

                for label in &auto_answered {
                    eprintln!("  {} answered from your saved credentials.", label);
                }

                let answers = match collect_answers(&name, &instructions, &prompts) {
                    Ok(answers) => answers,
                    Err(error) => {
                        // Never leave a half-authenticated connection behind.
                        let _ = ipc_support::send(&IpcMessage::CancelKeyboardInteractive {
                            auth_id: auth_id.clone(),
                        });
                        return Err(error);
                    }
                };

                response = ipc_support::send(&IpcMessage::RespondKeyboardInteractive {
                    auth_id,
                    responses: answers,
                })?;
            }
            IpcMessage::Error { message } => {
                // The server not offering keyboard-interactive is not a failure
                // of this path; it means this path did not apply.
                if message.contains("no more auth methods")
                    || message.contains("Unable to authenticate")
                    || message.contains("not supported")
                {
                    return Ok(None);
                }
                bail!("{}", message)
            }
            other => bail!(
                "Unexpected response from background service: {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }
}

/// Ask the user one answer per prompt, in the order the server sent them.
fn collect_answers(
    name: &str,
    instructions: &str,
    prompts: &[KeyboardInteractivePrompt],
) -> Result<Vec<String>> {
    if !name.trim().is_empty() {
        eprintln!("{}", name.trim());
    }
    if !instructions.trim().is_empty() {
        eprintln!("{}", instructions.trim());
    }

    let mut answers = Vec::with_capacity(prompts.len());
    for prompt in prompts {
        let label = if prompt.prompt.trim().is_empty() {
            "Answer: ".to_string()
        } else {
            prompt.prompt.clone()
        };

        // `echo` is the server telling us whether the answer may appear on
        // screen. Honour it rather than guessing from the wording.
        let answer = if prompt.echo {
            read_visible(&label)?
        } else {
            read_hidden(&label)?
        };

        answers.push(answer);
    }

    Ok(answers)
}

fn read_visible(label: &str) -> Result<String> {
    eprint!("{}", label);
    io::stderr().flush()?;

    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line)? == 0 {
        bail!("Input ended before the prompt was answered");
    }

    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Read an answer without echoing it, restoring the terminal whatever happens.
fn read_hidden(label: &str) -> Result<String> {
    eprint!("{}", label);
    io::stderr().flush()?;

    terminal::enable_raw_mode()?;
    let result = read_hidden_raw();
    let _ = terminal::disable_raw_mode();
    eprintln!();

    result
}

/// What a key event means while an answer is being typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyAction {
    /// The answer is complete.
    Validate,
    /// Add this character to the answer.
    Append(char),
    /// Remove the last character.
    Erase,
    /// Clear what has been typed so far.
    Clear,
    /// Abandon the prompt.
    Cancel,
    /// Nothing to do.
    Ignore,
}

/// Decide what a key event means, with no terminal involved.
///
/// This is separate from the read loop so it can actually be tested. The
/// distinction that matters is `KeyEventKind`: on Windows, crossterm reports
/// key *releases* as well as presses. Ignoring that field made the release of
/// the Enter that launched the command count as "answer submitted", so the
/// prompt was answered with an empty string before the user could type
/// anything. Only presses and auto-repeats may act.
pub(crate) fn interpret_key(event: KeyEvent) -> KeyAction {
    if !matches!(event.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return KeyAction::Ignore;
    }

    match event.code {
        KeyCode::Enter => KeyAction::Validate,
        KeyCode::Backspace => KeyAction::Erase,
        KeyCode::Esc => KeyAction::Cancel,
        KeyCode::Char('c') if event.modifiers.contains(KeyModifiers::CONTROL) => KeyAction::Cancel,
        KeyCode::Char('u') if event.modifiers.contains(KeyModifiers::CONTROL) => KeyAction::Clear,
        // A bare Ctrl+<letter> is a control code, not text to type.
        KeyCode::Char(_) if event.modifiers.contains(KeyModifiers::CONTROL) => KeyAction::Ignore,
        KeyCode::Char(character) => KeyAction::Append(character),
        _ => KeyAction::Ignore,
    }
}

fn read_hidden_raw() -> Result<String> {
    // Anything already queued belongs to whatever happened before this prompt,
    // typically the Enter that launched the command. Discard it so it cannot
    // be mistaken for an answer.
    while event::poll(std::time::Duration::from_millis(0))? {
        let _ = event::read()?;
    }

    let mut answer = String::new();

    loop {
        let Event::Key(key) = event::read()? else {
            continue;
        };

        match interpret_key(key) {
            KeyAction::Validate => return Ok(answer),
            KeyAction::Append(character) => answer.push(character),
            KeyAction::Erase => {
                answer.pop();
            }
            KeyAction::Clear => answer.clear(),
            KeyAction::Cancel => bail!("Cancelled"),
            KeyAction::Ignore => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode, kind: KeyEventKind) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, kind)
    }

    /// The bug this whole function exists to prevent: on Windows the release of
    /// the Enter that launched the command arrives as soon as raw mode starts,
    /// and used to submit an empty answer before anything could be typed.
    #[test]
    fn releasing_enter_does_not_submit_the_answer() {
        assert_eq!(
            interpret_key(key(KeyCode::Enter, KeyEventKind::Release)),
            KeyAction::Ignore
        );
        assert_eq!(
            interpret_key(key(KeyCode::Enter, KeyEventKind::Press)),
            KeyAction::Validate
        );
    }

    #[test]
    fn releasing_a_character_does_not_type_it_twice() {
        assert_eq!(
            interpret_key(key(KeyCode::Char('7'), KeyEventKind::Press)),
            KeyAction::Append('7')
        );
        assert_eq!(
            interpret_key(key(KeyCode::Char('7'), KeyEventKind::Release)),
            KeyAction::Ignore
        );
    }

    #[test]
    fn auto_repeat_still_types() {
        assert_eq!(
            interpret_key(key(KeyCode::Char('x'), KeyEventKind::Repeat)),
            KeyAction::Append('x')
        );
    }

    #[test]
    fn editing_keys_behave() {
        assert_eq!(
            interpret_key(key(KeyCode::Backspace, KeyEventKind::Press)),
            KeyAction::Erase
        );
        assert_eq!(
            interpret_key(key(KeyCode::Esc, KeyEventKind::Press)),
            KeyAction::Cancel
        );
    }

    #[test]
    fn control_combinations_are_not_typed_into_the_answer() {
        let ctrl = |c| {
            KeyEvent::new_with_kind(KeyCode::Char(c), KeyModifiers::CONTROL, KeyEventKind::Press)
        };
        assert_eq!(interpret_key(ctrl('c')), KeyAction::Cancel);
        assert_eq!(interpret_key(ctrl('u')), KeyAction::Clear);
        // Ctrl+A must not append a literal 'a' to a password.
        assert_eq!(interpret_key(ctrl('a')), KeyAction::Ignore);
    }
}
