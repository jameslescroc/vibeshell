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
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
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
            } => {
                if !announced {
                    eprintln!(
                        "Server '{}' requires two-factor authentication (keyboard-interactive).",
                        server_name
                    );
                    announced = true;
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

fn read_hidden_raw() -> Result<String> {
    let mut answer = String::new();

    loop {
        match event::read()? {
            Event::Key(KeyEvent {
                code, modifiers, ..
            }) => match code {
                KeyCode::Enter => return Ok(answer),
                KeyCode::Backspace => {
                    answer.pop();
                }
                KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                    bail!("Cancelled")
                }
                KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => {
                    answer.clear();
                }
                KeyCode::Char(character) => answer.push(character),
                KeyCode::Esc => bail!("Cancelled"),
                _ => {}
            },
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}
