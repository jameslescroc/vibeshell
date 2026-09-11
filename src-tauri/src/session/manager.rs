use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::session::{Session, SessionInfo, SessionState};
use crate::ssh::{KeyboardInteractiveOutcome, KeyboardInteractivePrompt, PtyConfig, SshClient};
use crate::storage::{Database, Server};

/// How long a half-finished keyboard-interactive exchange is kept around while
/// waiting for the user to type the answers. Matches the inactivity timeout
/// used by `SshClient::connect_keyboard_interactive`, so both sides give up at
/// roughly the same moment instead of leaving a dangling registry entry.
const KEYBOARD_INTERACTIVE_TTL: Duration = Duration::from_secs(300);

/// Credentials for SSH authentication
#[derive(Debug, Clone)]
pub enum SshCredential {
    Password(String),
    PrivateKey {
        key: String,
        passphrase: Option<String>,
    },
}

impl SshCredential {
    /// Convert a device-local stored credential into the material required by
    /// the SSH engine. Imported profiles keep only a private-key path in the
    /// database; the key itself is read just before connecting.
    pub fn from_stored(credential: crate::storage::database::Credential) -> Result<Self> {
        match credential.auth_type.as_str() {
            "password" => Ok(Self::Password(credential.credential)),
            "key" | "key_with_passphrase" => {
                let key = if credential.credential.trim().is_empty() {
                    let key_path = credential.key_path.as_deref().ok_or_else(|| {
                        anyhow!(
                            "Private-key credential for '{}' has neither key data nor a key path",
                            credential.server_name
                        )
                    })?;
                    std::fs::read_to_string(key_path).with_context(|| {
                        format!(
                            "Failed to read private key for '{}' from {}",
                            credential.server_name, key_path
                        )
                    })?
                } else {
                    credential.credential
                };
                Ok(Self::PrivateKey {
                    key,
                    passphrase: credential.passphrase.filter(|value| !value.is_empty()),
                })
            }
            other => Err(anyhow!(
                "Unknown auth type '{}' for server '{}'",
                other,
                credential.server_name
            )),
        }
    }
}

/// A keyboard-interactive exchange that has started but is not finished: the
/// server asked something and we are waiting for the user's answers.
///
/// The SSH connection is already open and half-authenticated, so it has to be
/// carried across the `start` / `respond` command boundary. `SshClient` is
/// cheap to clone (it is a bundle of `Arc`s) but the SSH output receiver is
/// not, which is why the whole thing is owned by the registry and moved out
/// when the exchange finally succeeds.
struct PendingKeyboardInteractive {
    server_name: String,
    username: String,
    client: SshClient,
    output_rx: mpsc::Receiver<Vec<u8>>,
    pty_config: Option<PtyConfig>,
    started_at: Instant,
    /// The stored password is offered at most once per exchange. A server that
    /// asks again is rejecting it, and replaying it would burn login attempts
    /// in a loop.
    stored_password_used: bool,
}

/// Can this prompt be answered from the credential saved for the server?
///
/// Only a prompt the server marks as hidden and labels as a password
/// qualifies. This is a heuristic on server-supplied text, and it is meant to
/// fail closed: when it does not match, the human is asked, which is the
/// behaviour we had before. It must never be widened to echoing prompts, or a
/// stored password could be sent in answer to "Verification code:".
fn prompt_wants_stored_password(prompt: &KeyboardInteractivePrompt) -> bool {
    if prompt.echo {
        return false;
    }
    let label = prompt.prompt.to_lowercase();
    label.contains("password") || label.contains("mot de passe")
}

impl PendingKeyboardInteractive {
    fn is_expired(&self) -> bool {
        self.started_at.elapsed() >= KEYBOARD_INTERACTIVE_TTL
    }
}

/// One step of a keyboard-interactive conversation, as seen by callers of
/// [`SessionManager`].
///
/// This mirrors [`KeyboardInteractiveOutcome`] but carries the ready-to-use
/// [`Session`] on success, because authenticating is only half the job: the
/// shell still has to be opened and wired up before the caller can do anything
/// useful with it.
pub enum KeyboardInteractiveStep {
    /// Authentication succeeded and the session is connected and registered.
    Authenticated(Arc<Session>),
    /// The server refused the answers. The connection has been discarded.
    Rejected,
    /// The server is asking for more input.
    Prompts {
        name: String,
        instructions: String,
        prompts: Vec<KeyboardInteractivePrompt>,
        /// Labels of prompts that were answered from the saved credential
        /// without asking anyone. Reported so a caller can say so instead of
        /// leaving the user wondering what happened to the password step.
        auto_answered: Vec<String>,
    },
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, Arc<Session>>>>,
    /// Keyboard-interactive exchanges waiting for user input, keyed by auth id.
    pending_keyboard_interactive: Arc<RwLock<HashMap<String, PendingKeyboardInteractive>>>,
    database: Arc<Database>,
}

impl SessionManager {
    pub fn new(database: Arc<Database>) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_keyboard_interactive: Arc::new(RwLock::new(HashMap::new())),
            database,
        }
    }

    pub async fn list(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;
        let mut infos = Vec::new();
        for session in sessions.values() {
            infos.push(session.get_info().await);
        }
        infos
    }

    pub async fn get(&self, id: &str) -> Option<Arc<Session>> {
        let sessions = self.sessions.read().await;
        sessions.get(id).cloned()
    }

    /// Resolve a full session UUID or an unambiguous prefix for MCP callers.
    pub async fn resolve(&self, id: &str) -> Result<Arc<Session>> {
        if let Some(session) = self.sessions.read().await.get(id).cloned() {
            return Ok(session);
        }
        let needle = id.trim().to_ascii_lowercase();
        if needle.len() < 4 {
            return Err(anyhow::anyhow!("Session reference '{}' is too short", id));
        }
        let sessions = self.sessions.read().await;
        let matches: Vec<_> = sessions
            .values()
            .filter(|session| session.id.to_ascii_lowercase().starts_with(&needle))
            .cloned()
            .collect();
        match matches.as_slice() {
            [session] => Ok(session.clone()),
            [] => Err(anyhow::anyhow!("Session not found: {}", id)),
            _ => Err(anyhow::anyhow!("Ambiguous session reference: {}", id)),
        }
    }

    pub async fn find_reusable_by_server_name(&self, server_name: &str) -> Option<Arc<Session>> {
        // A session is only reusable if the server config has not changed since
        // the session was created. Otherwise stale connections would mask
        // config updates (host/port/auth edits appearing to "not apply").
        let server_updated_at = self
            .database
            .server_get_by_name(server_name)
            .ok()
            .flatten()
            .map(|server| server.updated_at)
            .unwrap_or(0);

        let sessions = {
            let sessions = self.sessions.read().await;
            sessions.values().cloned().collect::<Vec<_>>()
        };

        let mut reusable = Vec::new();
        for session in sessions {
            if session.server_name != server_name {
                continue;
            }

            if session.created_at() < server_updated_at {
                debug!(
                    "[SessionManager] Skipping stale session {} (server '{}' updated after session creation)",
                    session.id, server_name
                );
                continue;
            }

            if matches!(session.get_state().await, SessionState::Connected) {
                reusable.push(session);
            }
        }

        reusable
            .into_iter()
            .min_by_key(|session| session.created_at())
    }

    /// Kill all sessions belonging to a server. Returns the killed session ids
    /// so callers can clean up per-session state (e.g. SFTP caches).
    pub async fn kill_by_server_id(&self, server_id: &str) -> Result<Vec<String>> {
        let session_ids: Vec<String> = {
            let sessions = self.sessions.read().await;
            sessions
                .values()
                .filter(|session| session.server_id == server_id)
                .map(|session| session.id.clone())
                .collect()
        };

        for session_id in &session_ids {
            info!(
                "[SessionManager] Killing session {} for deleted server {}",
                session_id, server_id
            );
            self.kill(session_id).await?;
        }

        Ok(session_ids)
    }

    pub async fn reap_inactive_sessions(&self, max_idle: Duration) -> Result<Vec<String>> {
        let sessions = {
            let sessions = self.sessions.read().await;
            sessions.values().cloned().collect::<Vec<_>>()
        };

        let mut stale_ids = Vec::new();
        for session in sessions {
            if session.should_reap(max_idle).await {
                stale_ids.push(session.id.clone());
            }
        }

        for session_id in &stale_ids {
            info!(
                "[SessionManager] Reaping inactive session {} after {:?} idle",
                session_id, max_idle
            );
            self.kill(session_id).await?;
        }

        Ok(stale_ids)
    }

    pub async fn create(&self, server_id: &str) -> Result<Arc<Session>> {
        let server = self
            .database
            .server_get(server_id)?
            .ok_or_else(|| anyhow!("Server not found: {}", server_id))?;
        self.create_for_server(&server).await
    }

    pub async fn create_by_name(&self, server_name: &str) -> Result<Arc<Session>> {
        let server = self
            .database
            .server_get_by_name(server_name)?
            .ok_or_else(|| anyhow!("Server not found: {}", server_name))?;
        self.create_for_server(&server).await
    }

    async fn create_for_server(&self, server: &Server) -> Result<Arc<Session>> {
        // For backward compatibility, create a session in connecting state
        // The actual SSH connection should be done via create_with_credentials
        let (input_tx, _input_rx) = tokio::sync::mpsc::channel(256);
        let (output_tx, _) = tokio::sync::broadcast::channel(256);

        let session = Arc::new(Session::new(
            server.id.clone(),
            server.name.clone(),
            input_tx,
            output_tx,
        ));

        // Session stays in Connecting state until connect_session is called
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.id.clone(), session.clone());

        Ok(session)
    }

    /// Create a session and connect with provided credentials
    /// Supports jump host (ProxyJump) connections and post-login commands
    pub async fn create_with_credentials(
        &self,
        server_name: &str,
        credential: SshCredential,
        pty_config: Option<PtyConfig>,
    ) -> Result<Arc<Session>> {
        info!(
            "[SessionManager] Creating session for server '{}'",
            server_name
        );

        let server = self
            .database
            .server_get_by_name(server_name)?
            .ok_or_else(|| {
                error!("[SessionManager] Server not found: {}", server_name);
                anyhow!("Server not found: {}", server_name)
            })?;

        info!(
            "[SessionManager] Found server: {}@{}:{}",
            server.username, server.host, server.port
        );

        // Create channels for input/output
        let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (output_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(256);

        // Create a channel for SSH output that will be bridged to broadcast
        let (ssh_output_tx, mut ssh_output_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

        // Create the session
        let session = Arc::new(Session::new(
            server.id.clone(),
            server.name.clone(),
            input_tx,
            output_tx.clone(),
        ));

        info!("[SessionManager] Session created with ID: {}", session.id);

        // === Jump Host Support ===
        // If server has a jump_host_id, we connect through the jump host first
        let _jump_bridge_handle: Option<tokio::task::JoinHandle<()>> = if let Some(ref jump_id) =
            server.jump_host_id
        {
            info!(
                "[SessionManager] Server has jump host configured: {}",
                jump_id
            );

            let jump_server = self.database.server_get(jump_id)?.ok_or_else(|| {
                error!("[SessionManager] Jump host server not found: {}", jump_id);
                anyhow!("Jump host server not found: {}", jump_id)
            })?;

            info!(
                "[SessionManager] Jump host: {}@{}:{}",
                jump_server.username, jump_server.host, jump_server.port
            );

            // Get saved credentials for jump host
            let jump_cred = self
                .database
                .credential_get(&jump_server.name)?
                .ok_or_else(|| {
                    error!(
                        "[SessionManager] No saved credentials for jump host '{}'",
                        jump_server.name
                    );
                    anyhow!(
                        "No saved credentials for jump host '{}'. Please save credentials first.",
                        jump_server.name
                    )
                })?;

            // Create a separate SSH client for the jump host (with a dummy output channel)
            let (jump_output_tx, _jump_output_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
            let mut jump_ssh = SshClient::new(jump_output_tx);

            // Connect to jump host. Imported profiles may reference a local
            // key path instead of duplicating private-key contents in SQLite.
            match SshCredential::from_stored(jump_cred)? {
                SshCredential::Password(password) => {
                    info!("[SessionManager] Connecting to jump host with password...");
                    jump_ssh
                        .connect_password(
                            &jump_server.host,
                            jump_server.port,
                            &jump_server.username,
                            &password,
                        )
                        .await?;
                }
                SshCredential::PrivateKey { key, passphrase } => {
                    info!("[SessionManager] Connecting to jump host with key...");
                    jump_ssh
                        .connect_key(
                            &jump_server.host,
                            jump_server.port,
                            &jump_server.username,
                            &key,
                            passphrase.as_deref(),
                        )
                        .await?;
                }
            }

            info!("[SessionManager] Connected to jump host, opening tunnel to target...");

            // Open a direct-tcpip channel from jump host to the target server
            let jump_handle_arc = jump_ssh.session_arc();
            let forward_channel = {
                let handle_guard = jump_handle_arc.lock().await;
                let handle = handle_guard
                    .as_ref()
                    .ok_or_else(|| anyhow!("Jump host SSH session not available"))?;
                handle
                    .channel_open_direct_tcpip(&server.host, server.port as u32, "127.0.0.1", 0)
                    .await
                    .map_err(|e| anyhow!("Failed to open tunnel through jump host: {}", e))?
            };

            info!("[SessionManager] Tunnel through jump host established");

            // Create a local TCP listener bridge
            // The target SSH client will connect to this local port which bridges through the jump host
            let bridge_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let bridge_port = bridge_listener.local_addr()?.port();
            info!(
                "[SessionManager] Bridge listener on 127.0.0.1:{}",
                bridge_port
            );

            // Spawn bridge task
            let bridge_handle = tokio::spawn(async move {
                match bridge_listener.accept().await {
                    Ok((tcp_stream, _)) => {
                        // Use into_stream() for bidirectional channel I/O
                        let channel_stream = forward_channel.into_stream();
                        let (mut ch_reader, mut ch_writer) = tokio::io::split(channel_stream);
                        let (mut tcp_reader, mut tcp_writer) = tokio::io::split(tcp_stream);

                        let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(2);

                        // TCP -> SSH channel (to target through jump host)
                        let done1 = done_tx.clone();
                        let t2s = tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let mut buf = vec![0u8; 32768];
                            loop {
                                match tcp_reader.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if (ch_writer.write_all(&buf[..n]).await).is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            let _ = ch_writer.shutdown().await;
                            let _ = done1.send(()).await;
                        });

                        // SSH channel -> TCP (from target through jump host)
                        let done2 = done_tx;
                        let s2t = tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let mut buf = vec![0u8; 32768];
                            loop {
                                match ch_reader.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if (tcp_writer.write_all(&buf[..n]).await).is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            let _ = tcp_writer.shutdown().await;
                            let _ = done2.send(()).await;
                        });

                        done_rx.recv().await;
                        t2s.abort();
                        s2t.abort();
                    }
                    Err(e) => {
                        error!("[SessionManager] Bridge accept error: {}", e);
                    }
                }
                // Keep jump_ssh alive as long as this task runs
                drop(jump_ssh);
            });

            // Now connect the target SSH through our local bridge
            let mut ssh_client = SshClient::new(ssh_output_tx);
            info!(
                "[SessionManager] Connecting to target through bridge at 127.0.0.1:{}...",
                bridge_port
            );

            match credential {
                SshCredential::Password(password) => {
                    ssh_client
                        .connect_password("127.0.0.1", bridge_port, &server.username, &password)
                        .await?;
                }
                SshCredential::PrivateKey { key, passphrase } => {
                    ssh_client
                        .connect_key(
                            "127.0.0.1",
                            bridge_port,
                            &server.username,
                            &key,
                            passphrase.as_deref(),
                        )
                        .await?;
                }
            }

            info!("[SessionManager] Target SSH connected via jump host, opening shell...");
            ssh_client.open_shell(pty_config).await?;

            session.set_ssh_client(ssh_client).await;
            session.set_state(SessionState::Connected).await;

            Some(bridge_handle)
        } else {
            // === Direct Connection (no jump host) ===
            let mut ssh_client = SshClient::new(ssh_output_tx);

            info!("[SessionManager] Connecting SSH client...");
            match &credential {
                SshCredential::Password(_) => {
                    info!("[SessionManager] Using password authentication");
                }
                SshCredential::PrivateKey { passphrase, .. } => {
                    info!(
                        "[SessionManager] Using key authentication (passphrase: {})",
                        if passphrase.is_some() { "yes" } else { "no" }
                    );
                }
            }

            match credential {
                SshCredential::Password(password) => {
                    ssh_client
                        .connect_password(&server.host, server.port, &server.username, &password)
                        .await?;
                }
                SshCredential::PrivateKey { key, passphrase } => {
                    ssh_client
                        .connect_key(
                            &server.host,
                            server.port,
                            &server.username,
                            &key,
                            passphrase.as_deref(),
                        )
                        .await?;
                }
            }

            info!("[SessionManager] SSH connected, opening shell...");
            ssh_client.open_shell(pty_config).await?;

            session.set_ssh_client(ssh_client).await;
            session.set_state(SessionState::Connected).await;

            None
        };

        info!("[SessionManager] Shell opened successfully");

        // Spawn task to bridge SSH output to broadcast channel
        let session_for_output = session.clone();
        let session_id_for_output = session.id.clone();
        tokio::spawn(async move {
            debug!(
                "[SessionManager] Output bridge task started for session {}",
                session_id_for_output
            );
            while let Some(data) = ssh_output_rx.recv().await {
                session_for_output.publish_output(data).await;
            }
            debug!(
                "[SessionManager] Output bridge task ended for session {}",
                session_id_for_output
            );
        });

        // Spawn task to bridge input channel to SSH stdin
        let session_clone = session.clone();
        let session_id_for_input = session.id.clone();
        tokio::spawn(async move {
            debug!(
                "[SessionManager] Input bridge task started for session {}",
                session_id_for_input
            );
            while let Some(data) = input_rx.recv().await {
                if let Err(e) = session_clone.write_to_ssh(&data).await {
                    error!(
                        "[SessionManager] Error writing to SSH for session {}: {}",
                        session_id_for_input, e
                    );
                    break;
                }
            }
            debug!(
                "[SessionManager] Input bridge task ended for session {}",
                session_id_for_input
            );
        });

        // === Post-login Command ===
        if let Some(ref cmd) = server.post_login_command {
            if !cmd.trim().is_empty() {
                let session_for_cmd = session.clone();
                let cmd_str = cmd.clone();
                let sid = session.id.clone();
                tokio::spawn(async move {
                    // Small delay to let shell initialize
                    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                    let cmd_with_newline = format!("{}\n", cmd_str);
                    if let Err(e) = session_for_cmd
                        .write_to_ssh(cmd_with_newline.as_bytes())
                        .await
                    {
                        warn!(
                            "[SessionManager] Failed to send post-login command for session {}: {}",
                            sid, e
                        );
                    } else {
                        info!(
                            "[SessionManager] Sent post-login command for session {}: {}",
                            sid, cmd_str
                        );
                    }
                });
            }
        }

        // Store the session
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.id.clone(), session.clone());

        info!(
            "[SessionManager] Session {} ready and connected",
            session.id
        );
        Ok(session)
    }

    /// Connect an existing session with credentials
    pub async fn connect_session(
        &self,
        session_id: &str,
        credential: SshCredential,
        pty_config: Option<PtyConfig>,
    ) -> Result<()> {
        info!(
            "[SessionManager] Connecting existing session {}",
            session_id
        );

        let session = {
            let sessions = self.sessions.read().await;
            sessions.get(session_id).cloned().ok_or_else(|| {
                error!("[SessionManager] Session not found: {}", session_id);
                anyhow!("Session not found: {}", session_id)
            })?
        };

        // Get server info
        let server = self
            .database
            .server_get(&session.server_id)?
            .ok_or_else(|| {
                error!(
                    "[SessionManager] Server not found for session {}",
                    session_id
                );
                anyhow!("Server not found for session")
            })?;

        info!(
            "[SessionManager] Connecting to {}@{}:{}",
            server.username, server.host, server.port
        );

        // Create channel for SSH output
        let (ssh_output_tx, mut ssh_output_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

        // Create and connect SSH client
        let mut ssh_client = SshClient::new(ssh_output_tx);

        info!("[SessionManager] Starting SSH connection...");
        match &credential {
            SshCredential::Password(_) => {
                info!("[SessionManager] Using password authentication");
            }
            SshCredential::PrivateKey { passphrase, .. } => {
                info!(
                    "[SessionManager] Using key authentication (passphrase: {})",
                    if passphrase.is_some() { "yes" } else { "no" }
                );
            }
        }

        match credential {
            SshCredential::Password(password) => {
                ssh_client
                    .connect_password(&server.host, server.port, &server.username, &password)
                    .await?;
            }
            SshCredential::PrivateKey { key, passphrase } => {
                ssh_client
                    .connect_key(
                        &server.host,
                        server.port,
                        &server.username,
                        &key,
                        passphrase.as_deref(),
                    )
                    .await?;
            }
        }

        info!("[SessionManager] SSH connected, opening shell...");

        // Open shell with PTY
        ssh_client.open_shell(pty_config).await?;

        info!(
            "[SessionManager] Shell opened successfully for session {}",
            session_id
        );

        // Store the SSH client in the session
        session.set_ssh_client(ssh_client).await;
        session.set_state(SessionState::Connected).await;

        // Bridge SSH output to session broadcast
        let session_for_output = session.clone();
        let session_id_clone = session_id.to_string();
        tokio::spawn(async move {
            debug!(
                "[SessionManager] Output bridge task started for session {}",
                session_id_clone
            );
            while let Some(data) = ssh_output_rx.recv().await {
                session_for_output.publish_output(data).await;
            }
            debug!(
                "[SessionManager] Output bridge task ended for session {}",
                session_id_clone
            );
        });

        info!(
            "[SessionManager] Session {} connected successfully",
            session_id
        );
        Ok(())
    }

    // === Keyboard-interactive (RFC 4256) ===
    //
    // Two-factor servers (`AuthenticationMethods keyboard-interactive`) offer
    // neither `password` nor `publickey`, and drive a multi-prompt
    // conversation instead. Nothing about it can be stored: a TOTP code is
    // valid for 30 seconds. So the exchange is started, parked in a registry,
    // and resumed once the user has typed the answers.

    /// Start a keyboard-interactive exchange for a saved server.
    ///
    /// Returns the id identifying this exchange plus the first step. When the
    /// step is [`KeyboardInteractiveStep::Prompts`], answer it with
    /// [`Self::respond_keyboard_interactive`] using the returned id.
    pub async fn start_keyboard_interactive(
        &self,
        server_name: &str,
        pty_config: Option<PtyConfig>,
    ) -> Result<(String, KeyboardInteractiveStep)> {
        self.reap_expired_keyboard_interactive().await;

        let server = self
            .database
            .server_get_by_name(server_name)?
            .ok_or_else(|| {
                error!("[SessionManager] Server not found: {}", server_name);
                anyhow!("Server not found: {}", server_name)
            })?;

        // A jump host would need the bridge to stay alive across the whole
        // conversation, which the current bridge task cannot do. Fail loudly
        // instead of opening a connection that cannot be completed.
        if server.jump_host_id.is_some() {
            return Err(anyhow!(
                "Keyboard-interactive authentication through a jump host is not supported yet \
                 (server '{}')",
                server_name
            ));
        }

        info!(
            "[SessionManager] Starting keyboard-interactive authentication for {}@{}:{}",
            server.username, server.host, server.port
        );

        let (ssh_output_tx, ssh_output_rx) = mpsc::channel::<Vec<u8>>(256);
        let mut client = SshClient::new(ssh_output_tx);

        let outcome = client
            .connect_keyboard_interactive(&server.host, server.port, &server.username, None)
            .await?;

        let mut stored_password_used = false;
        let (outcome, auto_answered) = self
            .autofill_keyboard_interactive(
                &server.name,
                &server.username,
                &mut client,
                &mut stored_password_used,
                outcome,
            )
            .await?;

        let auth_id = Uuid::new_v4().to_string();

        match outcome {
            KeyboardInteractiveOutcome::Authenticated => {
                // Some servers accept straight away (for example when the
                // module is satisfied by something other than a prompt).
                let session = self
                    .finalize_keyboard_interactive_session(
                        &server,
                        client,
                        ssh_output_rx,
                        pty_config,
                    )
                    .await?;
                Ok((auth_id, KeyboardInteractiveStep::Authenticated(session)))
            }
            KeyboardInteractiveOutcome::Rejected => {
                Ok((auth_id, KeyboardInteractiveStep::Rejected))
            }
            KeyboardInteractiveOutcome::Prompts {
                name,
                instructions,
                prompts,
            } => {
                let pending = PendingKeyboardInteractive {
                    server_name: server.name.clone(),
                    username: server.username.clone(),
                    client,
                    output_rx: ssh_output_rx,
                    pty_config,
                    started_at: Instant::now(),
                    stored_password_used,
                };
                self.pending_keyboard_interactive
                    .write()
                    .await
                    .insert(auth_id.clone(), pending);

                debug!(
                    "[SessionManager] Keyboard-interactive exchange {} parked with {} prompt(s)",
                    auth_id,
                    prompts.len()
                );

                Ok((
                    auth_id,
                    KeyboardInteractiveStep::Prompts {
                        name,
                        instructions,
                        prompts,
                        auto_answered,
                    },
                ))
            }
        }
    }

    /// Answer one round of prompts. The server may reply with more prompts, in
    /// which case this must be called again with the same `auth_id`.
    pub async fn respond_keyboard_interactive(
        &self,
        auth_id: &str,
        responses: Vec<String>,
    ) -> Result<KeyboardInteractiveStep> {
        self.reap_expired_keyboard_interactive().await;

        // Take ownership: the entry is only put back if the conversation is
        // still going. Any error or terminal answer therefore drops the
        // half-authenticated connection instead of leaking it.
        let mut pending = self
            .pending_keyboard_interactive
            .write()
            .await
            .remove(auth_id)
            .ok_or_else(|| {
                anyhow!(
                    "No keyboard-interactive authentication in progress for '{}' \
                     (it may have expired after {}s)",
                    auth_id,
                    KEYBOARD_INTERACTIVE_TTL.as_secs()
                )
            })?;

        let username = pending.username.clone();
        let server_name = pending.server_name.clone();
        let outcome = pending
            .client
            .keyboard_interactive_respond(&username, responses)
            .await?;

        let mut stored_password_used = pending.stored_password_used;
        let (outcome, auto_answered) = self
            .autofill_keyboard_interactive(
                &server_name,
                &username,
                &mut pending.client,
                &mut stored_password_used,
                outcome,
            )
            .await?;
        pending.stored_password_used = stored_password_used;

        match outcome {
            KeyboardInteractiveOutcome::Authenticated => {
                let server = self
                    .database
                    .server_get_by_name(&pending.server_name)?
                    .ok_or_else(|| anyhow!("Server not found: {}", pending.server_name))?;

                let session = self
                    .finalize_keyboard_interactive_session(
                        &server,
                        pending.client,
                        pending.output_rx,
                        pending.pty_config,
                    )
                    .await?;

                info!(
                    "[SessionManager] Keyboard-interactive exchange {} authenticated, session {}",
                    auth_id, session.id
                );
                Ok(KeyboardInteractiveStep::Authenticated(session))
            }
            KeyboardInteractiveOutcome::Rejected => {
                warn!(
                    "[SessionManager] Keyboard-interactive exchange {} rejected by server",
                    auth_id
                );
                Ok(KeyboardInteractiveStep::Rejected)
            }
            KeyboardInteractiveOutcome::Prompts {
                name,
                instructions,
                prompts,
            } => {
                debug!(
                    "[SessionManager] Keyboard-interactive exchange {} continues with {} prompt(s)",
                    auth_id,
                    prompts.len()
                );
                pending.started_at = Instant::now();
                self.pending_keyboard_interactive
                    .write()
                    .await
                    .insert(auth_id.to_string(), pending);

                Ok(KeyboardInteractiveStep::Prompts {
                    name,
                    instructions,
                    prompts,
                    auto_answered,
                })
            }
        }
    }

    /// Abandon an exchange, e.g. when the user closes the prompt dialog.
    /// Unknown or already-finished ids are not an error.
    pub async fn cancel_keyboard_interactive(&self, auth_id: &str) -> Result<()> {
        let pending = self
            .pending_keyboard_interactive
            .write()
            .await
            .remove(auth_id);

        if let Some(mut pending) = pending {
            info!(
                "[SessionManager] Cancelling keyboard-interactive exchange {}",
                auth_id
            );
            if let Err(e) = pending.client.disconnect().await {
                debug!(
                    "[SessionManager] Error disconnecting cancelled exchange {}: {}",
                    auth_id, e
                );
            }
        }

        Ok(())
    }

    /// Password saved for this server, if there is one to offer.
    fn stored_password(&self, server_name: &str) -> Result<Option<String>> {
        let Some(credential) = self.database.credential_get(server_name)? else {
            return Ok(None);
        };
        if credential.auth_type != "password" || credential.credential.is_empty() {
            return Ok(None);
        }
        Ok(Some(credential.credential))
    }

    /// Answer rounds that only ask for the saved password, so the user is asked
    /// for the one thing they alone can supply: the code.
    ///
    /// A round is only answered when **every** prompt in it wants the stored
    /// password. Rounds are all-or-nothing in RFC 4256 — one answer per prompt,
    /// in order — so a round mixing a code and a password is handed to the
    /// caller untouched rather than half-guessed.
    async fn autofill_keyboard_interactive(
        &self,
        server_name: &str,
        username: &str,
        client: &mut SshClient,
        stored_password_used: &mut bool,
        mut outcome: KeyboardInteractiveOutcome,
    ) -> Result<(KeyboardInteractiveOutcome, Vec<String>)> {
        let mut auto_answered: Vec<String> = Vec::new();

        loop {
            let fillable = match &outcome {
                KeyboardInteractiveOutcome::Prompts { prompts, .. } => {
                    !*stored_password_used
                        && !prompts.is_empty()
                        && prompts.iter().all(prompt_wants_stored_password)
                }
                _ => false,
            };

            if !fillable {
                return Ok((outcome, auto_answered));
            }

            let Some(password) = self.stored_password(server_name)? else {
                debug!(
                    "[SessionManager] '{}' asks for a password but none is saved; asking the user",
                    server_name
                );
                return Ok((outcome, auto_answered));
            };

            let count = match &outcome {
                KeyboardInteractiveOutcome::Prompts { prompts, .. } => {
                    for prompt in prompts {
                        auto_answered.push(prompt.prompt.trim().to_string());
                    }
                    prompts.len()
                }
                _ => unreachable!("checked by `fillable` above"),
            };

            info!(
                "[SessionManager] Answering {} keyboard-interactive password prompt(s) for '{}' \
                 from the saved credential",
                count, server_name
            );
            *stored_password_used = true;

            outcome = client
                .keyboard_interactive_respond(username, vec![password; count])
                .await?;
        }
    }

    /// Number of exchanges currently waiting for user input.
    pub async fn pending_keyboard_interactive_count(&self) -> usize {
        self.pending_keyboard_interactive.read().await.len()
    }

    /// Drop exchanges the user never answered, so an abandoned dialog does not
    /// keep a half-authenticated SSH connection open forever.
    async fn reap_expired_keyboard_interactive(&self) {
        let expired: Vec<String> = {
            let pending = self.pending_keyboard_interactive.read().await;
            pending
                .iter()
                .filter(|(_, entry)| entry.is_expired())
                .map(|(id, _)| id.clone())
                .collect()
        };

        for auth_id in expired {
            info!(
                "[SessionManager] Reaping expired keyboard-interactive exchange {}",
                auth_id
            );
            let _ = self.cancel_keyboard_interactive(&auth_id).await;
        }
    }

    /// Open the shell on an authenticated connection and register the session.
    ///
    /// This mirrors the tail of [`Self::create_with_credentials`]. It is kept
    /// separate on purpose: the password and key paths are untouched by the
    /// 2FA work, so they keep their existing, already-shipped code path.
    async fn finalize_keyboard_interactive_session(
        &self,
        server: &Server,
        mut ssh_client: SshClient,
        mut ssh_output_rx: mpsc::Receiver<Vec<u8>>,
        pty_config: Option<PtyConfig>,
    ) -> Result<Arc<Session>> {
        let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(256);
        let (output_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(256);

        let session = Arc::new(Session::new(
            server.id.clone(),
            server.name.clone(),
            input_tx,
            output_tx,
        ));

        info!(
            "[SessionManager] Keyboard-interactive authentication done, opening shell for session {}",
            session.id
        );
        ssh_client.open_shell(pty_config).await?;

        session.set_ssh_client(ssh_client).await;
        session.set_state(SessionState::Connected).await;
        // Reconnecting would mean asking a human for a fresh code, so this
        // session must outlive the idle reaper.
        session.mark_costly_to_reauthenticate().await;

        // Bridge SSH output to the session broadcast channel.
        let session_for_output = session.clone();
        let session_id_for_output = session.id.clone();
        tokio::spawn(async move {
            debug!(
                "[SessionManager] Output bridge task started for session {}",
                session_id_for_output
            );
            while let Some(data) = ssh_output_rx.recv().await {
                session_for_output.publish_output(data).await;
            }
            debug!(
                "[SessionManager] Output bridge task ended for session {}",
                session_id_for_output
            );
        });

        // Bridge the input channel to SSH stdin.
        let session_for_input = session.clone();
        let session_id_for_input = session.id.clone();
        tokio::spawn(async move {
            debug!(
                "[SessionManager] Input bridge task started for session {}",
                session_id_for_input
            );
            while let Some(data) = input_rx.recv().await {
                if let Err(e) = session_for_input.write_to_ssh(&data).await {
                    error!(
                        "[SessionManager] Error writing to SSH for session {}: {}",
                        session_id_for_input, e
                    );
                    break;
                }
            }
            debug!(
                "[SessionManager] Input bridge task ended for session {}",
                session_id_for_input
            );
        });

        if let Some(ref cmd) = server.post_login_command {
            if !cmd.trim().is_empty() {
                let session_for_cmd = session.clone();
                let cmd_str = cmd.clone();
                let sid = session.id.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                    let cmd_with_newline = format!("{}\n", cmd_str);
                    if let Err(e) = session_for_cmd
                        .write_to_ssh(cmd_with_newline.as_bytes())
                        .await
                    {
                        warn!(
                            "[SessionManager] Failed to send post-login command for session {}: {}",
                            sid, e
                        );
                    } else {
                        info!(
                            "[SessionManager] Sent post-login command for session {}: {}",
                            sid, cmd_str
                        );
                    }
                });
            }
        }

        self.sessions
            .write()
            .await
            .insert(session.id.clone(), session.clone());

        info!(
            "[SessionManager] Session {} ready and connected (keyboard-interactive)",
            session.id
        );
        Ok(session)
    }

    pub async fn kill(&self, id: &str) -> Result<()> {
        info!("[SessionManager] Killing session {}", id);
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(id) {
            // Disconnect SSH gracefully
            if let Err(e) = session.disconnect().await {
                error!("[SessionManager] Error disconnecting session {}: {}", id, e);
            } else {
                info!("[SessionManager] Session {} disconnected successfully", id);
            }
        } else {
            warn!("[SessionManager] Session {} not found for kill", id);
        }
        Ok(())
    }

    pub async fn kill_all(&self) -> Result<()> {
        info!("[SessionManager] Killing all sessions");
        let mut sessions = self.sessions.write().await;
        let count = sessions.len();
        for (id, session) in sessions.iter() {
            if let Err(e) = session.disconnect().await {
                error!("[SessionManager] Error disconnecting session {}: {}", id, e);
            }
        }
        sessions.clear();
        info!("[SessionManager] Killed {} sessions", count);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Database;
    use tokio::sync::{broadcast, mpsc};

    async fn manager_with_ids(ids: &[&str]) -> SessionManager {
        let temp = tempfile::tempdir().unwrap();
        let database = Arc::new(Database::new_at(temp.path().join("sessions.db")).unwrap());
        let manager = SessionManager::new(database);
        let mut sessions = manager.sessions.write().await;
        for id in ids {
            let (input_tx, _) = mpsc::channel(1);
            let (output_tx, _) = broadcast::channel(1);
            let mut session = Session::new("server".into(), "server".into(), input_tx, output_tx);
            session.id = (*id).into();
            sessions.insert(session.id.clone(), Arc::new(session));
        }
        drop(sessions);
        manager
    }

    #[tokio::test]
    async fn resolve_accepts_full_and_unique_prefix() {
        let manager = manager_with_ids(&["abcdef01-0000-0000-0000-000000000001"]).await;
        assert_eq!(
            manager.resolve("abcdef01").await.unwrap().id,
            "abcdef01-0000-0000-0000-000000000001"
        );
        assert!(manager.resolve("abc").await.is_err());
    }

    #[tokio::test]
    async fn resolve_rejects_ambiguous_prefix() {
        let manager = manager_with_ids(&[
            "abcdef01-0000-0000-0000-000000000001",
            "abcdef01-0000-0000-0000-000000000002",
        ])
        .await;
        let error = match manager.resolve("abcdef01").await {
            Ok(_) => panic!("ambiguous prefix should fail"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("Ambiguous"));
    }

    #[tokio::test]
    async fn cancelling_an_unknown_keyboard_interactive_exchange_is_not_an_error() {
        let manager = manager_with_ids(&[]).await;
        assert_eq!(manager.pending_keyboard_interactive_count().await, 0);

        // The dialog can be closed after the exchange already finished, so an
        // unknown id has to be a no-op rather than an error the UI must handle.
        manager
            .cancel_keyboard_interactive("no-such-exchange")
            .await
            .unwrap();

        assert_eq!(manager.pending_keyboard_interactive_count().await, 0);
    }

    #[tokio::test]
    async fn responding_without_a_started_exchange_is_reported_clearly() {
        let manager = manager_with_ids(&[]).await;

        let error = match manager
            .respond_keyboard_interactive("no-such-exchange", vec!["123456".to_string()])
            .await
        {
            Ok(_) => panic!("responding to an unknown exchange should fail"),
            Err(error) => error.to_string(),
        };

        assert!(
            error.contains("No keyboard-interactive authentication in progress"),
            "unexpected error: {error}"
        );
        // The message has to mention the expiry, because that is the most
        // likely reason an id stops being known.
        assert!(error.contains("expired"), "unexpected error: {error}");
    }

    fn prompt(label: &str, echo: bool) -> KeyboardInteractivePrompt {
        KeyboardInteractivePrompt {
            prompt: label.to_string(),
            echo,
        }
    }

    #[test]
    fn a_hidden_password_prompt_can_be_answered_from_the_saved_credential() {
        assert!(prompt_wants_stored_password(&prompt("Password: ", false)));
        assert!(prompt_wants_stored_password(&prompt(
            "root@host's Password:",
            false
        )));
        assert!(prompt_wants_stored_password(&prompt(
            "Mot de passe : ",
            false
        )));
    }

    #[test]
    fn a_one_time_code_is_never_answered_from_the_saved_credential() {
        // The failure this guards against is sending the account password in
        // answer to a code prompt, which would hand it to anything listening
        // and burn a login attempt.
        assert!(!prompt_wants_stored_password(&prompt(
            "Verification code: ",
            false
        )));
        assert!(!prompt_wants_stored_password(&prompt("OTP: ", false)));
        assert!(!prompt_wants_stored_password(&prompt(
            "Two-factor token:",
            false
        )));
    }

    #[test]
    fn an_echoing_prompt_is_never_answered_from_the_saved_credential() {
        // A server that echoes what is typed is not asking for a secret, even
        // if the word "password" appears in the label.
        assert!(!prompt_wants_stored_password(&prompt(
            "Enter your password hint: ",
            true
        )));
    }

    #[test]
    fn stored_private_key_can_reference_a_local_file() {
        let temp = tempfile::tempdir().unwrap();
        let key_path = temp.path().join("id_ed25519");
        std::fs::write(&key_path, "private-key-material").unwrap();
        let credential = crate::storage::database::Credential {
            id: "credential-id".to_string(),
            server_name: "imported".to_string(),
            auth_type: "key_with_passphrase".to_string(),
            credential: String::new(),
            passphrase: Some(String::new()),
            key_path: Some(key_path.to_string_lossy().into_owned()),
            created_at: 0,
        };

        match SshCredential::from_stored(credential).unwrap() {
            SshCredential::PrivateKey { key, passphrase } => {
                assert_eq!(key, "private-key-material");
                assert!(passphrase.is_none());
            }
            SshCredential::Password(_) => panic!("expected private-key credential"),
        }
    }
}
