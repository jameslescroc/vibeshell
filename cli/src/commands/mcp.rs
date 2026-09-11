//! MCP stdio transport backed by the desktop Agent Gateway.
//!
//! MCP hosts are configured once, with a command, and expect that command to
//! keep working. The Gateway deliberately does not offer a stable address: it
//! binds an ephemeral loopback port and mints a fresh token on every launch, so
//! a predictable port cannot be squatted by another local process and a leaked
//! token dies when the app restarts. The published manifest is the discovery
//! mechanism.
//!
//! Pinning the address in a host's configuration defeats that: it works until
//! the app restarts, then fails with a stale port and a rejected token. This
//! command bridges the two. It speaks newline-delimited JSON-RPC on stdin and
//! stdout, resolves the endpoint from the manifest on every call, starts the
//! desktop app when it is not running, and re-reads the manifest when a token
//! is refused.
//!
//! Sessions therefore belong to the visible app, not to a second private
//! session registry, so what an agent does stays visible in the terminal the
//! user is watching.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use vibeshell_core::mcp::gateway::{gateway_manifest_path, GatewayManifest, GatewayStatus};

/// How long to wait for the desktop app to publish a usable manifest.
const READY_TIMEOUT: Duration = Duration::from_secs(20);
/// Polling interval while waiting for the app to come up.
const READY_POLL: Duration = Duration::from_millis(250);
/// Health probe timeout. Only proves the endpoint answers.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(3);
/// A call may legitimately take minutes: opening an SSH connection, or waiting
/// for a human to answer a two-factor prompt.
const CALL_TIMEOUT: Duration = Duration::from_secs(300);

/// A Gateway that answered a health probe.
struct Endpoint {
    url: String,
    token: String,
}

pub fn run() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to start the async runtime")?;
    runtime.block_on(serve())
}

async fn serve() -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(CALL_TIMEOUT)
        .build()
        .context("Failed to build the HTTP client")?;

    // stdout carries protocol only. Everything else goes to stderr, or the
    // host will fail to parse the stream.
    eprintln!("[VibeShell MCP] bridging stdio to the Agent Gateway");

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(error) => {
                // Malformed input still deserves a protocol-shaped answer.
                let response =
                    error_response(Value::Null, -32700, &format!("Parse error: {error}"));
                write_line(&mut stdout, &response).await?;
                continue;
            }
        };

        // A notification has no id and must not be answered.
        let id = request.get("id").cloned();
        let response = match forward(&client, &request).await {
            Ok(value) => value,
            Err(error) => {
                let Some(id) = id.clone() else {
                    eprintln!("[VibeShell MCP] notification failed: {error}");
                    continue;
                };
                error_response(id, -32000, &error.to_string())
            }
        };

        if id.is_none() {
            continue;
        }
        write_line(&mut stdout, &response).await?;
    }

    Ok(())
}

async fn write_line(stdout: &mut tokio::io::Stdout, value: &Value) -> Result<()> {
    let mut encoded = serde_json::to_vec(value)?;
    encoded.push(b'\n');
    stdout.write_all(&encoded).await?;
    stdout.flush().await?;
    Ok(())
}

fn error_response(id: Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

/// Send one request, refreshing the endpoint if the token was rejected.
async fn forward(client: &reqwest::Client, request: &Value) -> Result<Value> {
    let endpoint = ready(client).await?;

    match post(client, &endpoint, request).await {
        Ok(response) => Ok(response),
        // A 401 means the app restarted and reissued its token between the
        // manifest read and the call. Resolve again and retry once.
        Err(error) if is_unauthorized(&error) => {
            eprintln!("[VibeShell MCP] gateway restarted, re-reading the manifest");
            let endpoint = ready(client).await?;
            post(client, &endpoint, request).await
        }
        Err(error) => Err(error),
    }
}

fn is_unauthorized(error: &anyhow::Error) -> bool {
    error.to_string().contains("401")
}

async fn post(client: &reqwest::Client, endpoint: &Endpoint, request: &Value) -> Result<Value> {
    let response = client
        .post(format!("{}/mcp", endpoint.url.trim_end_matches('/')))
        .bearer_auth(&endpoint.token)
        .json(request)
        .send()
        .await
        .context("Agent Gateway request failed")?;

    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!("Agent Gateway returned HTTP {}", status.as_u16()));
    }

    response
        .json()
        .await
        .context("Agent Gateway returned a malformed response")
}

fn read_manifest() -> Option<GatewayManifest> {
    let path: PathBuf = gateway_manifest_path().ok()?;
    let contents = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Resolve a Gateway that answers, starting the desktop app if needed.
async fn ready(client: &reqwest::Client) -> Result<Endpoint> {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    let mut launched = false;
    let mut last_reason = "no manifest published yet".to_string();

    loop {
        if let Some(manifest) = read_manifest() {
            if manifest.status == GatewayStatus::Running {
                match (manifest.endpoint.clone(), manifest.token.clone()) {
                    (Some(url), Some(token)) => {
                        let endpoint = Endpoint { url, token };
                        if healthy(client, &endpoint).await {
                            return Ok(endpoint);
                        }
                        last_reason = "the published endpoint did not answer".to_string();
                    }
                    _ => last_reason = "the manifest has no endpoint or token".to_string(),
                }
            } else {
                last_reason = "VibeShell is not running".to_string();
            }

            if !launched {
                launch(&manifest.launch_path);
                launched = true;
            }
        } else if !launched {
            launch("");
            launched = true;
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "VibeShell's Agent Gateway is not available ({}). Start VibeShell and try again.",
                last_reason
            ));
        }
        tokio::time::sleep(READY_POLL).await;
    }
}

async fn healthy(client: &reqwest::Client, endpoint: &Endpoint) -> bool {
    let url = format!("{}/health", endpoint.url.trim_end_matches('/'));
    matches!(
        client
            .get(url)
            .bearer_auth(&endpoint.token)
            .timeout(HEALTH_TIMEOUT)
            .send()
            .await,
        Ok(response) if response.status().is_success()
    )
}

/// Start the desktop app, detached, so it outlives this process.
fn launch(launch_path: &str) {
    let mut command = if !launch_path.is_empty() {
        let mut command = std::process::Command::new(launch_path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    } else if cfg!(target_os = "macos") {
        let mut command = std::process::Command::new("/usr/bin/open");
        command.args(["-a", "VibeShell"]);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    } else {
        let mut command = std::process::Command::new("VibeShell");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    };

    match command.spawn() {
        Ok(_) => eprintln!("[VibeShell MCP] starting VibeShell"),
        Err(error) => eprintln!("[VibeShell MCP] could not start VibeShell: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rejected_token_is_recognised_as_worth_retrying() {
        // The whole point of this bridge: a restarted app reissues its token,
        // and the next call must recover instead of failing the user.
        assert!(is_unauthorized(&anyhow!("Agent Gateway returned HTTP 401")));
        assert!(!is_unauthorized(&anyhow!(
            "Agent Gateway returned HTTP 500"
        )));
    }

    #[test]
    fn a_parse_failure_is_reported_in_protocol_shape() {
        let response = error_response(Value::Null, -32700, "Parse error");
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["error"]["code"], -32700);
    }
}
