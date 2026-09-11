# Setting up VibeShell for an AI agent

How to let an assistant drive SSH and SFTP through VibeShell, on a new machine.

There are two pieces, and they do different jobs:

| Piece | What it does |
|---|---|
| **The skill** | Teaches the assistant *how* to use VibeShell: which commands, in what order, and what to do when a server refuses a stored credential. |
| **The MCP server** | Gives the assistant *tools it can call* against the running desktop app, sharing the terminal the user is watching. |

The skill alone works for CLI-driven assistants. The MCP server is what lets an
assistant act on the visible session. Installing both is the usual setup.

---

## 1. Install VibeShell

Run the installer, then open the app once so it can create its data directory
and publish its Agent Gateway manifest.

Verify the CLI is on `PATH`:

```bash
vibeshell version
```

If it is not found, use the full path for the rest of this document:

- Windows `C:\Program Files\VibeShell\vibeshell.exe`
- macOS `/Applications/VibeShell.app/Contents/MacOS/vibeshell`
- Linux `~/.local/bin/vibeshell`

## 2. The skill installs itself

Every `vibeshell` run installs the canonical skill into the agent directories it
detects, so simply running `vibeshell version` is usually enough.

Check what was detected and where it landed:

```bash
vibeshell list
```

Install into a specific tool, or remove it:

```bash
vibeshell install <tool-id>
vibeshell uninstall <tool-id>
```

To manage the file yourself, set `VIBESHELL_SKIP_SKILL_AUTO_INSTALL=1`. Without
it, edits to an installed `SKILL.md` are overwritten on the next run: the binary
carries the canonical copy.

## 3. Add the MCP server

Configure it as a **command**, not as a URL:

```json
{
  "mcp": {
    "vibeshell": {
      "type": "local",
      "command": ["vibeshell", "mcp"],
      "enabled": true
    }
  }
}
```

On Windows, with the absolute path:

```json
"command": ["C:\\Program Files\\VibeShell\\vibeshell.exe", "mcp"]
```

`vibeshell mcp` speaks MCP on stdin and stdout and forwards to the desktop app's
Agent Gateway. It starts VibeShell if it is not running.

### Do not hardcode the Gateway URL

The Gateway binds an **ephemeral** loopback port and mints a **new token** on
every launch. That is deliberate: a predictable port could be squatted by
another local process, and a leaked token stops working when the app restarts.
The published manifest is how clients are meant to find it.

So a configuration like this works until the next restart, then fails with a
refused connection and a rejected token:

```json
"type": "remote",
"url": "http://127.0.0.1:54677/",
"headers": { "Authorization": "Bearer ..." }
```

`vibeshell mcp` re-reads the manifest on every call and recovers on its own when
the token is refused. Nothing to update, and no token stored in a config file.

## 4. Check it

```bash
vibeshell version
vibeshell servers
vibeshell daemon status
```

For the MCP server, ask the assistant to list tools. Roughly thirty should
appear, including `server_list`, `session_create`, `session_send_input` and
`session_auth_start`.

By hand:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"check","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | vibeshell mcp
```

Two JSON lines on stdout means it works. Diagnostics go to stderr; stdout
carries protocol only.

---

## Servers that require two-factor

Some servers accept neither a password nor a key: they run a
keyboard-interactive exchange and ask for a one-time code. No saved credential
can answer that, so `vibeshell ssh <server>` reports **No saved credentials**
even on a profile that looks complete.

**Save the password, not the code.** If the server asks for a password as well
as a code, save the password in the VibeShell app. It is then answered
automatically and only the code is left to type. A one-time code expires in
about thirty seconds; an account password does not, and does not belong in a
chat transcript.

**Authenticating in a terminal.** Run it yourself and answer the prompts:

```bash
vibeshell ssh <server>
```

Answers the server marks as hidden are not echoed. The session is then reusable
by alias, and an assistant can work with it without ever handling the second
factor:

```bash
vibeshell sessions
vibeshell ssh-session 001 -- uptime
```

**Authenticating through the assistant.** With the MCP server configured, the
assistant can run the exchange itself: `session_auth_start` returns the
server's questions, and `session_auth_respond` answers them. Each prompt is
flagged so the assistant knows what to do with it:

- `secret` — do not display the answer
- `save_in_app` — a long-lived password; ask the user to save it in VibeShell
  rather than type it into the conversation

A session authenticated this way is exempt from the idle timeout and lives until
it is closed or the background service stops, because rebuilding it would cost
the user another code.

---

## Troubleshooting

**`vibeshell` not found.** Use the absolute path in the MCP `command`. The
installer adds it to `PATH`, which needs a new shell, sometimes a logout.

**MCP connection refused after a restart.** The configuration is pinned to a URL.
Replace it with the `command` form above.

**Tools listed but every call fails.** VibeShell is not running and could not be
started. Open it once by hand, then try again.

**Edits to `SKILL.md` keep reverting.** Expected: the binary reinstalls the
canonical copy on every run. Set `VIBESHELL_SKIP_SKILL_AUTO_INSTALL=1` to manage
it yourself.

**A session disappeared.** Detached sessions are reaped after 30 minutes idle.
Two-factor sessions are exempt. `vibeshell sessions` shows what is alive.
