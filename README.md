# dsh-mobile-connect (v3.1.0)

Phone gateway plugin for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH) and multi-agent CLIs (Antigravity `agy acp`, Claude Code, Codex, OpenCode).
It starts its own HTTP/SSE + Noise_IK E2EE listener and exposes the session list, messaging, models, workspace files and
the pairing handshake, so a self-hosted phone app can drive desktop agents from another device.
It runs next to the shipped console plugin, on its own port, with its own token, sharing no state.

手机网关插件（v3.1.0）：在电脑上开一个独立的 HTTP/SSE + 端到端加密端口，统一暴露 DSH、Antigravity、Claude Code、Codex、OpenCode 的会话列表、发消息、模型切换与工作区文件能力，供自建手机 App 使用。与内置控制台并行运行，端口、令牌、状态互不相干。

## Install

```bash
# from this repository (git)
dsh plugin --profile <profile> add github:hyfdracula/dsh-mobile-connect

# from npm
dsh plugin --profile <profile> add dsh-mobile-connect
```

Then restart DSH. A Host-only row named `mobile-connect` is inserted by this package's
`cordis.patch.yml`; if port 8901 is taken, override it in the profile's own `cordis.patch.yml`:

```yaml
- id: mobile-connect
  config:
    port: 8911
    host: '0.0.0.0'
```

`0.0.0.0` listens on IPv4 only; the default `::` listens on both stacks, which is what a phone on
the same Wi-Fi needs.

## What it serves

| Route | Purpose |
|---|---|
| `GET /health` | unauthenticated liveness probe |
| `GET /api/pair/info` | pairing metadata: host, port, LAN candidates, public URL |
| `POST /api/pair/claim` | exchange a live 6-digit code for the bearer token |
| `GET /api/sessions` | session rows (title, cwd, running, archived, pinned, tokens, model) |
| `GET /api/sessions/:id/messages` | messages plus per-turn stats and the last turn error |
| `POST /api/sessions/:id/messages` | send a prompt |
| `GET /api/sessions/:id/fs` | workspace listing |
| `GET /api/sessions/:id/fs/file` | small text preview (415 for binaries) |
| `GET /api/sessions/:id/fs/download` | download any file inside the workspace |

Every route except `/health` and the two pairing routes requires
`Authorization: Bearer <token>` or `?t=<token>`. The token lives in `~/.dsh/dsh-mobile.json`
(mode 0600) and is minted on first use.

## Pairing

1. Open **Settings → Mobile connection** in DSH and copy the 6-digit code, or scan the QR.
2. The QR payload is `dshmobile://pair?b=<base>&c=<code>` plus optional `&a=<alt>` entries: the phone
   tries the first address, then the alternatives, before reporting a failure. That covers laptops
   with several adapters (Docker, WSL, Hyper-V) and a LAN address that is blocked but a tunnel that works.
3. The code is single use, valid for 15 minutes, and rotates after every successful claim. Eight wrong
   claims from one peer lock it out for five minutes.

If a phone cannot connect at all, check in this order: same Wi-Fi network, the desktop firewall
allowing the DSH process on that port, and finally whether the panel's public URL is reachable.

## Security notes

- The token is a bearer credential: anyone who has it can read sessions and send prompts.
- LAN pairing is on by default; remote (tunnel) pairing is off until you set a public URL.
- File reads are confined to the session's workspace, resolved through `realpath`, so symlinks and
  junctions cannot escape it.
- Do not expose this port to the open internet without your own TLS terminator.

## Develop

The published package contains the built `lib/` only. The TypeScript source, the DSH client section
and the phone app live in the author's workspace; see the repository issues for the source request.

## License

MIT
