# brocode 🌐🤖

Autonomous vision-driven web automation framework for Hermes, OpenCode, Claude Code, and developer subagents, powered by [`browser-use`](https://github.com/browser-use/browser-use).

---

## ⚡ Key Highlights
- **Model:** `gpt-6-luna` powered directly through your local CLI Proxy API (`http://localhost:8317/v1`).
- **Vision-Driven Execution:** Real-time visual DOM tree navigation, coordinate clicking, and multi-step reasoning.
- **Persistent Chrome Session (CDP):** Runs on Chrome DevTools Protocol (`http://localhost:9222`) using persistent profile `.chrome_profile` so logins, cookies, and active sessions stay alive without bot blocks.
- **Artifact Logging:** Automatically saves action traces, extracted data, and history to `artifacts/`.

---

## 🛠️ Quick Commands

### 1. Run a Browser Task
```bash
brocode run "Go to https://news.ycombinator.com and extract the top 3 stories"
```
Options:
- `--max-actions <N>`: Maximum steps/actions (default: 15).
- `--model <name>`: Model override (default: `gpt-6-luna`).
- `--no-cdp`: Run in standalone browser instead of connecting to CDP daemon.
- `--headful`: Run browser with visible GUI window.

### 2. Manage the Chrome Daemon
```bash
# Check status of Chrome CDP and environment
brocode status

# Start persistent background Chrome daemon (CDP on port 9222)
brocode start-chrome

# Stop background Chrome daemon
brocode stop-chrome
```

---

## 🤖 Usage by Other Coding Agents (OpenCode / Claude Code / Scripts)

### Shell Execution
Any tool or subagent can call the global binary:
```bash
brocode run "<your task description>"
```

### Python API
```python
import asyncio
from brocode import run_task

async def main():
    result = await run_task("Search for the latest Python release date and return it")
    print(result["result"])

asyncio.run(main())
```
