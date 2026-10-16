# AGENTS.md

brocode is a browser you talk to in goals. An LLM agent reads the page and decides each click. Anything you automate here goes through that agent.

## Run the preflight first

For the specific procedure of applying to a job, read `APPLYING.md`. It is the
runbook that produced a confirmed submission, including the exact goal text and
the screening answers.

`brocode run` runs `brocode doctor` before it touches the browser and refuses to
start if any check fails. You can also run `brocode doctor "your goal" --model X`
on its own. Fix every line marked with a cross before doing anything else.

What it catches, all of which have actually happened here:

- Chrome running without `--proxy-server`, so its traffic was leaving on the host
  IP while the logs looked fine.
- The egress proxy dead or replaced by another process on the same port.
- Host and proxied egress returning the same IP, meaning the exit node is not in
  the path.
- Orphan Chrome processes left behind by a bad `stop-chrome`.
- A flash-tier model on a goal that needs an interaction.

If you are about to debug a failed run, run `brocode doctor` first. Most "the
agent is broken" reports here were really a misconfigured browser.

## Entry point

Shell.

    brocode run "<goal in plain English>"
    brocode run "<goal>" --max-actions 30 --headful

Python.

    import asyncio
    from brocode import run_task

    result = asyncio.run(run_task("Open https://example.com and return the page title"))
    print(result["result"])

`run_task` returns a dict with `task_id`, `artifact`, `recordings`, and `result`. The `--max-actions` flag caps steps at 15 by default. `--model` overrides the model for one run. `--file PATH` registers a file the agent may upload, and is required before any upload will work.

## Do not write automation scripts

The one-off Playwright scripts that used to live here are gone on purpose. They hardcoded selectors, job URLs, and pixel coordinates for captcha checkboxes, and they broke the first time the page changed. Do not bring them back.

Concretely, do not:

- Write Playwright or Selenium code to drive this browser.
- Hardcode CSS selectors, XPath, or DOM text to click.
- Click by screen coordinates.
- Encode a site's flow as a fixed sequence of steps.

If you need something clicked, describe it in the goal. The agent finds it. When the agent fails, fix the goal wording or raise `--max-actions`. Do not reach for a selector.

## Browser lifecycle

There is no long-running Chrome daemon any more. `run_task` launches a fresh
Chrome per run against the persistent profile and closes it when the run ends.
`brocode status` shows the browser binary, display, and egress.

One thing will bite you: Chrome takes a `SingletonLock` on the profile. If a run
is killed hard, a stale lock survives and the next launch fails with "Browser
process exited before CDP became available". `brocode doctor` catches it and
names the dead pid. Clear it with `rm .chrome_profile/Singleton*` after making
sure no Chrome is still using the profile.

## Persistence

Chrome runs against `.chrome_profile` in place, so logins, cookies, and open tabs
survive between runs. Treat that profile as shared authenticated state. Do not
log out, do not clear cookies, do not launch a second Chrome against it.

`stealth.patch()` is what keeps the profile in place. browser-use's
`BrowserProfile._copy_profile` otherwise copies it to `/tmp/browser-use-user-data-dir-*`
whenever the path or executable contains "chrome", and that copy is one-way, so
anything the run does is silently discarded.

## Stealth

`stealth.py` is infrastructure. It pins the things that make this browser look
like a person rather than a driver.

Swapping in Patchright does not work here, and it is worth knowing why rather
than trying again. browser-use launches Chrome as a raw subprocess and speaks
CDP, so Patchright's patches, which live at `launch_persistent_context` time,
never run. browser-use also calls `Runtime.evaluate` in a dozen places, which is
the `Runtime.enable` leak Patchright exists to close.

What we can and do control:

- Real Google Chrome, not Playwright's Chromium. Anti-bot detects the difference.
  Install with `.venv/bin/python -m patchright install chrome`.
- Launch flags. Patchright strips `--disable-component-update` and
  `--disable-default-apps` precisely because they read as a stealth driver.
  We strip them too.
- `no_viewport=True`. Without it the outer window and inner viewport disagree,
  which is physically impossible for a real browser and an instant tell.
- Software WebGL through SwiftShader. A browser with no WebGL at all is itself
  suspicious. Xvfb has no GPU, so we ask for it explicitly.
- Headful under Xvfb, never headless. Headless is its own detection category.

## Infrastructure

Three files here are plumbing, not task code. Do not delete them.

`local_exit_proxy.py` is a CONNECT proxy on `127.0.0.1:1088` that binds every
outbound socket to `100.122.152.101`, this host's Tailscale address. Linux
`ip rule 5200` matches that source and looks up table 52, whose default is
`dev tailscale0`, so only this browser leaves through the Tailscale exit node.
Rule 5260 sends every other process out Azure eth0. The isolation is
per-socket. Do not "simplify" this into a host-wide `--exit-node` change or
a system proxy setting, and do not point anything but Chrome at the proxy.

Start it with `python3 local_exit_proxy.py` before launching Chrome.
`BROCODE_PROXY_URL` in `.env` is what tells Chrome to use it.

The scoping lives in `ip rule`, and it is fragile. `brocode doctor` checks it as
`ip rule scoping`. You need these two in this order:

    ip rule add from 100.122.152.101 lookup 52 priority 5200
    ip rule add from all lookup main priority 5260

The first pulls only traffic bound to the Tailscale address into the exit node.
The second keeps everything else on eth0. `tailscale set --exit-node` deletes
both and routes the whole host through the exit node, which is the opposite of
what this setup is for. If `host egress IP` and `proxied egress IP` ever come
back identical, that is what happened.

## Recording

Every `run_task` screencasts the session to `artifacts/recordings/` and lists
the resulting files in the returned dict and in the artifact JSON. Pass
`record=False` to `run_task`, or `--no-record` on the CLI, to skip it. The
capture is driven through CDP `Page.screencastFrame` on the session the agent
is driving.

## Captcha

`captcha_solver.py` is infrastructure. Do not delete it, and do not replace it
with a script that clicks image tiles.

browser-use's built-in captcha handling only listens for
`BrowserUse.captchaSolverStarted/Finished` CDP events, which a Browser Use cloud
proxy emits. On a local Chrome nothing sends those, so the agent is left to click
tiles by vision and loses. This module closes that gap.

It solves the real way. Read `data-sitekey` and the page URL, send them to
NoCaptchaAI, receive a `g-recaptcha-response` token, inject it into the form and
fire the widget callback. Nobody clicks tiles. Costs a fraction of a cent per
solve and the free tier covers 6,000 a month.

Set `NOCAPTCHA_API_KEY` in `.env`. `brocode doctor` fails preflight without it.

Check the plumbing without spending a solve:

    .venv/bin/python captcha_solver.py --selftest

That tests detection and token injection against `2captcha.com/demo/recaptcha-v2`
using a deliberately fake token, so it costs nothing. Green means the sitekey is
found and the form accepts a token.

Two traps here. reCAPTCHA takes about 10 seconds to render through the egress
proxy, so poll the readiness flag rather than sleeping a fixed amount. And the
hard block, "Your computer or network may be sending automated queries", is
terminal. A solver cannot fix it because Google stops serving a solvable
challenge. Only a fresh IP and fingerprint help. The agent reports it and stops.

## Model

`gpt-6-luna` through the local OpenAI-compatible proxy at `http://localhost:8317/v1`, configured in `.env`. `VISION_MODEL` is what `run_task` uses. `DEFAULT_MODEL` is also configured for compatibility. Pass `--model` to override per run.

## Output

Each run writes `artifacts/task_<timestamp>.json` holding the goal, the model, the final result, errors, and the URLs visited. Read that file to see what happened. Prefer the returned dict over parsing stdout.

## Debugging browser-use without fooling yourself

Two traps cost hours here. Both produce confident, wrong conclusions.

Do not count actions with `model_fields`. Action models are pydantic `RootModel`
unions, so `model_fields` is always just `{'root'}` whether the schema holds 24
actions or zero. Count them from `model_json_schema()` and the `anyOf` list.

Do not probe the action schema with a small `max_steps`. browser-use swaps in a
done-only output model when `step_info.is_last_step()` or when
`consecutive_failures >= max_failures`. A probe that runs one step will show you
that done-only schema and it will look like the normal state. Check
`step_info.max_steps` and `is_last_step()` before concluding anything.

If an agent claims tools are missing, print the schema the LLM actually
received. Treat the claim as a hypothesis, not a fact.

## Making work repeatable

Save the goal string, not code. A goal is a paragraph of plain English you can rerun or hand to another agent. When a task must run against many URLs or on a schedule, write the goals down and vary the arguments. A new script in this folder is the wrong answer.
