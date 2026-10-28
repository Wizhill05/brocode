# Questions during a running browser task

The worker exposes a registered `ask_caller` action for missing non-secret task
information. It is not a shell/script tool, approval mechanism, or CAPTCHA solver.

## What is implemented

A Python caller can supply an asynchronous `question_handler` to `Runtime.run` or
`Runtime.start`. It receives a `QuestionRequest` and returns a nonempty string (or
raises/declines). While waiting, the worker's browser process and profile lease
remain owned by the same task. The reply is supplied to the browser model as task
data, not permission to change scope or perform a mutation.

Questions are bounded to 2,000 characters, up to eight optional choices of 500
characters each, and a requested wait of 1–300 seconds. Answers are bounded to
2,000 characters. The overall task timeout still applies, including time spent
waiting for an answer; this is not indefinite suspension. Cancellation tears down
the owned browser normally. A task remains `running` while the question event is
pending; `needs_input` remains a terminal result.

No handler returns an explicit `QUESTION_HANDLER_REQUIRED` failure rather than a
guessed answer. Obvious credential requests are rejected, but the keyword guard
is best-effort, not a guarantee against every paraphrase. Never send passwords,
login codes, or other credentials through this channel.

## ACP and other clients

The ACP adapter uses the installed SDK's structured form elicitation, only when
the client advertises form support. Missing support produces
`QUESTION_ACP_UNSUPPORTED`. Having a working SDK implementation and synthetic tests
does not prove that a particular T3/OpenCode version advertises or renders this
feature. Real-client acceptance testing is still required.

The CLI and MCP adapters do not currently wire a question-answer handler. A skill
cannot add a missing transport capability. Use a supported Python handler or a
verified ACP client; do not promise users that unanswered tasks can resume later.

## What this does not implement

- Restoring a browser after process exit, disconnect, timeout, or cancellation.
- A durable inbox that lets arbitrary clients answer a suspended run by ID.
- Human control of Chrome to complete a CAPTCHA, or automatic challenge solving.
- Website uploads, submission approval, domain expansion, or new action authority.

Answers and questions can include private applicant facts. Events and task results
may persist locally; keep them private. Never add private answers to public
playbooks. Actual website submissions still require the separate approval path,
meaningful verification, and evidence-based reconciliation after uncertainty.
