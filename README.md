# canvas

A Herald extension that reads Canvas LMS for you: your active courses, grades,
submission state, announcements and inbox headers. Anything that changes
Canvas (a submission, a message) is shown to you on Telegram exactly as it
will be sent and happens only after you tap yes.

Many schools have turned off Canvas's mobile OAuth for third parties, so this
uses your own browser session instead. You log in once, on your phone, to a
real Chromium running on your server, shown to you through a private noVNC
page that only your Tailscale account can open. Herald never sees or types
your password. A timer renews the session every ten minutes, and if your
school's SSO lets it, a lapsed session is recovered without asking you.

## What it needs

- Herald v0.4.0 or later (`herald ext install` arrived there).
- Linux with systemd, and Tailscale on the server and on your phone. Allow
  your user to publish the login page on your tailnet, once:
  `sudo tailscale set --operator=$USER`
- A virtual display, a VNC-to-WebSocket bridge and noVNC:
  `sudo apt install tigervnc-standalone-server websockify novnc`
- Playwright and requests in Herald's venv, with its Chromium:
  `~/herald/venv/bin/pip install playwright requests && ~/herald/venv/bin/playwright install chromium`

## Install

Send your Herald this repository's URL and ask it to install it, or run:

```bash
herald ext install https://github.com/benmross/herald-canvas
herald ext setup canvas        # asks for the settings below
herald ext enable canvas
herald services install        # the keepalive timer and the login service
```

Then log in once: ask Herald for the Canvas login page, or run
`systemctl --user start herald-canvas-login.service` and open your
`canvas.login_url` on your phone. Enter your credentials and finish Duo in the
remote browser. The page closes itself when Canvas answers as you, or after 15
minutes, and the first sync runs straight away.

## Settings

All of them live in your own `config.json`; nothing personal goes in this
directory, so `herald ext update` can always fast-forward it.

| key | what |
|---|---|
| `canvas.base_url` | your school's Canvas, e.g. `https://umd.instructure.com` |
| `canvas.login_url` | where the login page is served on your tailnet, e.g. `https://myserver.tail1234.ts.net:8447` |
| `canvas.login_users` | the Tailscale logins allowed to open it |
| `canvas.metadata_only_courses` | course codes to lock to names, dates, grades and submission state (no text, files, rubrics, answers or messages) |
| `canvas.auth_dir` | cookies and browser profile; default `$HERALD_HOME/canvas`, mode 700 |
| `canvas.upload_roots`, `canvas.upload_hosts` | where a submission may read files from, and which storage hosts may receive them |

A metadata-only course still has its News page watched: the page is hashed in
Python, only the hash is kept, and a change sends you a link. Use it for any
course whose syllabus forbids putting its materials into an AI tool.

## Use

`herald-canvas status` checks the connection without showing cookies.
`herald-canvas courses` lists course metadata.
`herald-canvas get /api/v1/courses/123/assignments` reads a permitted endpoint.
`herald-canvas keepalive` renews the session now.

Writes go through Herald's red-action door as `canvas.request` and
`canvas.submit`. A submission re-checks the approved file's bytes before
upload, and uploads go to storage hosts without your Canvas cookies. Quizzes
and external tools are blocked outright.

## Security

Every request to the login page checks your Tailscale identity and the
configured host, and WebSockets must come from the same origin. The VNC and
WebSocket backends listen only on loopback, and the tailnet route is removed
when the login service stops. Cookies and the browser profile stay in
`canvas.auth_dir` with private permissions. Nothing records screenshots or
keystrokes. How long your school's sessions and Duo trust last is up to your
school; keepalive cannot promise they never expire.
