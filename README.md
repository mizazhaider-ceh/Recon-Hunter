<div align="center">

# 🔎 Recon-Hunter

### Exam-grade recon + source-code analyzer. Single file. Zero dependencies.

*Stop guessing the parameter, the hint, and the encoding. Let the page tell you.*

<br>

![Python](https://img.shields.io/badge/Python-3.7%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/Dependencies-NONE-2ECC71?style=for-the-badge)
![GUI](https://img.shields.io/badge/GUI-tkinter-9B59B6?style=for-the-badge&logo=windowsterminal&logoColor=white)
![Platform](https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20Kali-1F6FEB?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-F1C40F?style=for-the-badge)
![Authorized use only](https://img.shields.io/badge/Authorized%20use-ONLY-E74C3C?style=for-the-badge)

```text
╔══════════════════════════════════════════════════════╗
║      Recon Hunter - Recon + Source-Code Analyzer     ║
║ Comments|Forms|Headers|Cookies|Decoder|Sweep|Advise  ║
║          stdlib only · no DoS · polite               ║
╚══════════════════════════════════════════════════════╝
```

</div>

Recon-Hunter automates the first move of every web challenge: **View Source**.
You point it at a page (with your session cookie) and it reads the HTML for you,
then prints the things you would otherwise hunt for by hand: HTML comments where
instructors hide hints, every form with its inject field name (your `-p`), hidden
inputs and their values, secrets in inline scripts, the cookies the page sets,
and whether the page already shows a success word.

Its headline feature is **sweep mode**: hit a whole range of challenges in one
run and get a compact card for each, so you can see all of them, their inject
field, their hint, and which are already solved, at a glance.

It is one Python file with zero dependencies, so it runs anywhere Python 3 runs:
Kali, Windows, a fresh exam VM. No `pip install`. It is for **authorized**
testing only: labs, CTFs, and exam environments where you have permission.

---

## 📖 Table of contents

- [Why this tool exists](#-why-this-tool-exists)
- [The session cookie warning (read this first)](#-the-session-cookie-warning-read-this-first)
- [Install and requirements](#-install-and-requirements)
- [Graphical interface (GUI)](#-graphical-interface-gui)
- [Quick start](#-quick-start)
- [Sweep mode: see every challenge at once](#-sweep-mode-see-every-challenge-at-once)
- [What it finds](#-what-it-finds)
- [Every flag, explained](#-every-flag-explained)
- [How it feeds the other Hunters](#-how-it-feeds-the-other-hunters)
- [Troubleshooting](#-troubleshooting)
- [Author](#-author)

---

## 💡 Why this tool exists

In a web exam the slowest part is often the start: open the page, read the
source, find which field is injectable, spot the instructor's hint in a comment,
remember which challenges you already solved. Recon-Hunter does all of that in
one command, for one page or for the whole set.

It exists because of two dead runs that waste exam time:

- Firing a fuzzer at the wrong parameter because you guessed the field name.
- Missing a "grep for X" hint that was sitting in an HTML comment all along.

Recon-Hunter reads the page once and hands you the field name and the hint, so
your XSS or SQLi run is right the first time.

---

## 🍪 The session cookie warning (read this first)

> ### Treat your session cookie as sacred
>
> **Do NOT change your browser during the exam.** If you must, carry the session
> to the new browser by hand. Switching browsers can drop your session.
>
> **Do NOT change your `sessionID` / `PHPSESSID`.** If it changes, the exam
> stops. The challenge state is tied to that one cookie value.
>
> **Treat the cookie as sacred:** never strip it, never regenerate it, never let
> a tool rotate it. Recon-Hunter sends your cookie exactly as you give it on
> every request, and echoes it before the first request so you can confirm.

Paste the cookie as **`name=value`**, for example `PHPSESSID=8f3a9c...`, not just
the value. Several are allowed, separated by `;`.

---

## ⚙️ Install and requirements

- **Python 3.7 or newer.** That is the only requirement for the command-line tool.
- No third-party packages. See `requirements.txt`.

```bash
git clone https://github.com/mizazhaider-ceh/Recon-Hunter.git
cd Recon-Hunter
python recon_hunter.py -h
```

On Windows use `python`, on most Linux boxes use `python3`.

---

## 🖥️ Graphical interface (GUI)

There is a full graphical front-end, `recon_hunter_gui.py`, also pure standard
library (tkinter), with a light / dark theme, hover tooltips, and a Help guide.

```bash
python recon_hunter_gui.py
```

There is nothing to `pip install`. On some Linux distros tkinter is a separate
system package, so if the GUI says `No module named 'tkinter'`, run
`sudo apt install python3-tk` (Debian / Ubuntu / Kali). See `requirements.txt`.

Keep `recon_hunter_gui.py` in the same folder as `recon_hunter.py`. The GUI
builds the exact `recon_hunter.py` command from the form and runs the real tool,
streaming its output live.

---

## 🚀 Quick start

Recon one page:

```bash
python recon_hunter.py \
    -u "https://target/challenge.php?challenge=2" \
    --cookie "PHPSESSID=your_live_session" \
    --insecure
```

You get the page title, the form (with the inject field marked), any HTML
comments and "grep for X" hints, secrets found in scripts, and the cookies the
page set.

---

## 🛰️ Sweep mode: see every challenge at once

This is the feature that saves the most time. Put `{n}` where the challenge
number goes and give a range:

```bash
python recon_hunter.py \
    --sweep "https://target/challenge.php?challenge={n}" \
    --range 1-15 \
    --cookie "PHPSESSID=your_live_session" \
    --insecure
```

You get one rich card per challenge, for example:

```
=== challenge 13 ===  [unsolved]  status=200
  title  : Quick, become the Sultan!
  form   : POST /challenge.php?challenge=13
      users (select)
  select : users  options={2, 4, 6, 8, 10}
      missing from UI -> try 0, 1, 11, 3, 5, 7, 9  (parameter tampering)
  response headers:
      Challengevalue: MakewayforPrinceAli  <- custom / interesting
  decoded values:
      guest  (hex-decoded, from comment: 6775657374)
      You, uh, you don't want to go  (URL-decoded, from cookie KeyChallenge8)
  HINT   : grep for 'tr0uble'   ->  grep keyword: tr0uble
  NEXT STEPS:
      > Dropdown "users" shows {2,4,6,8,10} -> try a value NOT in the list (e.g. 0,1,11)
      > Custom response header(s) present -> the key may be leaked there
```

In one run you learn, for every challenge: the inject field for your fuzzer, the
grep hint, which ones are already **SOLVED** (the page contains the success
word), and any cookies set along the way. If your URL already contains
`?challenge=2`, you can skip `--sweep` and just add `--range 1-15` to `-u`.

---

## 🔍 What it finds

It is recon **and** source-code analysis in one report, printed in full (no
cut-off):

| Section | What it pulls out |
|---------|-------------------|
| `comments` | HTML comments in full, where instructors hide hints, keys, and request shapes (the "grep for X" pattern is highlighted). |
| `form` | Each form's method, action, and every input name. The likely inject field is marked `<- inject here (-p NAME)`. |
| `select` | Dropdown options, with **missing values flagged** as parameter-tampering targets (the classic "value not in the UI" trick). |
| `response headers` | Interesting/custom response headers, because the key is often leaked in one (for example `Challengevalue:`). `--full` shows every header. |
| `set-cookie` | Cookies the page issues (for example the `KeyChallengeN` chain you need for later challenges). |
| `decoded values` | A built-in **decoder** that auto base64 / hex / URL-decodes anything that looks encoded, including **double-base64**, so the plaintext key just appears. |
| `secret` | Hidden inputs, data attributes, and strings in inline scripts that look like keys, tokens, flags, or passwords. |
| `assets` | Linked `.js` / `.css` / `.txt`. With `--assets` it fetches and scans each one (cracks the "flag hidden in a `.js`" pattern). |
| `NEXT STEPS` | An advisor that suggests the likely vulnerability and which tool to reach for. |
| `SOLVED` | Whether the body already contains the success word (default `congratulations`). |

Everything is shown in full. In `--full` mode (the default for a single page)
nothing is truncated, and `-o FILE` saves the whole report.

---

## 🚩 Every flag, explained

### Target (use `-u` OR `--sweep`)

| Flag | What it does |
|------|--------------|
| `-u`, `--url URL` | A single page to recon. Add `--range` to also sweep neighbouring challenge numbers. |
| `--sweep TEMPLATE` | A URL template with `{n}` where the number goes, e.g. `".../challenge.php?challenge={n}"`. Use with `--range`. |
| `--range A-B` | Number range for the sweep, e.g. `--range 1-15`. With `-u`, the number in `?challenge=N` is replaced. |

### Network and session

| Flag | What it does |
|------|--------------|
| `--cookie STR` | The Cookie header sent with every request, as `name=value`. Echoed for confirmation before the run. |
| `--header K:V` | An extra HTTP header. Repeatable. |
| `-t`, `--threads N` | Worker threads for sweep mode. Default 8, hard cap 20. |
| `--timeout N` | Per-request timeout in seconds. Default 10. |
| `--insecure` | Skip TLS certificate verification. Needed for self-signed lab certificates. |

### Output

| Flag | What it does |
|------|--------------|
| `--success WORD` | The word that marks a solved page. Default `congratulations`. |
| `--assets` | Fetch each linked `.js` / `.css` / `.txt` and scan it for secrets and encoded strings. Cracks the "flag hidden in a `.js`" pattern (sometimes double-base64). |
| `--full` | Full untruncated detail even in sweep mode (long output). |
| `--show-scripts` | Print inline `<script>` contents in full (noisy but complete). |
| `-o`, `--output FILE` | Also write the full plain-text report to a file. |
| `--no-color` | Disable ANSI colors. |
| `-y`, `--yes` | Skip the cookie-confirmation prompt. |

### Misc

| Flag | What it does |
|------|--------------|
| `-h`, `--help` | Show the full built-in help. |
| `--selftest` | Parse a built-in sample page offline and print the findings. Good first run. |

---

## 🔗 How it feeds the other Hunters

Recon-Hunter is the scout for the rest of the kit:

- It gives you the **inject field name** to drop into XSS-Hunter's `-p` or into
  the right field for Auth-Hunter.
- It gives you the **grep hint** so you can run with the correct `--grep`.
- It shows which challenges are **already solved**, so you do not waste a run.
- It surfaces the **`KeyChallengeN` cookie chain** you need before starting
  later challenges.

Typical flow: `recon_hunter --sweep ... --range 1-15` to map everything, then
point XSS-Hunter or Auth-Hunter at the one you want with the field and hint it
just handed you.

---

## 🩹 Troubleshooting

**Every page errors instantly.** Check the URL. A `view-source:` prefix copied
from the browser is not a real address; strip it. The tool warns about this.

**`malformed cookie segment`.** Paste the cookie as `name=value`
(`PHPSESSID=...`), not just the value.

**TLS certificate error.** Add `--insecure`; lab certs are self-signed.

**A page shows no form or comment.** Some content is rendered by JavaScript after
load, which a source reader cannot see. Fall back to the browser DevTools for
those, but most exam challenges are plain server-rendered HTML.

---

## 👤 Author

Built by **Muhammad Izaz Haider**, Student of CyberSecurity at Howest, lover of
AI and offensive security.

- GitHub: [@mizazhaider-ceh](https://github.com/mizazhaider-ceh)

Made for students, by a student. If it helped you pass, pass it on.

---

<div align="center">

### ⭐ If Recon-Hunter helped you, drop a star and share it with your class.

**Made with care for students, by a student.**

![Built by Muhammad Izaz Haider](https://img.shields.io/badge/Built%20by-Muhammad%20Izaz%20Haider-36C5F0?style=for-the-badge)
![AI x Offensive Security](https://img.shields.io/badge/AI%20x%20Offensive%20Security-9B59B6?style=for-the-badge)

</div>

---

### Legal and ethical use

Recon-Hunter is for **authorized** security testing only: your own systems,
explicit-permission engagements, CTFs, and exam labs where attacking the target
is the point. Reading a site you do not have permission to test can still be
unlawful. You are responsible for how you use it.
