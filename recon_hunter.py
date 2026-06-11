#!/usr/bin/env python3
"""recon_hunter.py - Exam-Grade Recon / View-Source Automator.

Single-file, stdlib only, threaded, polite. Built for authorized web
pentesting labs / CTFs. It automates the rule every exam needs: "View Source
first". Point it at a page (with your session cookie) and it pulls out the
things you would hunt for by hand:

  - HTML comments (where instructors hide hints like "grep for ...")
  - every form: method, action, and each input NAME (this is your -p / fields)
  - hidden inputs and their values (CSRF tokens, flags, ids)
  - data-* attributes, <meta> tags, page title and headings
  - inline <script> contents and suspicious secrets (key, token, flag, base64)
  - cookies the page sets (the KeyChallengeN chain), and links to other pages
  - whether the response already contains a success word (solved markers)

SWEEP MODE hits a whole range of challenges at once and prints one compact
card per challenge, so you can see ALL of them, their inject field, their
hint, and whether they are already solved, in a single run.

Not a scanner / not a DoS tool: it only GETs the pages you point it at.
"""

import argparse
import concurrent.futures
import gzip
import http.client
import os
import re
import socket
import ssl
import sys
import urllib.parse
import zlib
from html.parser import HTMLParser


# ============================================================
#  ANSI COLORS
# ============================================================
if os.name == 'nt':
    try:
        os.system('')
    except Exception:
        pass

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


class C:
    R = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    CYAN = '\033[36m'
    MAG = '\033[35m'
    BLUE = '\033[34m'
    GREY = '\033[90m'


def disable_colors():
    for k in list(vars(C).keys()):
        if not k.startswith('_'):
            setattr(C, k, '')


BANNER_TMPL = """{c}
╔══════════════════════════════════════════════════════╗
║        Recon Hunter - View-Source Automator          ║
║  Comments | Forms | Secrets | Cookies | Sweep-all    ║
║          stdlib only · no DoS · polite               ║
╚══════════════════════════════════════════════════════╝{r}"""


def banner():
    return BANNER_TMPL.format(c=C.CYAN, r=C.R)


# ============================================================
#  ARGPARSE - the help text IS the manual. Read once, never re-read.
# ============================================================
def build_parser():
    epilog = (
        f"\n{C.BOLD}USAGE SCENARIOS{C.R}  (read once before the exam)\n"
        f"\n{C.CYAN}-- A. Recon ONE page (full detail) --{C.R}\n"
        f"  See everything the page hides: comments, forms, fields, secrets.\n"
        f"    {C.GREEN}python recon_hunter.py \\\n"
        f"        -u \"https://site/challenge.php?challenge=2\" \\\n"
        f"        --cookie \"PHPSESSID=abc\" --insecure{C.R}\n"
        f"\n{C.CYAN}-- B. SWEEP every challenge at once (the big one) --{C.R}\n"
        f"  Put {C.YELLOW}{{n}}{C.R} where the challenge number goes, give a range.\n"
        f"  One compact card per challenge: inject field, hint, solved? cookies.\n"
        f"    {C.GREEN}python recon_hunter.py \\\n"
        f"        --sweep \"https://site/challenge.php?challenge={{n}}\" \\\n"
        f"        --range 1-15 --cookie \"PHPSESSID=abc\" --insecure{C.R}\n"
        f"\n{C.CYAN}-- C. Auto-range on a normal URL --{C.R}\n"
        f"  If the URL already has ?challenge=2, --range swaps the number for you.\n"
        f"    {C.GREEN}python recon_hunter.py -u \"https://site/challenge.php?challenge=2\" \\\n"
        f"        --range 1-15 --cookie \"PHPSESSID=abc\" --insecure{C.R}\n"
        f"\n{C.BOLD}WHAT IT FINDS{C.R}\n"
        f"  {C.GREEN}comments {C.R} HTML comments (instructors hide hints here, e.g. 'grep for X')\n"
        f"  {C.GREEN}forms    {C.R} method + action + every input NAME  (this is your -p / fields)\n"
        f"  {C.GREEN}hidden   {C.R} hidden input values (CSRF tokens, ids, flags)\n"
        f"  {C.GREEN}secrets  {C.R} key / token / flag / password / base64-looking strings in JS\n"
        f"  {C.GREEN}cookies  {C.R} Set-Cookie the page issues (the KeyChallengeN chain)\n"
        f"  {C.GREEN}solved   {C.R} whether the page already contains a success word\n"
        f"\n{C.BOLD}COOKIE SAFETY{C.R}\n"
        f"  Your PHPSESSID is sacred. The tool ECHOES the parsed cookie before any\n"
        f"  request and waits for ENTER. Ctrl-C to abort. {C.DIM}(-y skips the prompt){C.R}\n"
        f"\n{C.BOLD}EXIT CODES{C.R}\n"
        f"  0  at least one page fetched      2  argument / network error\n"
    )

    p = argparse.ArgumentParser(
        prog='recon_hunter.py',
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            banner()
            + f"\n  {C.BOLD}Exam-grade recon / View-Source automator.{C.R}"
            + f"\n  Pulls comments, forms, fields, secrets and cookies out of a page."
        ),
        epilog=epilog,
        add_help=False,
    )

    g_tgt = p.add_argument_group(f'{C.BOLD}TARGET{C.R}  (use -u OR --sweep)')
    g_tgt.add_argument(
        '-u', '--url', metavar='URL',
        help='Single page to recon.\n'
             '  example:  -u "https://site/challenge.php?challenge=2"\n'
             'Add --range to also sweep neighbouring challenge numbers.',
    )
    g_tgt.add_argument(
        '--sweep', metavar='TEMPLATE',
        help='URL template with {n} where the challenge number goes.\n'
             '  example:  --sweep "https://site/challenge.php?challenge={n}"\n'
             'Use with --range to fetch a whole batch at once.',
    )
    g_tgt.add_argument(
        '--range', metavar='A-B',
        help='Number range for sweep mode.  example:  --range 1-15\n'
             'With -u (no {n}), the number in ?challenge=N is replaced.',
    )

    g_net = p.add_argument_group(f'{C.BOLD}NETWORK & SESSION{C.R}')
    g_net.add_argument(
        '--cookie', metavar='STR',
        help='Cookie header sent with every request.\n'
             '  example:  --cookie "PHPSESSID=abc123"\n'
             'Echoed before the run so you can confirm the right session.',
    )
    g_net.add_argument(
        '--header', metavar='K:V', action='append', default=[],
        help='Extra HTTP header. Repeatable.\n'
             '  example:  --header "User-Agent: Mozilla/5.0"',
    )
    g_net.add_argument(
        '-t', '--threads', type=int, default=8,
        help='Worker threads for sweep mode. Default 8. Hard-capped at 20.',
    )
    g_net.add_argument(
        '--timeout', type=float, default=10.0,
        help='Per-request timeout in seconds. Default 10.',
    )
    g_net.add_argument(
        '--insecure', action='store_true',
        help='Skip TLS certificate verification (lab use only).',
    )

    g_out = p.add_argument_group(f'{C.BOLD}OUTPUT{C.R}')
    g_out.add_argument(
        '--success', dest='success_word', metavar='WORD', default='congratulations',
        help='Word that marks a solved challenge. Default: congratulations.\n'
             'Shown as SOLVED when the page body contains it.',
    )
    g_out.add_argument(
        '--full', action='store_true',
        help='Force full detail even in sweep mode (long output).',
    )
    g_out.add_argument(
        '--show-scripts', action='store_true',
        help='Print inline <script> contents (can be noisy).',
    )
    g_out.add_argument(
        '-o', '--output', metavar='FILE',
        help='Write a plain-text report to this file as well.',
    )
    g_out.add_argument(
        '--no-color', action='store_true',
        help='Disable ANSI colors.',
    )
    g_out.add_argument(
        '-y', '--yes', action='store_true',
        help='Skip the cookie-confirmation prompt.',
    )

    g_misc = p.add_argument_group(f'{C.BOLD}MISC{C.R}')
    g_misc.add_argument('-h', '--help', action='help', help='Show this help and exit.')
    g_misc.add_argument('--selftest', action='store_true',
                        help='Parse a built-in sample page and print findings (offline).')

    return p


# ============================================================
#  HTTP CLIENT
# ============================================================
DEFAULT_UA = 'Mozilla/5.0 (Recon-Hunter/1.0)'


def send(url, headers, timeout, insecure=False):
    """GET one URL. Returns (status, body_text, resp_headers_list, err_or_None)."""
    parsed = urllib.parse.urlparse(url)
    if not parsed.hostname:
        return 0, '', [], f'bad url: {url!r} (did you leave "view-source:" on the front?)'
    if parsed.scheme not in ('http', 'https'):
        return 0, '', [], (f'unsupported scheme {parsed.scheme!r} in {url!r} '
                           f'(strip any "view-source:" prefix)')
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    h = dict(headers)
    h.setdefault('User-Agent', DEFAULT_UA)
    h.setdefault('Accept', '*/*')
    h.setdefault('Host', host)
    h['Accept-Encoding'] = 'gzip, deflate'

    try:
        if parsed.scheme == 'https':
            ctx = (ssl._create_unverified_context()
                   if insecure else ssl.create_default_context())
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request('GET', path, headers=h)
        resp = conn.getresponse()
        raw = resp.read()
        enc = (resp.getheader('Content-Encoding') or '').lower().strip()
        try:
            if enc == 'gzip':
                raw = gzip.decompress(raw)
            elif enc == 'deflate':
                try:
                    raw = zlib.decompress(raw)
                except zlib.error:
                    raw = zlib.decompress(raw, -zlib.MAX_WBITS)
        except Exception:
            pass
        text = raw.decode('utf-8', errors='replace')
        resp_headers = resp.getheaders()
        try:
            conn.close()
        except Exception:
            pass
        return resp.status, text, resp_headers, None
    except ssl.SSLError as e:
        return 0, '', [], f'SSL: {e} (try --insecure)'
    except (http.client.HTTPException, ConnectionError, socket.error, OSError) as e:
        return 0, '', [], f'{type(e).__name__}: {e}'
    except Exception as e:
        return 0, '', [], f'{type(e).__name__}: {e}'


# ============================================================
#  HTML PARSER
# ============================================================
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.comments = []
        self.forms = []
        self._cur_form = None
        self.inputs = []
        self.links = []
        self.title = ''
        self._in_title = False
        self.headings = []
        self._cur_heading = None
        self.scripts = []
        self._in_script = False
        self._script_buf = ''
        self.metas = []
        self.data_attrs = []

    def handle_comment(self, data):
        t = data.strip()
        if t:
            self.comments.append(t)

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        for k, v in attrs:
            if k and k.startswith('data-'):
                self.data_attrs.append((tag, k, v or ''))
        if tag == 'form':
            self._cur_form = {
                'method': (d.get('method') or 'GET').upper(),
                'action': d.get('action') or '',
                'inputs': [],
            }
        elif tag in ('input', 'textarea', 'select'):
            info = {
                'name': d.get('name'),
                'type': d.get('type') or ('textarea' if tag == 'textarea' else 'text'),
                'value': d.get('value'),
            }
            self.inputs.append(info)
            if self._cur_form is not None:
                self._cur_form['inputs'].append(info)
        elif tag == 'a':
            if d.get('href'):
                self.links.append(d['href'])
        elif tag == 'title':
            self._in_title = True
        elif tag in ('h1', 'h2', 'h3'):
            self._cur_heading = tag
        elif tag == 'script':
            self._in_script = True
            self._script_buf = ''
            if d.get('src'):
                self.scripts.append(('src', d['src']))
        elif tag == 'meta':
            self.metas.append(d)

    def handle_startendtag(self, tag, attrs):
        # self-closing inputs / metas
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == 'form' and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None
        elif tag == 'title':
            self._in_title = False
        elif tag in ('h1', 'h2', 'h3'):
            self._cur_heading = None
        elif tag == 'script' and self._in_script:
            self._in_script = False
            if self._script_buf.strip():
                self.scripts.append(('inline', self._script_buf.strip()))

    def handle_data(self, data):
        if self._in_title:
            self.title += data.strip()
        if self._cur_heading:
            t = data.strip()
            if t:
                self.headings.append((self._cur_heading, t))
        if self._in_script:
            self._script_buf += data


# ============================================================
#  ANALYSIS
# ============================================================
GREP_RE = re.compile(r"grep\s+for\s*['\"]?([^'\"<>\s]+)", re.I)
SECRET_KEYS = ('flag', 'ctf', 'secret', 'token', 'apikey', 'api_key', 'password',
               'passwd', 'pwd', 'key', 'congrat')
FLAGISH_RE = re.compile(r"(?:flag|ctf|key)\s*[:{]\s*[^\s}'\"<>]{3,}", re.I)
B64_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def parse_page(text):
    p = PageParser()
    try:
        p.feed(text)
    except Exception:
        pass
    return p


def find_hints(comments, scripts, metas, full_text):
    """Return a list of (label, text) hint tuples."""
    hints = []
    for c in comments:
        m = GREP_RE.search(c)
        if m:
            hints.append(('GREP HINT', f'{c}   ->  grep keyword: {m.group(1)}'))
        else:
            hints.append(('comment', c))
    for m in GREP_RE.finditer(full_text):
        token = m.group(1)
        if not any(token in h[1] for h in hints):
            hints.append(('GREP HINT', f'grep keyword: {token}'))
    return hints


def find_secrets(scripts, inputs, data_attrs):
    """Return a list of secret-looking strings."""
    out = []
    seen = set()

    def add(src, val):
        val = (val or '').strip()
        if not val or val in seen:
            return
        seen.add(val)
        out.append((src, val))

    for kind, body in scripts:
        if kind != 'inline':
            continue
        for m in FLAGISH_RE.finditer(body):
            add('script', m.group(0))
        low = body.lower()
        for key in SECRET_KEYS:
            idx = low.find(key)
            if idx != -1:
                snippet = body[max(0, idx - 10):idx + 60].replace('\n', ' ').strip()
                add('script', snippet)
        for m in B64_RE.finditer(body):
            add('script(base64?)', m.group(0))
    for inp in inputs:
        if inp.get('type') == 'hidden' and inp.get('value'):
            add('hidden:' + (inp.get('name') or '?'), inp['value'])
    for tag, k, v in data_attrs:
        if v:
            add(f'{tag}[{k}]', v)
    return out


def get_set_cookies(resp_headers):
    return [v for (k, v) in resp_headers if k.lower() == 'set-cookie']


# ============================================================
#  RENDERING
# ============================================================
def fmt_field(inp):
    name = inp.get('name') or '(no name)'
    typ = inp.get('type') or 'text'
    val = inp.get('value')
    s = f'{name} ({typ})'
    if val:
        v = val if len(val) <= 40 else val[:37] + '...'
        s += f' = {v}'
    return s


def render_card(label, url, status, resp_headers, findings, success_word, out_lines):
    def line(s=''):
        print(s)
        out_lines.append(_strip(s))

    p = findings['parser']
    solved = findings['solved']
    badge = (f'{C.GREEN}{C.BOLD}[SOLVED]{C.R}' if solved
             else f'{C.GREY}[unsolved]{C.R}')
    title = p.title or (p.headings[0][1] if p.headings else '')
    line(f'\n{C.BOLD}{C.CYAN}== {label} =={C.R}  {badge}  '
         f'{C.DIM}status={status}{C.R}')
    line(f'  {C.DIM}{url}{C.R}')
    if title:
        line(f'  {C.BOLD}title :{C.R} {title}')

    # forms (the inject fields)
    if p.forms:
        for fm in p.forms:
            names = [i['name'] for i in fm['inputs'] if i.get('name')]
            line(f'  {C.BOLD}form  :{C.R} {fm["method"]} {fm["action"] or "(self)"}')
            for inp in fm['inputs']:
                tag = (f'{C.GREEN}<- inject here (-p {inp["name"]}){C.R}'
                       if inp.get('name') and inp.get('type') in (None, 'text', 'search',
                                                                  'textarea', 'email', None)
                       else '')
                line(f'      {C.YELLOW}{fmt_field(inp)}{C.R} {tag}')
    elif p.inputs:
        line(f'  {C.BOLD}inputs:{C.R} ' + ', '.join(fmt_field(i) for i in p.inputs))

    # hints (comments / grep)
    for kind, text in findings['hints']:
        if kind == 'GREP HINT':
            line(f'  {C.MAG}{C.BOLD}hint  :{C.R} {C.MAG}{text}{C.R}')
        else:
            line(f'  {C.DIM}comment:{C.R} {text}')

    # secrets
    for src, val in findings['secrets']:
        v = val if len(val) <= 80 else val[:77] + '...'
        line(f'  {C.RED}secret:{C.R} ({src}) {v}')

    # cookies the page set
    for ck in findings['cookies']:
        line(f'  {C.CYAN}set-cookie:{C.R} {ck}')

    # links to other challenges / pages
    if findings['links']:
        shown = findings['links'][:8]
        line(f'  {C.DIM}links :{C.R} ' + ', '.join(shown)
             + (f'  (+{len(findings["links"]) - 8} more)'
                if len(findings['links']) > 8 else ''))


def render_full(label, url, status, resp_headers, findings, success_word,
                show_scripts, out_lines):
    render_card(label, url, status, resp_headers, findings, success_word, out_lines)
    p = findings['parser']
    if p.metas:
        print(f'  {C.DIM}meta  :{C.R} ' + str(len(p.metas)) + ' tag(s)')
    if show_scripts:
        for kind, body in p.scripts:
            if kind == 'inline':
                snippet = body if len(body) <= 400 else body[:400] + ' ...'
                print(f'  {C.DIM}script:{C.R}\n      ' + snippet.replace('\n', '\n      '))
            else:
                print(f'  {C.DIM}script src:{C.R} {body}')


def analyze(text, resp_headers, success_word):
    p = parse_page(text)
    return {
        'parser': p,
        'solved': success_word.lower() in text.lower() if success_word else False,
        'hints': find_hints(p.comments, p.scripts, p.metas, text),
        'secrets': find_secrets(p.scripts, p.inputs, p.data_attrs),
        'cookies': get_set_cookies(resp_headers),
        'links': p.links,
    }


_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def _strip(s):
    return _ANSI_RE.sub('', s)


# ============================================================
#  COOKIE SAFETY
# ============================================================
def cookie_safety_check(args):
    if not args.cookie:
        print(f'{C.YELLOW}[!] No --cookie supplied. If the pages need a session, '
              f'add --cookie "PHPSESSID=..." first.{C.R}')
        return
    print(f'\n{C.BOLD}-- Cookie safety check --{C.R}')
    for seg in [s.strip() for s in args.cookie.split(';') if s.strip()]:
        if '=' in seg:
            k, _, v = seg.partition('=')
            red = v[:6] + '...' + v[-4:] if len(v) > 12 else v
            print(f'  {C.CYAN}{k.strip()}{C.R} = {red}')
        else:
            print(f'  {C.RED}malformed cookie segment: {seg!r} '
                  f'(use name=value, e.g. PHPSESSID=...){C.R}')
    print(f'{C.DIM}This cookie will be sent VERBATIM with every request.{C.R}')
    if args.yes:
        print(f'{C.DIM}--yes given - skipping confirmation.{C.R}\n')
        return
    try:
        input(f'{C.BOLD}Press ENTER to start, Ctrl-C to abort:{C.R} ')
    except (KeyboardInterrupt, EOFError):
        print(f'\n{C.YELLOW}[!] Aborted before any request was sent.{C.R}')
        sys.exit(0)


# ============================================================
#  TARGET BUILDING
# ============================================================
def parse_range(spec):
    spec = spec.strip()
    if '-' in spec:
        a, _, b = spec.partition('-')
        return list(range(int(a), int(b) + 1))
    return [int(spec)]


def build_targets(args):
    """Return list of (label, url)."""
    if args.sweep:
        if '{n}' not in args.sweep:
            raise ValueError('--sweep TEMPLATE must contain {n}, '
                             'e.g. ".../challenge.php?challenge={n}"')
        nums = parse_range(args.range) if args.range else [1]
        return [(f'challenge {n}', args.sweep.replace('{n}', str(n))) for n in nums]

    url = args.url
    if args.range:
        # replace the challenge number in ?challenge=N (or any =N) with each n
        nums = parse_range(args.range)
        m = re.search(r'(challenge=)(\d+)', url)
        if m:
            return [(f'challenge {n}', url[:m.start(2)] + str(n) + url[m.end(2):])
                    for n in nums]
        m2 = re.search(r'=(\d+)(\b)', url)
        if m2:
            return [(f'n={n}', url[:m2.start(1)] + str(n) + url[m2.end(1):]) for n in nums]
        raise ValueError('--range with -u needs a number in the URL '
                         '(e.g. ?challenge=2) to replace.')
    return [(url, url)]


def parse_headers(args_list):
    out = {}
    for hv in args_list:
        if ':' not in hv:
            raise ValueError(f'bad --header: {hv!r} (expected K:V)')
        k, _, v = hv.partition(':')
        out[k.strip()] = v.strip()
    return out


# ============================================================
#  MAIN
# ============================================================
SAMPLE_HTML = """
<html><head><title>Challenge 2 - Escape from Jasmine</title></head><body>
<!-- grep for 'tr0uble' (replace 0 with o) -->
<h1>Quick, create an alert to distract everybody!</h1>
<form method="POST" action="/challenge.php?challenge=2">
    <input type="text" name="alert">
    <input type="hidden" name="csrf_token" value="a1b2c3d4e5">
    <input type="submit" value="Submit">
</form>
<a href="/challenge.php?challenge=3">next challenge</a>
<div data-key="CaveOfWonders"></div>
<script>var apiKey = "S3cr3tApiKey_8f3a9c"; console.log("debug");</script>
</body></html>
"""


def run_selftest():
    print(banner())
    print(f'\n{C.BOLD}[selftest] parsing a built-in sample challenge page...{C.R}')
    findings = analyze(SAMPLE_HTML, [('Set-Cookie', 'KeyChallenge2=ride_the_carpet; path=/')],
                       'congratulations')
    render_full('SAMPLE', '(built-in)', 200, [], findings, 'congratulations', True, [])
    ok = (findings['parser'].forms
          and any('alert' == (i.get('name')) for i in findings['parser'].inputs)
          and any(k == 'GREP HINT' for k, _ in findings['hints'])
          and findings['secrets'] and findings['cookies'])
    print(f'\n{C.GREEN if ok else C.RED}[selftest] '
          f'{"OK - forms, grep hint, secret and cookie all parsed." if ok else "FAILED"}{C.R}')
    return 0 if ok else 1


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.no_color:
        disable_colors()

    if args.selftest:
        return run_selftest()

    if not args.url and not args.sweep:
        print(banner())
        parser.print_help()
        print(f'\n{C.RED}[!] Need either -u URL or --sweep TEMPLATE.{C.R}')
        return 2

    print(banner())

    if args.threads < 1:
        args.threads = 1
    if args.threads > 20:
        print(f'{C.YELLOW}[!] --threads {args.threads} capped to 20 (polite max).{C.R}')
        args.threads = 20

    try:
        targets = build_targets(args)
        extra_headers = parse_headers(args.header)
    except ValueError as e:
        print(f'{C.RED}[!] {e}{C.R}')
        return 2

    headers = {'User-Agent': DEFAULT_UA, 'Accept': '*/*'}
    headers.update(extra_headers)
    if args.cookie:
        headers['Cookie'] = args.cookie

    tls = f'{C.YELLOW}insecure{C.R}' if args.insecure else 'verify-tls'
    print(f'{C.BOLD}Targets :{C.R} {len(targets)}   '
          f'{C.BOLD}Threads:{C.R} {args.threads}   {C.BOLD}TLS:{C.R} {tls}   '
          f'{C.BOLD}Solved word:{C.R} "{args.success_word}"')

    cookie_safety_check(args)

    out_lines = []
    sweep = len(targets) > 1
    full = args.full or not sweep
    fetched = 0
    solved_count = 0
    ssl_hint_shown = False

    def fetch(item):
        label, url = item
        status, text, rh, err = send(url, headers, args.timeout, args.insecure)
        return label, url, status, text, rh, err

    results = []
    if sweep:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for res in ex.map(fetch, targets):
                results.append(res)
    else:
        results.append(fetch(targets[0]))

    # keep input order
    for label, url, status, text, rh, err in results:
        if err is not None:
            print(f'\n{C.BOLD}{C.CYAN}== {label} =={C.R}  {C.RED}[error]{C.R} {err}')
            out_lines.append(f'== {label} == [error] {err}')
            if ('SSL' in err or 'cert' in err.lower()) and not ssl_hint_shown:
                ssl_hint_shown = True
                print(f'  {C.YELLOW}Add --insecure for self-signed lab certs.{C.R}')
            continue
        fetched += 1
        findings = analyze(text, rh, args.success_word)
        if findings['solved']:
            solved_count += 1
        if full:
            render_full(label, url, status, rh, findings, args.success_word,
                        args.show_scripts, out_lines)
        else:
            render_card(label, url, status, rh, findings, args.success_word, out_lines)

    # summary
    print(f'\n{C.BOLD}=========== SUMMARY ==========={C.R}')
    print(f'  Pages fetched : {fetched} / {len(targets)}')
    if args.success_word:
        print(f'  {C.GREEN}Solved (contains "{args.success_word}"): {solved_count}{C.R}')

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write('\n'.join(out_lines) + '\n')
            print(f'  Report saved to {C.CYAN}{args.output}{C.R}')
        except OSError as e:
            print(f'  {C.RED}Could not write {args.output}: {e}{C.R}')

    return 0 if fetched else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
