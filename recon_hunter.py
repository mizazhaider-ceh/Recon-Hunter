#!/usr/bin/env python3
"""recon_hunter.py - Exam-Grade Recon + Source-Code Analyzer.

Single-file, stdlib only, threaded, polite. Built for authorized web
pentesting labs / CTFs. It automates the rule every exam needs ("View Source
first") AND analyzes the source the way you would by hand, then prints one
full report. For a page (or a whole sweep of challenges) it pulls out:

  - HTML comments IN FULL (where instructors hide hints, keys, request shapes)
  - every form: method, action, and each input NAME (your -p / fields)
  - <select> dropdowns and their options, with missing values flagged
    (parameter-tampering targets)
  - hidden inputs, data-* attributes, <meta> tags, title and headings
  - inline <script> contents and secrets (key / token / flag / base64)
  - ALL interesting RESPONSE HEADERS (custom headers often leak the key)
  - cookies the page sets (the KeyChallengeN chain)
  - a DECODER that auto base64 / hex / URL-decodes anything that looks encoded
    (and double-base64), so the plaintext key just appears
  - linked assets (.js / .css / .txt); with --assets it fetches and scans them
  - a NEXT STEPS advisor that suggests the likely vulnerability and tool

SWEEP MODE fetches a whole range of challenges and ends with a CHALLENGE MAP:
one table row per challenge (solved? inject field, hint, title).

Not a scanner / not a DoS tool: it only GETs the pages you point it at.
"""

import argparse
import base64
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
║      Recon Hunter - Recon + Source-Code Analyzer     ║
║ Comments|Forms|Headers|Cookies|Decoder|Sweep|Advise  ║
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
        f"\n{C.CYAN}-- A. Recon + analyze ONE page (full report) --{C.R}\n"
        f"    {C.GREEN}python recon_hunter.py \\\n"
        f"        -u \"https://site/challenge.php?challenge=2\" \\\n"
        f"        --cookie \"PHPSESSID=abc\" --insecure{C.R}\n"
        f"\n{C.CYAN}-- B. SWEEP every challenge at once (+ challenge map) --{C.R}\n"
        f"  Put {C.YELLOW}{{n}}{C.R} where the challenge number goes, give a range.\n"
        f"    {C.GREEN}python recon_hunter.py \\\n"
        f"        --sweep \"https://site/challenge.php?challenge={{n}}\" \\\n"
        f"        --range 1-15 --cookie \"PHPSESSID=abc\" --insecure{C.R}\n"
        f"\n{C.CYAN}-- C. Also fetch and scan linked JS/assets --{C.R}\n"
        f"  Flags often hide in a new .js file (double Base64). --assets pulls them.\n"
        f"    {C.GREEN}python recon_hunter.py -u URL --assets --cookie \"...\" --insecure{C.R}\n"
        f"\n{C.BOLD}WHAT IT FINDS (full, not cut off){C.R}\n"
        f"  {C.GREEN}comments {C.R} HTML comments in full (hints, keys, request shapes)\n"
        f"  {C.GREEN}forms    {C.R} method + action + every input NAME (your -p / fields)\n"
        f"  {C.GREEN}selects  {C.R} dropdown options, with MISSING values flagged (tampering)\n"
        f"  {C.GREEN}headers  {C.R} interesting response headers (custom ones leak keys)\n"
        f"  {C.GREEN}cookies  {C.R} Set-Cookie the page issues (KeyChallengeN chain)\n"
        f"  {C.GREEN}decoder  {C.R} auto base64 / hex / URL decode (and double-base64)\n"
        f"  {C.GREEN}secrets  {C.R} key / token / flag / password-looking strings in JS\n"
        f"  {C.GREEN}assets   {C.R} linked .js/.css/.txt; --assets fetches and scans them\n"
        f"  {C.GREEN}advise   {C.R} NEXT STEPS: likely vuln + which tool to use\n"
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
            + f"\n  {C.BOLD}Exam-grade recon + source-code analyzer.{C.R}"
            + f"\n  Reads a page and reports comments, forms, headers, cookies,"
            + f"\n  decoded secrets, assets, and the likely next move."
        ),
        epilog=epilog,
        add_help=False,
    )

    g_tgt = p.add_argument_group(f'{C.BOLD}TARGET{C.R}  (use -u OR --sweep)')
    g_tgt.add_argument(
        '-u', '--url', metavar='URL',
        help='Single page to recon and analyze.\n'
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
        help='Cookie header sent with every request, as name=value.\n'
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
        help='Word that marks a solved challenge. Default: congratulations.',
    )
    g_out.add_argument(
        '--assets', action='store_true',
        help='Also fetch each linked .js/.css/.txt and scan it for secrets and\n'
             'encoded strings. Use it to crack the "flag hidden in a .js" pattern.',
    )
    g_out.add_argument(
        '--full', action='store_true',
        help='Full untruncated detail even in sweep mode (long output).',
    )
    g_out.add_argument(
        '--show-scripts', action='store_true',
        help='Print inline <script> contents in full (noisy but complete).',
    )
    g_out.add_argument(
        '-o', '--output', metavar='FILE',
        help='Write the full plain-text report to this file as well.',
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
        self.selects = []
        self._cur_select = None

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
        elif tag in ('input', 'textarea'):
            info = {
                'name': d.get('name'),
                'type': d.get('type') or ('textarea' if tag == 'textarea' else 'text'),
                'value': d.get('value'),
            }
            self.inputs.append(info)
            if self._cur_form is not None:
                self._cur_form['inputs'].append(info)
        elif tag == 'select':
            info = {'name': d.get('name'), 'type': 'select', 'value': None}
            self.inputs.append(info)
            if self._cur_form is not None:
                self._cur_form['inputs'].append(info)
            self._cur_select = {'name': d.get('name'), 'options': []}
        elif tag == 'option':
            if self._cur_select is not None:
                self._cur_select['options'].append(d.get('value'))
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
        elif tag == 'link':
            if d.get('href'):
                self.links.append(d['href'])
        elif tag == 'meta':
            self.metas.append(d)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == 'form' and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None
        elif tag == 'select' and self._cur_select is not None:
            self.selects.append(self._cur_select)
            self._cur_select = None
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


def parse_page(text):
    p = PageParser()
    try:
        p.feed(text)
    except Exception:
        pass
    return p


# ============================================================
#  DECODER  (base64 / hex / URL, with double-base64)
# ============================================================
def _looks_text(s):
    s = s or ''
    if len(s) < 3:
        return False
    if any((ord(c) < 9) or (13 < ord(c) < 32) or ord(c) == 127 for c in s):
        return False
    letters = sum(c.isalpha() for c in s)
    return letters >= max(2, int(len(s) * 0.35))


def _decode_bytes(data):
    try:
        s = data.decode('utf-8')
    except Exception:
        return None
    return s if _looks_text(s) else None


def decode_chain(token, depth=0):
    """Return a list of (method, decoded_value) for anything that decodes."""
    token = (token or '').strip().strip('.,;:"\'')
    out = []
    if not token:
        return out
    if '%' in token:
        u = urllib.parse.unquote(token)
        if u != token and _looks_text(u):
            out.append(('URL-decoded', u))
    if re.fullmatch(r'[0-9a-fA-F]+', token) and len(token) % 2 == 0 and 6 <= len(token) <= 256:
        try:
            v = _decode_bytes(bytes.fromhex(token))
            if v:
                out.append(('hex-decoded', v))
        except Exception:
            pass
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', token) and len(token) >= 8 and len(token) % 4 == 0:
        try:
            dec = base64.b64decode(token, validate=True)
            v = _decode_bytes(dec)
            if v:
                out.append(('base64-decoded', v))
                if depth < 2:
                    for m2, v2 in decode_chain(v, depth + 1):
                        out.append(('base64 then ' + m2, v2))
        except Exception:
            pass
    return out


# ============================================================
#  ANALYSIS
# ============================================================
GREP_RE = re.compile(r"grep\s+for\s*['\"]?([^'\"<>\s]+)", re.I)
SECRET_KEYS = ('flag', 'ctf', 'secret', 'token', 'apikey', 'api_key', 'password',
               'passwd', 'pwd', 'key', 'congrat')
FLAGISH_RE = re.compile(r"(?:flag|ctf|key)\s*[:{]\s*[^\s}'\"<>]{3,}", re.I)
B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{6,}\b")

STD_HEADERS = {
    'date', 'content-type', 'content-length', 'connection', 'server', 'vary',
    'cache-control', 'expires', 'pragma', 'set-cookie', 'transfer-encoding',
    'content-encoding', 'accept-ranges', 'etag', 'last-modified', 'keep-alive',
    'x-powered-by', 'strict-transport-security', 'content-security-policy',
    'x-frame-options', 'x-content-type-options', 'referrer-policy', 'age', 'via',
    'access-control-allow-origin', 'x-xss-protection', 'permissions-policy',
    'upgrade', 'alt-svc', 'report-to', 'nel', 'cf-ray', 'cf-cache-status',
}
KEYWORDISH = ('key', 'flag', 'challenge', 'value', 'secret', 'token', 'hint',
              'pass', 'user', 'admin', 'next', 'unlock')
TEXTLIKE = (None, 'text', 'search', 'email', 'textarea', 'url', 'tel', 'password')


def find_hints(comments, scripts, metas, full_text):
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
                snippet = body[max(0, idx - 10):idx + 70].replace('\n', ' ').strip()
                add('script', snippet)
    for inp in inputs:
        if inp.get('type') == 'hidden' and inp.get('value'):
            add('hidden:' + (inp.get('name') or '?'), inp['value'])
    for tag, k, v in data_attrs:
        if v:
            add(f'{tag}[{k}]', v)
    return out


def get_set_cookies(resp_headers):
    return [v for (k, v) in resp_headers if k.lower() == 'set-cookie']


def interesting_headers(resp_headers):
    out = []
    for k, v in resp_headers:
        lk = k.lower()
        if lk == 'set-cookie':
            continue
        if lk not in STD_HEADERS or any(w in lk or w in v.lower() for w in KEYWORDISH):
            out.append((k, v))
    return out


def detect_selects(selects):
    out = []
    for s in selects:
        vals = [v for v in s['options'] if v is not None]
        nums, allnum = [], bool(vals)
        for v in vals:
            try:
                nums.append(int(v))
            except (TypeError, ValueError):
                allnum = False
        suggest = []
        if allnum and nums:
            lo, hi = min(nums), max(nums)
            present = set(nums)
            for n in range(max(0, lo - 2), lo):
                suggest.append(n)
            suggest.append(hi + 1)
            for n in range(lo, hi + 1):
                if n not in present:
                    suggest.append(n)
            seen = set()
            suggest = [x for x in suggest if not (x in seen or seen.add(x))]
        out.append({'name': s['name'] or '(select)', 'options': vals, 'suggest': suggest})
    return out


def collect_assets(p):
    out, seen = [], set()

    def add(kind, u):
        if u and u not in seen:
            seen.add(u)
            out.append((kind, u))

    for kind, val in p.scripts:
        if kind == 'src':
            add('js', val)
    for l in p.links:
        base = l.lower().split('?')[0]
        if base.endswith('.js'):
            add('js', l)
        elif base.endswith('.css'):
            add('css', l)
        elif base.endswith('.txt'):
            add('txt', l)
    return out


def find_decodes(p, resp_headers, full_text):
    """Return list of (source, token, method, decoded_value)."""
    results, seen = [], set()

    def consider(src, token):
        for method, val in decode_chain(token):
            key = (src, val)
            if key in seen:
                continue
            seen.add(key)
            results.append((src, token.strip(), method, val))

    for inp in p.inputs:
        if inp.get('value'):
            consider('hidden ' + (inp.get('name') or '?'), inp['value'])
    for tag, k, v in p.data_attrs:
        if v:
            consider('%s[%s]' % (tag, k), v)
    for ck in get_set_cookies(resp_headers):
        name, _, val = ck.partition('=')
        val = val.split(';')[0].strip()
        if val:
            consider('cookie ' + name.strip(), val)
    for k, v in resp_headers:
        if k.lower() != 'set-cookie' and v:
            consider('header ' + k, v)

    blobs = [('comment', c) for c in p.comments]
    for kind, body in p.scripts:
        if kind == 'inline':
            blobs.append(('script', body))
    for src, body in blobs:
        for m in B64_RE.finditer(body):
            consider(src, m.group(0))
        for m in HEX_RE.finditer(body):
            consider(src, m.group(0))
    # base64 sitting in plain page text (e.g. a <p> with a key blob)
    for m in B64_RE.finditer(full_text):
        consider('page', m.group(0))
    return results


def suggest(findings):
    p = findings['parser']
    tips = []
    pwd = any(i.get('type') == 'password' for i in p.inputs)
    texts = [i for i in p.inputs if i.get('name') and i.get('type') in TEXTLIKE
             and i.get('type') != 'password']
    if pwd:
        tips.append('Login form -> brute force with auth_hunter (-L users.txt -P pass.txt).')
    if texts:
        n = texts[0]['name']
        tips.append('Text field "%s" -> test XSS (xss_hunter -p %s) and SQLi '
                    "(submit a single ' then a single \" and watch for an error)." % (n, n))
    numlink = next((l for l in p.links if re.search(r'=\d+\b', l)), None)
    if numlink:
        tips.append('Numeric parameter in a link (%s) -> try IDOR (increment / swap the id).'
                    % numlink)
    if findings['decodes']:
        tips.append('Encoded string(s) decoded below -> submit the decoded value, or '
                    're-encode YOUR target the same way (encoding is not security).')
    for s in findings['selects']:
        if s['suggest']:
            tips.append('Dropdown "%s" shows {%s} -> try a value NOT in the list (e.g. %s) '
                        'for parameter tampering.'
                        % (s['name'], ','.join(map(str, s['options'])),
                           ','.join(str(x) for x in s['suggest'][:3])))
    if findings['headers']:
        tips.append('Custom response header(s) present -> the key may be leaked there '
                    '(see RESPONSE HEADERS above).')
    if findings['assets']:
        tips.append('Linked asset(s) found -> re-run with --assets to fetch and scan them '
                    '(flags love to hide in a .js, sometimes double-Base64).')
    return tips


def analyze(text, resp_headers, success_word):
    p = parse_page(text)
    f = {
        'parser': p,
        'solved': success_word.lower() in text.lower() if success_word else False,
        'hints': find_hints(p.comments, p.scripts, p.metas, text),
        'secrets': find_secrets(p.scripts, p.inputs, p.data_attrs),
        'cookies': get_set_cookies(resp_headers),
        'links': p.links,
        'headers': interesting_headers(resp_headers),
        'all_headers': list(resp_headers),
        'selects': detect_selects(p.selects),
        'decodes': find_decodes(p, resp_headers, text),
        'assets': collect_assets(p),
    }
    f['tips'] = suggest(f)
    return f


_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def _strip(s):
    return _ANSI_RE.sub('', s)


# ============================================================
#  RENDERING
# ============================================================
def fmt_field(inp):
    name = inp.get('name') or '(no name)'
    typ = inp.get('type') or 'text'
    val = inp.get('value')
    s = f'{name} ({typ})'
    if val:
        s += f' = {val}'
    return s


def render_page(label, url, status, findings, success_word, full, show_scripts, out_lines):
    def line(s=''):
        print(s)
        out_lines.append(_strip(s))

    def cut(s, n):
        s = ' '.join(str(s).split())
        return s if (full or len(s) <= n) else s[:n - 3] + '...'

    p = findings['parser']
    solved = findings['solved']
    badge = (f'{C.GREEN}{C.BOLD}[SOLVED]{C.R}' if solved else f'{C.GREY}[unsolved]{C.R}')
    title = p.title or (p.headings[0][1] if p.headings else '')
    line(f'\n{C.BOLD}{C.CYAN}=================== {label} ==================={C.R}  '
         f'{badge}  {C.DIM}status={status}{C.R}')
    line(f'  {C.DIM}{url}{C.R}')
    if title:
        line(f'  {C.BOLD}title  :{C.R} {title}')
    for tag, htext in (p.headings[:1] if not full else p.headings):
        if htext and htext != title:
            line(f'  {C.BOLD}heading:{C.R} {cut(htext, 120)}')

    # forms + selects (the inject fields)
    if p.forms:
        for fm in p.forms:
            line(f'  {C.BOLD}form   :{C.R} {fm["method"]} {fm["action"] or "(self)"}')
            for inp in fm['inputs']:
                inject = (inp.get('name') and inp.get('type') in TEXTLIKE)
                tag = (f'  {C.GREEN}<- inject here (-p {inp["name"]}){C.R}' if inject else '')
                line(f'      {C.YELLOW}{fmt_field(inp)}{C.R}{tag}')
    elif p.inputs:
        line(f'  {C.BOLD}inputs :{C.R} ' + ', '.join(fmt_field(i) for i in p.inputs))

    for s in findings['selects']:
        line(f'  {C.BOLD}select :{C.R} {s["name"]}  options={{{", ".join(map(str, s["options"]))}}}')
        if s['suggest']:
            line(f'      {C.MAG}missing from UI -> try {", ".join(str(x) for x in s["suggest"])}'
                 f'  (parameter tampering){C.R}')

    # response headers (the leak channel)
    hdrs = findings['all_headers'] if full else findings['headers']
    if hdrs:
        line(f'  {C.BOLD}{C.CYAN}response headers:{C.R}')
        for k, v in hdrs:
            mark = (f'  {C.MAG}<- custom / interesting{C.R}'
                    if any(w in k.lower() or w in v.lower() for w in KEYWORDISH) else '')
            line(f'      {C.CYAN}{k}:{C.R} {cut(v, 200)}{mark}')

    # cookies
    for ck in findings['cookies']:
        line(f'  {C.CYAN}set-cookie:{C.R} {ck}')

    # decoder output (the star of the show)
    if findings['decodes']:
        line(f'  {C.BOLD}{C.GREEN}decoded values:{C.R}')
        for src, token, method, val in findings['decodes']:
            line(f'      {C.GREEN}{val}{C.R}  {C.DIM}({method}, from {src}: {cut(token, 48)}){C.R}')

    # hints / comments IN FULL
    for kind, text in findings['hints']:
        if kind == 'GREP HINT':
            line(f'  {C.MAG}{C.BOLD}HINT   :{C.R} {C.MAG}{text}{C.R}')
        else:
            line(f'  {C.DIM}comment:{C.R} {cut(text, 200)}')

    # secrets
    for src, val in findings['secrets']:
        line(f'  {C.RED}secret :{C.R} ({src}) {cut(val, 160)}')

    # assets
    if findings['assets']:
        line(f'  {C.BOLD}assets :{C.R} '
             + ', '.join(f'{u}' for _, u in findings['assets']))

    # links
    if findings['links']:
        shown = findings['links'] if full else findings['links'][:8]
        extra = ('' if full or len(findings['links']) <= 8
                 else f'  (+{len(findings["links"]) - 8} more, use --full)')
        line(f'  {C.DIM}links  :{C.R} ' + ', '.join(shown) + extra)

    if full and show_scripts:
        for kind, body in p.scripts:
            if kind == 'inline':
                line(f'  {C.DIM}inline script:{C.R}\n      ' + body.replace('\n', '\n      '))
            else:
                line(f'  {C.DIM}script src:{C.R} {body}')

    # next steps advisor
    if findings['tips']:
        line(f'  {C.BOLD}{C.YELLOW}NEXT STEPS:{C.R}')
        for t in findings['tips']:
            line(f'      {C.YELLOW}>{C.R} {t}')


# ============================================================
#  ASSET FETCH & SCAN
# ============================================================
def scan_assets(base_url, assets, headers, args, out_lines):
    def line(s=''):
        print(s)
        out_lines.append(_strip(s))

    for kind, ref in assets:
        full_url = urllib.parse.urljoin(base_url, ref)
        status, text, rh, err = send(full_url, headers, args.timeout, args.insecure)
        if err is not None:
            line(f'  {C.RED}asset {ref}: {err}{C.R}')
            continue
        line(f'  {C.BOLD}asset:{C.R} {ref}  {C.DIM}({status}, {len(text)} bytes){C.R}')
        hits = 0
        for m in FLAGISH_RE.finditer(text):
            line(f'      {C.RED}flagish:{C.R} {m.group(0)}')
            hits += 1
        seen = set()
        for m in list(B64_RE.finditer(text)) + list(HEX_RE.finditer(text)):
            for method, val in decode_chain(m.group(0)):
                if val in seen:
                    continue
                seen.add(val)
                line(f'      {C.GREEN}decoded:{C.R} {val}  {C.DIM}({method}){C.R}')
                hits += 1
        if hits == 0:
            line(f'      {C.DIM}(no secrets or encoded strings found){C.R}')


# ============================================================
#  SUMMARY TABLE  (the one-glance challenge map)
# ============================================================
def primary_field(findings):
    for fm in findings['parser'].forms:
        for inp in fm['inputs']:
            if inp.get('name') and inp.get('type') in TEXTLIKE:
                return inp['name']
    for inp in findings['parser'].inputs:
        if inp.get('name'):
            return inp['name']
    return '-'


def hint_keyword(findings):
    for kind, text in findings['hints']:
        if kind == 'GREP HINT':
            m = re.search(r'grep keyword:\s*(\S+)', text)
            if m:
                return m.group(1)
    if findings['decodes']:
        return 'decoded!'
    return '-'


def page_title(findings):
    p = findings['parser']
    t = p.title or (p.headings[0][1] if p.headings else '')
    return ' '.join(t.split())


def render_summary(rows, out_lines):
    def line(s=''):
        print(s)
        out_lines.append(_strip(s))

    line(f'\n{C.BOLD}=================== CHALLENGE MAP ==================={C.R}')
    header = '  %-12s %-7s %-16s %-14s %s' % ('target', 'solved', 'inject (-p)',
                                              'hint/decode', 'title')
    line(f'{C.DIM}{header}{C.R}')
    line(f'{C.DIM}  {"-" * 70}{C.R}')
    for label, solved, field, hint, title in rows:
        row = '  %-12s %-7s %-16s %-14s %s' % (
            label[:12], 'yes' if solved else ('err' if solved is None else 'no'),
            (field or '-')[:16], (hint or '-')[:14], (title or '')[:40])
        if solved is True:
            print(f'{C.GREEN}{row}{C.R}')
        elif solved is None:
            print(f'{C.RED}{row}{C.R}')
        else:
            print(row)
        out_lines.append(_strip(row))
    solved_n = sum(1 for r in rows if r[1] is True)
    hinted = [r for r in rows if r[3] and r[3] != '-']
    line(f'{C.DIM}  {"-" * 70}{C.R}')
    line(f'  {C.GREEN}solved: {solved_n}{C.R}   '
         f'{C.MAG}with hint/decode: {len(hinted)}{C.R}   total: {len(rows)}')


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
    if args.sweep:
        if '{n}' not in args.sweep:
            raise ValueError('--sweep TEMPLATE must contain {n}, '
                             'e.g. ".../challenge.php?challenge={n}"')
        nums = parse_range(args.range) if args.range else [1]
        return [(f'challenge {n}', args.sweep.replace('{n}', str(n))) for n in nums]

    url = args.url
    if args.range:
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
#  SELF-TEST
# ============================================================
SAMPLE_HTML = """
<html><head><title>Challenge - Cave of Wonders</title>
<script src="/assets/details.js"></script></head><body>
<!-- The key for the first lesson is 6Yd0P -->
<!-- /challenge.php?challenge=4&user=6775657374 -->
<h1>Quick, become the Sultan!</h1>
<p>VGhpcyBpcyBub3QgdGhlIGNvcnJlY3Qga2V5Lg==</p>
<form method="POST" action="/challenge.php?challenge=13">
    <select name="users">
        <option value=2>Aladdin</option>
        <option value=4>Jasmine</option>
        <option value=6>Genie</option>
        <option value=8>Jafar</option>
        <option value=10>Abu</option>
    </select>
    <input type="hidden" name="csrf" value="a1b2c3">
    <input type="submit" value="Submit">
</form>
<a href="/challenge.php?challenge=9&id=1">next</a>
</body></html>
"""

SAMPLE_HEADERS = [
    ('Content-Type', 'text/html'),
    ('Challengevalue', 'MakewayforPrinceAli'),
    ('Set-Cookie', 'KeyChallenge8=You%2C%20uh%2C%20you%20don%27t%20want%20to%20go; path=/'),
]


def run_selftest():
    print(banner())
    print(f'\n{C.BOLD}[selftest] analyzing a built-in sample challenge page...{C.R}')
    findings = analyze(SAMPLE_HTML, SAMPLE_HEADERS, 'congratulations')
    render_page('SAMPLE', '(built-in)', 200, findings, 'congratulations', True, False, [])
    checks = {
        'form/select parsed': bool(findings['selects'] and findings['selects'][0]['suggest']),
        'hex decoded (guest)': any(v == 'guest' for _, _, _, v in findings['decodes']),
        'base64 decoded': any('correct key' in v.lower() for _, _, _, v in findings['decodes']),
        'url-decoded cookie': any('want to go' in v.lower() for _, _, _, v in findings['decodes']),
        'custom header found': any('challengevalue' == k.lower() for k, _ in findings['headers']),
        'comment key in full': any('6Yd0P' in t for _, t in findings['hints']),
        'asset (details.js)': any('details.js' in u for _, u in findings['assets']),
        'advisor tips': bool(findings['tips']),
    }
    print()
    ok = all(checks.values())
    for name, passed in checks.items():
        mark = f'{C.GREEN}PASS{C.R}' if passed else f'{C.RED}FAIL{C.R}'
        print(f'  [{mark}] {name}')
    print(f'\n{C.GREEN if ok else C.RED}[selftest] {"ALL OK" if ok else "SOME CHECKS FAILED"}{C.R}')
    return 0 if ok else 1


# ============================================================
#  MAIN
# ============================================================
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
          f'{C.BOLD}Assets:{C.R} {"on" if args.assets else "off"}   '
          f'{C.BOLD}Solved word:{C.R} "{args.success_word}"')

    cookie_safety_check(args)

    out_lines = []
    sweep = len(targets) > 1
    full = args.full or not sweep
    fetched = 0
    solved_count = 0
    ssl_hint_shown = False
    summary_rows = []

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

    for label, url, status, text, rh, err in results:
        if err is not None:
            print(f'\n{C.BOLD}{C.CYAN}== {label} =={C.R}  {C.RED}[error]{C.R} {err}')
            out_lines.append(f'== {label} == [error] {err}')
            summary_rows.append((label, None, 'err', '-', _strip(str(err))[:40]))
            if ('SSL' in err or 'cert' in err.lower()) and not ssl_hint_shown:
                ssl_hint_shown = True
                print(f'  {C.YELLOW}Add --insecure for self-signed lab certs.{C.R}')
            continue
        fetched += 1
        findings = analyze(text, rh, args.success_word)
        if findings['solved']:
            solved_count += 1
        summary_rows.append((label, bool(findings['solved']),
                             primary_field(findings), hint_keyword(findings),
                             page_title(findings)))
        render_page(label, url, status, findings, args.success_word, full,
                    args.show_scripts, out_lines)
        if args.assets and findings['assets']:
            scan_assets(url, findings['assets'], headers, args, out_lines)

    if len(targets) > 1:
        render_summary(summary_rows, out_lines)

    print(f'\n{C.BOLD}=========== SUMMARY ==========={C.R}')
    print(f'  Pages fetched : {fetched} / {len(targets)}')
    if args.success_word:
        print(f'  {C.GREEN}Solved (contains "{args.success_word}"): {solved_count}{C.R}')

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write('\n'.join(out_lines) + '\n')
            print(f'  Full report saved to {C.CYAN}{args.output}{C.R}')
        except OSError as e:
            print(f'  {C.RED}Could not write {args.output}: {e}{C.R}')

    return 0 if fetched else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
