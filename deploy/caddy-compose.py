#!/usr/bin/env python3
"""Compose the Caddyfile to install: secure-chat's deploy/Caddyfile plus every
foreign marker block of the live /etc/caddy/Caddyfile, carried over verbatim.

    python3 caddy-compose.py <new: deploy/Caddyfile> <live Caddyfile> <out> [<sites.d dir>]

/etc/caddy/Caddyfile is shared: other services on the box (the Kiosk news
app) keep their site in it between marker lines

    # >>> kiosk (managed by deploy.sh)
    ...
    # <<< kiosk

The 0.4.0 deploy installed deploy/Caddyfile over it wholesale and so took the
Kiosk site down (2026-09-26 20:13 UTC). The way forward is a file per service
in /etc/caddy/sites.d/, which deploy/Caddyfile imports and secure-chat never
touches; until every service writes there, this keeps their marker blocks.

Refuses (exit 1, nothing written) rather than guess:
  - a begin without its end, an end without its begin, nested or duplicate
    blocks, a near-miss marker, a marker line in deploy/Caddyfile itself;
  - anything OUTSIDE the marker blocks of the live file that deploy/Caddyfile
    does not also have (an unmarked site of another service would otherwise
    be dropped: the incident again);
  - a carried block or a sites.d/*.caddy file that names one of our own site
    addresses (e.g. a `log { hostnames <our host> ... }` would log our
    traffic, and a second site for it is not theirs to define).
A dropped block is a site down; a wrongly cut one may be a broken config -
both are for a human to look at. Running it on its own output gives the same
output (a re-run of the deploy changes nothing). Bytes are kept as they are
(no newline translation).

Runs on the box's system python3: standard library only.
"""
import os
import re
import sys

BEGIN = re.compile(r"#\s*>>>\s+(\S+)(\s.*)?")
END = re.compile(r"#\s*<<<\s+(\S+)\s*")


class MarkerError(Exception):
    pass


def _split(text):
    """([(name, block text incl. both marker lines)], [(line no, line) outside
    every marker block]), in file order."""
    blocks, outside = [], []
    current = None  # (name, [lines])
    for no, line in enumerate(text.splitlines(keepends=True), 1):
        s = line.strip()
        begin, end = BEGIN.fullmatch(s), END.fullmatch(s)
        if begin:
            if current:
                raise MarkerError(f"line {no}: '{s}' opens a block inside '# >>> {current[0]}'")
            current = (begin.group(1), [line])
        elif end:
            if not current:
                raise MarkerError(f"line {no}: '{s}' closes a block that was never opened")
            if end.group(1) != current[0]:
                raise MarkerError(f"line {no}: '{s}' closes '# >>> {current[0]}'")
            current[1].append(line if line.endswith(("\n", "\r")) else line + "\n")
            blocks.append((current[0], "".join(current[1])))
            current = None
        elif s.startswith("#") and (">>>" in s or "<<<" in s):
            # Close to a marker but not one: a typo here would silently drop
            # (or swallow) a site, so it is a human's call.
            raise MarkerError(f"line {no}: '{s}' looks like a marker but is not one")
        elif current:
            current[1].append(line)
        else:
            outside.append((no, line))
    if current:
        raise MarkerError(f"'# >>> {current[0]}' is never closed ('# <<< {current[0]}')")
    names = [n for n, _ in blocks]
    dups = sorted({n for n in names if names.count(n) > 1})
    if dups:
        raise MarkerError(f"marker block(s) more than once: {', '.join(dups)}")
    return blocks, outside


def marker_blocks(text):
    """[(name, block text incl. both marker lines)] in file order."""
    return _split(text)[0]


def top_level(lines):
    """The top-level entries of Caddyfile lines as (text, opens a block): a
    block's header (the text before its `{`; "" for the global options block)
    or a leaf line. Enough of the grammar for "is anything here that is not
    ours": comments and one-line quoted strings are dropped before braces are
    counted, and whatever this cannot model (a heredoc, a quote left open
    across lines, a line ending other than LF/CRLF) is refused, because a
    brace hidden in it could hide a whole site."""
    out, depth = [], 0
    for no, line in lines:
        if not line.endswith("\n") and line.splitlines()[0] != line:
            raise MarkerError(f"line {no}: a line ending other than LF or CRLF")
        # Strings first (a `#` in one is no comment), then comments.
        s = re.sub(r'"(?:\\.|[^"\\])*"|`[^`]*`', " STR ", line)
        s = re.sub(r"(^|\s)#.*$", "", s).strip()
        if '"' in s or "`" in s:
            raise MarkerError(f"line {no}: a quote left open across lines")
        if re.search(r"<<\S", s):
            raise MarkerError(f"line {no}: a heredoc")
        if not s:
            continue
        opens = s.endswith("{")
        if depth == 0:
            out.append((s[:-1].strip() if opens else s, opens))
        depth += s.count("{") - s.count("}")
        if depth < 0:
            raise MarkerError(f"line {no}: unbalanced '}}'")
    if depth:
        raise MarkerError("unbalanced '{' outside the marker blocks")
    return out


def _addresses(entries):
    """Site addresses: the headers of top-level BLOCKS ("" is the global
    options block, `(x)` a snippet; leaf lines like `import` are no sites)."""
    out = set()
    for h, opens in entries:
        if opens and h and not h.startswith("("):
            out.update(a.rstrip(",") for a in h.split())
    return out


def compose(new, live, sites=()):
    """deploy/Caddyfile, then each marker block of `live` after one blank line.

    `sites`: [(name, text)] of the sites.d files, only read: none may name one
    of deploy/Caddyfile's site addresses."""
    try:
        own, own_rest = _split(new)
    except MarkerError as e:
        raise MarkerError(f"deploy/Caddyfile: {e}") from None
    if own:
        raise MarkerError("deploy/Caddyfile must not hold marker blocks (they belong to other services)")
    ours = top_level(own_rest)
    try:
        carried, rest = _split(live)
        theirs = top_level(rest)
    except MarkerError as e:
        raise MarkerError(f"live Caddyfile: {e}") from None
    dropped = [t for t in theirs if t not in ours]
    if dropped:
        raise MarkerError(
            "live Caddyfile: outside any marker block and not in deploy/Caddyfile, "
            f"so it would be dropped: {[t for t, _ in dropped]} (another service's unmarked site?)")
    hosts = _addresses(ours)
    token = re.compile(r"(?<![\w.-])(" + "|".join(map(re.escape, sorted(hosts))) + r")(?![\w.-])", re.I) if hosts else None
    for where, text in [(f"marker block '{n}'", b) for n, b in carried] + [(f"sites.d/{n}", t) for n, t in sites]:
        hit = token.search(text) if token else None
        if hit:
            raise MarkerError(f"{where} names our own site address {hit.group(1)}")
    out = new.rstrip("\r\n") + "\n"
    for _name, block in carried:
        out += "\n" + block
    return out, [n for n, _ in carried]


def _read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def main(argv):
    if len(argv) not in (4, 5):
        sys.exit(__doc__.split("\n\n")[1])
    new_path, live_path, out_path = argv[1:4]
    try:
        new, live = _read(new_path), _read(live_path)
        sites = []
        if len(argv) == 5 and os.path.isdir(argv[4]):
            for n in sorted(os.listdir(argv[4])):
                if n.endswith(".caddy"):
                    sites.append((n, _read(os.path.join(argv[4], n))))
        out, names = compose(new, live, sites)
    except (MarkerError, OSError, UnicodeDecodeError) as e:
        print(f"!! {e}; nothing composed, decide by hand", file=sys.stderr)
        return 1
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        f.write(out)
    print("carried over from the live Caddyfile: " + (", ".join(names) if names else "(no marker blocks)"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
