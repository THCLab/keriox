#!/usr/bin/env python3
"""
KERI test vectors copied from the examples printed in the KERI specification.

Usage:
    python3 -I extract.py <spec repository> <out_dir>

Reads <spec repository>/spec/*.md (the examples are all in spec-body.md) and
writes <out_dir>/examples.json and <out_dir>/manifest.json.

Every fenced code block that holds one of the following becomes a vector,
with the line its content starts on and the section it is in:

  message    a KERI message body (a field map whose version string starts
             with "KERI"), together with its printed serialization (the
             Python byte string block that follows it) when there is one
  seal       a seal field map (a map without a version string whose labels
             are seal labels)
  threshold  a fractionally weighted signing threshold
  key-list   a list of public keys printed as the "next keys" a message's
             next key digests commit to
  uuid-list  the deterministic UUIDs of the "Working Examples Setup" annex

Each vector carries `checks`: the self-consistency of the example as far as
it can be computed from the printed text alone (no keys or salts are
needed): version string size, SAIDs, printed serialization against the
field map, CESR native decoding, field order against the order the
specification declares for the message type, and the links between
examples (prior event digests, next key commitments, delegation seals).
`consistent` is false when any check fails and `errata` lists why. The
examples are kept as printed, inconsistent or not, so a corrected
specification shows up as a changed vector.

The generator is self-contained (Python standard library only, including a
small BLAKE3 implementation) and deterministic.
"""
import ast
import base64
import json
import os
import re
import subprocess
import sys

TOOL_VERSION = "1.0.0"

# --------------------------------------------------------------------------
# BLAKE3 (default 32-byte hash), after the reference implementation
# --------------------------------------------------------------------------

_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
       0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_PERM = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_CHUNK_START, _CHUNK_END, _PARENT, _ROOT = 1, 2, 4, 8
_M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


def _g(s, a, b, c, d, x, y):
    s[a] = (s[a] + s[b] + x) & _M32
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _M32
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + y) & _M32
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _M32
    s[b] = _rotr(s[b] ^ s[c], 7)


def _compress(cv, block, counter, blen, flags):
    m = list(block)
    s = list(cv) + list(_IV[:4]) + [counter & _M32, (counter >> 32) & _M32,
                                    blen, flags]
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1])
        _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5])
        _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9])
        _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13])
        _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in _PERM]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _words(block):
    block = block.ljust(64, b"\0")
    return [int.from_bytes(block[i:i + 4], "little") for i in range(0, 64, 4)]


def _chunk_output(chunk, counter):
    """(cv, block words, counter, block len, flags) of a chunk's last block."""
    cv = list(_IV)
    blocks = [chunk[i:i + 64] for i in range(0, len(chunk), 64)] or [b""]
    for n, block in enumerate(blocks):
        flags = (_CHUNK_START if n == 0 else 0)
        if n == len(blocks) - 1:
            return (cv, _words(block), counter, len(block), flags | _CHUNK_END)
        cv = _compress(cv, _words(block), counter, 64, flags)[:8]


def _cv(out):
    return _compress(*out)[:8]


def _subtree(data, counter):
    """Output of the subtree over data, whose first chunk has index counter."""
    if len(data) <= 1024:
        return _chunk_output(data, counter)
    chunks = (len(data) + 1023) // 1024
    left = 1
    while left * 2 < chunks:
        left *= 2
    lo = _cv(_subtree(data[:left * 1024], counter))
    hi = _cv(_subtree(data[left * 1024:], counter + left))
    return (list(_IV), lo + hi, 0, 64, _PARENT)


def blake3(data):
    cv, block, counter, blen, flags = _subtree(bytes(data), 0)
    s = _compress(cv, block, 0 if flags & _PARENT else counter, blen,
                  flags | _ROOT)
    return b"".join(w.to_bytes(4, "little") for w in s[:8])


# --------------------------------------------------------------------------
# CESR helpers
# --------------------------------------------------------------------------

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
B64RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64int(text):
    n = 0
    for ch in text:
        n = n * 64 + B64.index(ch)
    return n


def int_b64(n, size):
    out = []
    for _ in range(size):
        out.append(B64[n % 64])
        n //= 64
    return "".join(reversed(out))


def b64decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def blake3_qb64(ser):
    """CESR qb64 of the Blake3-256 digest (code E) of ser."""
    return "E" + base64.urlsafe_b64encode(b"\0" + blake3(ser)).decode()[1:]


# fixed size primitive codes: code -> (hard size, soft size, xtra, full size)
FIXED = {}
for _c in "ABCDEFGHIJ":
    FIXED[_c] = (1, 0, 0, 44)
FIXED.update({
    "K": (1, 0, 0, 76), "L": (1, 0, 0, 76), "M": (1, 0, 0, 4),
    "N": (1, 0, 0, 12), "O": (1, 0, 0, 44), "P": (1, 0, 0, 124),
    "Q": (1, 0, 0, 44), "R": (1, 0, 0, 8), "S": (1, 0, 0, 16),
    "T": (1, 0, 0, 20), "U": (1, 0, 0, 24), "V": (1, 0, 0, 4),
    "W": (1, 0, 0, 4), "X": (1, 3, 0, 4), "Y": (1, 7, 0, 8),
    "0A": (2, 0, 0, 24), "0B": (2, 0, 0, 88), "0G": (2, 0, 0, 88),
    "0H": (2, 0, 0, 8), "0J": (2, 2, 1, 4), "0K": (2, 2, 0, 4),
    "0L": (2, 6, 1, 8), "0M": (2, 6, 0, 8), "0N": (2, 10, 1, 12),
    "0O": (2, 10, 0, 12), "1AAF": (4, 4, 0, 8), "1AAG": (4, 0, 0, 36),
    "1AAK": (4, 0, 0, 4), "1AAL": (4, 0, 0, 4), "1AAM": (4, 0, 0, 4),
    "1AAN": (4, 8, 0, 12),
})
NUMBERS = {"M", "N", "R", "S", "T", "U", "0H"}
TAGS = {"X", "Y", "0J", "0K", "0L", "0M", "0N", "0O", "1AAF", "1AAN"}
# variable size codes: selector of the lead size, kind letter
VARIABLE_KINDS = {"A": "strb64", "B": "bytes", "H": "decimal"}
# seal group count codes and the labels of each seal
SEAL_GROUPS = {"Q": ["d"], "R": ["rd"], "S": ["s", "d"], "T": ["i", "s", "d"],
               "U": ["i"], "V": ["bi", "d"], "W": ["t", "d"]}


class CesrError(ValueError):
    pass


def bext(chars, ls, escapive):
    """Text of a variable size Base64 string primitive (keripy Bexter)."""
    raw = b64decode(chars)[ls:]
    text = base64.urlsafe_b64encode(bytes(ls) + raw).decode()
    if text and ls == 0:
        ws = 1 if text[0] == "A" else 0
    else:
        ws = (ls + 1) % 4
    text = text[ws:]
    if escapive and text.startswith("-"):
        text = text[1:]
    return text


def primitive(qb64, at):
    """(kind, value, qb64, end) of the primitive at offset at."""
    first = qb64[at]
    if first in "456789":
        if first in "456":
            hs, ss = 2, 2
        else:
            hs, ss = 4, 4
        code = qb64[at:at + hs]
        ls = (int(first) - 4) % 3
        kind = VARIABLE_KINDS.get(code[-1] if hs == 2 else code[1:hs])
        if hs == 4:
            kind = VARIABLE_KINDS.get(code[3])
        if kind is None:
            raise CesrError(f"unsupported variable code {code!r} at {at}")
        size = b64int(qb64[at + hs:at + hs + ss]) * 4
        end = at + hs + ss + size
        if end > len(qb64):
            raise CesrError(f"primitive at {at} runs past the end")
        chars = qb64[at + hs + ss:end]
        if kind == "bytes":
            value = b64decode(chars)[ls:].decode("utf-8")
        else:
            value = chars, ls
        return kind, value, qb64[at:end], end
    for hs in (1, 2, 4):
        code = qb64[at:at + hs]
        if code in FIXED:
            break
    else:
        raise CesrError(f"unsupported code at {at}: {qb64[at:at + 4]!r}")
    hs, ss, xs, fs = FIXED[code]
    end = at + fs
    if end > len(qb64):
        raise CesrError(f"primitive at {at} runs past the end")
    text = qb64[at:end]
    if code in TAGS:
        return "tag", text[hs + xs:hs + ss], text, end
    if code in NUMBERS:
        return "number", format(b64int(text[hs:]), "x"), text, end
    if code == "1AAG":
        dts = text[4:].translate(str.maketrans("cdp", ":.+"))
        return "date", dts, text, end
    if code in ("1AAL", "1AAM", "1AAK"):
        return "special", {"1AAL": False, "1AAM": True, "1AAK": None}[code], \
            text, end
    return "matter", text, text, end


def counter(qb64, at):
    """(code letter, count in quadlets, end) of the count code at offset at."""
    if qb64.startswith("--", at):
        return qb64[at + 2], b64int(qb64[at + 3:at + 8]), at + 8
    if qb64[at] != "-":
        raise CesrError(f"expected a count code at {at}")
    return qb64[at + 1], b64int(qb64[at + 2:at + 4]), at + 4


def text_value(kind, value, escapive=True):
    if kind == "strb64":
        return bext(value[0], value[1], escapive)
    if kind == "decimal":
        return float(bext(value[0], value[1], False).replace("p", "."))
    return value


def item(qb64, at, field=None):
    """(value, end) of the item (primitive or group) at offset at."""
    if qb64[at] == "-":
        code, count, start = counter(qb64, at)
        end = start + count * 4
        if end > len(qb64):
            raise CesrError(f"group at {at} runs past the end")
        if code == "J":
            values, pos = [], start
            while pos < end:
                if qb64[pos] == "-" and counter(qb64, pos)[0] in SEAL_GROUPS:
                    seals, pos = seal_group(qb64, pos)
                    values.extend(seals)
                else:
                    v, pos = item(qb64, pos)
                    values.append(v)
            return values, end
        if code == "I":
            values, pos = {}, start
            while pos < end:
                kind, label, _, pos = primitive(qb64, pos)
                label = text_value(kind, label)
                v, pos = item(qb64, pos, label)
                values[label] = v
            return values, end
        if code in SEAL_GROUPS:
            return seal_group(qb64, at)
        raise CesrError(f"unsupported group code -{code} at {at}")
    kind, value, text, end = primitive(qb64, at)
    if field in ("r", "rr") and kind in ("strb64", "bytes"):
        if kind == "strb64":
            path = bext(value[0], value[1], False).removeprefix("--")
            return "/".join(path.split("-")), end
        return value, end
    if field in ("kt", "nt") and kind == "strb64":
        return weights(bext(value[0], value[1], True)), end
    return text_value(kind, value), end


def seal_group(qb64, at):
    code, count, start = counter(qb64, at)
    labels = SEAL_GROUPS[code]
    end = start + count * 4
    seals, pos = [], start
    while pos < end:
        seal = {}
        for label in labels:
            seal[label], pos = item(qb64, pos)
        seals.append(seal)
    return seals, end


def weights(text):
    """Weighted threshold from its Base64 infix form (keripy Tholder.limen)."""
    def weight(w):
        return w.replace("s", "/")

    clauses = []
    for clause in text.split("a"):
        elements = []
        for element in clause.split("c"):
            if "k" in element:
                key, rest = element.split("k", 1)
                elements.append({weight(key): [weight(w)
                                               for w in rest.split("v")]})
            else:
                elements.append(weight(element))
        clauses.append(elements)
    return clauses[0] if len(clauses) == 1 else clauses


# --------------------------------------------------------------------------
# Version strings
# --------------------------------------------------------------------------

V2RE = re.compile(r"^(?P<proto>[A-Z]{4})(?P<major>[A-Za-z0-9_-])"
                  r"(?P<minor>[A-Za-z0-9_-]{2})(?P<gmajor>[A-Za-z0-9_-])"
                  r"(?P<gminor>[A-Za-z0-9_-]{2})(?P<kind>[A-Z]{4})"
                  r"(?P<size>[A-Za-z0-9_-]{4})\.$")
V1RE = re.compile(r"^(?P<proto>[A-Z]{4})(?P<major>[0-9a-f])(?P<minor>[0-9a-f])"
                  r"(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_$")


def parse_version(vs):
    m = V2RE.match(vs)
    if m:
        return {"protocol": m["proto"],
                "version": f"{b64int(m['major'])}.{b64int(m['minor'])}",
                "genus_version": f"{b64int(m['gmajor'])}.{b64int(m['gminor'])}",
                "kind": m["kind"], "size": b64int(m["size"]),
                "native_prefix": vs[:10]}
    m = V1RE.match(vs)
    if m:
        return {"protocol": m["proto"],
                "version": f"{int(m['major'], 16)}.{int(m['minor'], 16)}",
                "kind": m["kind"], "size": int(m["size"], 16)}
    return None


# --------------------------------------------------------------------------
# Specification text
# --------------------------------------------------------------------------

FENCE = re.compile(r"^\s*```(\w*)\s*$")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
ORDER = re.compile(r"top-level fields of an? [^`]*`(\w{3})`[^`]*?following "
                   r"order:\s*`\[([^\]]*)\]`")
LABEL_ORDER = re.compile(r"^Field order by label:\s*(.*)$")
SAID_FIELDS = {"icp": ["d", "i"], "dip": ["d", "i"]}
NO_SAID = {"rct"}
SEAL_LABELS = {"d", "rd", "s", "i", "bi", "t"}


def literal(text):
    """(value, how) of a code block written as JSON or as a Python literal."""
    try:
        return json.loads(text), "json"
    except ValueError:
        pass
    try:
        return ast.literal_eval(text), "python"
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return None, None


def slug(text):
    text = re.sub(r"`|\[\[ref:\s*|\]\]", "", text).lower()
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-")


def blocks(lines):
    """(line, lang, headings, label order, text) of every fenced code block."""
    heads, label_order = [], None
    i = 0
    while i < len(lines):
        h = HEADING.match(lines[i])
        if h:
            level = len(h.group(1))
            heads = heads[:level - 1] + [""] * max(0, level - 1 - len(heads))
            heads = heads[:level - 1] + [h.group(2)]
            label_order = None
        lo = LABEL_ORDER.match(lines[i].strip())
        if lo:
            label_order = re.findall(r"`(\w+)`", lo.group(1))
        f = FENCE.match(lines[i])
        if f:
            start = i + 1
            j = start
            while j < len(lines) and not FENCE.match(lines[j]):
                j += 1
            yield (start + 1, f.group(1), [x for x in heads if x],
                   label_order, "\n".join(lines[start:j]))
            i = j + 1
            continue
        i += 1


def strip_assignment(text):
    """A block like `sad = \\` followed by a literal: the literal."""
    m = re.match(r"^\s*\w+\s*=\s*\\?\s*\n", text)
    return text[m.end():] if m else text


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

def valid_qb64(value):
    """None if value is a 44 character CESR primitive of a known code."""
    if not isinstance(value, str):
        return f"{value!r} is not a string"
    if not B64RE.match(value):
        return f"{value!r} has non-Base64 characters"
    if value[:1] in "BDE" and len(value) != 44:
        return f"{value!r} is {len(value)} characters, not 44"
    return None


def check_message(vec, orders):
    sad, checks, errata = vec["sad"], {}, []
    ilk = sad.get("t")
    vs = parse_version(sad["v"]) if isinstance(sad.get("v"), str) else None
    checks["version"] = vs
    if vs is None:
        errata.append(f"version string {sad.get('v')!r} does not parse")
        return checks, errata
    kind = vs["kind"]

    # field order against the order the body of the specification declares
    declared = orders.get(ilk)
    if declared is not None:
        ok = list(sad) == declared
        checks["field_order"] = {"declared": declared, "ok": ok,
                                 "declared_line": orders[ilk + "@line"]}
        if not ok:
            errata.append(f"fields {list(sad)} differ from the order the "
                          f"specification declares for {ilk} {declared} "
                          f"(line {orders[ilk + '@line']})")
    if vec.get("label_order") is not None:
        ok = list(sad) == vec["label_order"]
        checks["label_order"] = {"declared": vec["label_order"], "ok": ok}
        if not ok:
            errata.append(f"fields {list(sad)} differ from the 'Field order "
                          f"by label' line above the example "
                          f"{vec['label_order']}")

    # primitives that must be 44 character CESR primitives
    for label in ("d", "i", "p", "di", "ri", "x"):
        if label in sad:
            problem = valid_qb64(sad[label])
            if problem:
                errata.append(f"field {label}: {problem}")
    for label in ("k", "n", "b", "br", "ba"):
        for value in sad.get(label, []) if isinstance(sad.get(label), list) \
                else []:
            problem = valid_qb64(value)
            if problem:
                errata.append(f"field {label}: {problem}")
    if isinstance(sad.get("n"), list):
        bad = [x for x in sad["n"] if isinstance(x, str) and x[:1] != "E"]
        if bad:
            errata.append(f"next key digests n hold {bad}, which are not "
                          f"Blake3-256 digests (code E); a public key in n "
                          f"is not a next key commitment")

    # service endpoint URLs of replies
    attrs = sad.get("a") if isinstance(sad.get("a"), dict) else {}
    urls = ([attrs["url"]] if isinstance(attrs.get("url"), str) else []) + \
        [u for u in attrs.get("urls", []) if isinstance(u, str)]
    for url in urls:
        if url and not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url):
            errata.append(f"url {url!r} has no scheme:// prefix")
        elif url and isinstance(attrs.get("scheme"), str) and \
                not url.startswith(attrs["scheme"] + "://"):
            errata.append(f"url {url!r} does not use scheme "
                          f"{attrs['scheme']!r}")

    said_fields = [] if ilk in NO_SAID else [
        f for f in SAID_FIELDS.get(ilk, ["d"])
        if isinstance(sad.get(f), str) and sad.get(f)[:1] == "E"]

    raw = vec.get("raw")
    if kind == "JSON":
        ser = json.dumps(sad, separators=(",", ":"), ensure_ascii=False)
        size = len(ser.encode())
        checks["size"] = {"version": vs["size"], "computed": size,
                          "ok": vs["size"] == size}
        if vs["size"] != size:
            errata.append(f"version string size {vs['size']} but the "
                          f"serialization is {size} bytes")
        if raw is not None:
            ok = raw == ser
            checks["raw_matches_sad"] = ok
            if not ok:
                errata.append("printed serialization differs from the "
                              "compact JSON of the printed field map")
        if said_fields:
            dummied = dict(sad)
            for f in said_fields:
                dummied[f] = "#" * 44
            said = blake3_qb64(json.dumps(dummied, separators=(",", ":"),
                                          ensure_ascii=False).encode())
            checks["said"] = {"fields": said_fields, "computed": said,
                              "ok": all(sad[f] == said for f in said_fields)}
            for f in said_fields:
                if sad[f] != said:
                    errata.append(f"SAID field {f} is {sad[f]} but the SAID "
                                  f"of the serialization is {said}")
    elif kind == "CESR":
        if raw is None:
            errata.append("no printed native serialization to check")
            return checks, errata
        checks["size"] = {"version": vs["size"], "computed": len(raw),
                          "ok": vs["size"] == len(raw)}
        if vs["size"] != len(raw):
            errata.append(f"version string size {vs['size']} but the native "
                          f"serialization is {len(raw)} characters")
        try:
            decoded = decode_body(raw, sad, vs)
            ok = decoded == sad
            checks["raw_matches_sad"] = ok
            if not ok:
                diff = [k for k in list(dict.fromkeys(list(sad) +
                                                      list(decoded)))
                        if sad.get(k, "<missing>") !=
                        decoded.get(k, "<missing>")]
                checks["raw_decoded"] = decoded
                errata.append(f"native serialization decodes to a different "
                              f"field map (fields {diff} differ)")
        except CesrError as ex:
            checks["raw_matches_sad"] = False
            errata.append(f"native serialization does not decode: {ex}")
            return checks, errata
        if said_fields:
            # SAID slots follow the count code, version and message type
            _, _, start = counter(raw, 0)
            pos = start + 12 + 4
            dummied = raw
            for f in said_fields:
                dummied = dummied[:pos] + "#" * 44 + dummied[pos + 44:]
                pos += 44
            said = blake3_qb64(dummied.encode())
            checks["said"] = {"fields": said_fields, "computed": said,
                              "ok": all(sad[f] == said for f in said_fields)}
            for f in said_fields:
                if sad[f] != said:
                    errata.append(f"SAID field {f} is {sad[f]} but the SAID "
                                  f"of the native serialization is {said}")
    else:
        errata.append(f"serialization kind {kind} is not checked")
    return checks, errata


def decode_body(raw, sad, vs):
    """The field map a native CESR body decodes to, labelled by sad's keys."""
    code, count, start = counter(raw, 0)
    if code != "F":
        raise CesrError(f"expected a fixed field body count code -F, "
                        f"got -{code}")
    if start + count * 4 != len(raw):
        raise CesrError(f"count code says {count * 4} characters follow, "
                        f"{len(raw) - start} do")
    labels = list(sad)
    out, pos = {}, start
    for n, label in enumerate(labels):
        if pos >= len(raw):
            raise CesrError(f"body ends before field {label}")
        if n == 0:
            kind, value, text, pos = primitive(raw, pos)
            if text[:2] != "0O":
                raise CesrError(f"version field is {text!r}, not a Tag10")
            # the native version field carries no size: report the size the
            # version string should carry for the field map to match
            out[label] = sad[label] if value == vs["native_prefix"] else \
                f"{value}?"
            continue
        out[label], pos = item(raw, pos, label)
    if pos != len(raw):
        raise CesrError(f"{len(raw) - pos} characters left after the last "
                        f"field {labels[-1]}")
    return out


def check_seal(vec, orders):
    sad, errata = vec["sad"], []
    if vec["syntax"] != "json":
        errata.append("block is marked json but is not valid JSON")
    for label, value in sad.items():
        if label in ("d", "rd", "i", "bi"):
            problem = valid_qb64(value)
            if problem:
                errata.append(f"field {label}: {problem}")
        if label == "s" and not re.match(r"^(0|[1-9a-f][0-9a-f]*)$",
                                         str(value)):
            errata.append(f"field s: {value!r} is not lower case hex "
                          f"without leading zeros")
    declared = orders.get(vec["section"])
    checks = {}
    if declared:
        ok = list(sad) == declared
        checks["field_order"] = {"declared": declared, "ok": ok}
        if not ok:
            errata.append(f"fields {list(sad)} differ from the declared "
                          f"order {declared}")
    return checks, errata


def flat_weights(threshold):
    """(number of keys, clause sums as fractions) of a weighted threshold."""
    from fractions import Fraction
    clauses = threshold if threshold and isinstance(threshold[0], list) \
        else [threshold]
    keys, sums = 0, []
    for clause in clauses:
        total = Fraction(0)
        for w in clause:
            if isinstance(w, dict):
                (k, nested), = w.items()
                keys += len(nested)
                total += Fraction(k)
            else:
                keys += 1
                total += Fraction(w)
        sums.append(total)
    return keys, sums


def check_threshold(vec, orders):
    keys, sums = flat_weights(vec["value"])
    checks = {"keys": keys, "clause_sums": [str(s) for s in sums]}
    errata = [f"clause {n} weights sum to {s} < 1 and can never be satisfied"
              for n, s in enumerate(sums) if s < 1]
    return checks, errata


def check_uuids(vec, orders):
    expected = []
    for i in range(16):
        raw = b"kerispecworkraw" + b"%0x" % (i,)
        expected.append("0A" + base64.urlsafe_b64encode(b"\0\0" + raw)
                        .decode()[2:])
    ok = vec["value"] == expected
    checks = {"computed": expected, "ok": ok}
    return checks, ([] if ok else ["UUIDs differ from the Noncer encoding "
                                   "of the raws the annex prints"])


def link(vectors):
    """Checks across examples: prior digests, next key commitments, seals."""
    msgs = [v for v in vectors if v["type"] == "message"]
    by_kind = {}
    for v in msgs:
        kind = (v["checks"].get("version") or {}).get("kind")
        by_kind.setdefault(kind, []).append(v)
    for kind, group in by_kind.items():
        events = {}
        for v in group:
            sad = v["sad"]
            if sad.get("t") in ("icp", "dip", "ixn", "rot", "drt"):
                events[(sad.get("i"), sad.get("s"))] = v
        for (pre, sn), v in events.items():
            sad, links = v["sad"], v["checks"].setdefault("links", {})
            ilk = sad["t"]
            if ilk in ("ixn", "rot", "drt"):
                prior = events.get((pre, format(int(sn, 16) - 1, "x")))
                if prior is None:
                    links["prior"] = {"ok": None, "note": "prior event not "
                                      "printed"}
                else:
                    ok = sad.get("p") == prior["sad"].get("d")
                    links["prior"] = {"event": prior["id"], "ok": ok}
                    if not ok:
                        v["errata"].append(f"p is {sad.get('p')} but the "
                                           f"prior event {prior['id']} has "
                                           f"SAID {prior['sad'].get('d')}")
            if ilk in ("rot", "drt"):
                est = None
                for back in range(int(sn, 16) - 1, -1, -1):
                    e = events.get((pre, format(back, "x")))
                    if e and e["sad"]["t"] in ("icp", "dip", "rot", "drt"):
                        est = e
                        break
                if est is None:
                    links["next_keys"] = {"ok": None,
                                          "note": "prior establishment event "
                                                  "not printed"}
                else:
                    digs = [blake3_qb64(k.encode()) for k in sad.get("k", [])]
                    ok = digs == est["sad"].get("n")
                    links["next_keys"] = {"event": est["id"], "ok": ok,
                                          "digests_of_k": digs}
                    if not ok:
                        v["errata"].append(f"digests of the keys k do not "
                                           f"match the next key digests n of "
                                           f"{est['id']}")
            for seal in sad.get("a", []) if isinstance(sad.get("a"), list) \
                    else []:
                if isinstance(seal, dict) and set(seal) == {"i", "s", "d"}:
                    target = events.get((seal["i"], seal["s"]))
                    entry = {"seal": seal}
                    if target is None:
                        entry["ok"] = None
                        entry["note"] = "sealed event not printed"
                    else:
                        ok = target["sad"].get("d") == seal["d"]
                        entry.update(event=target["id"], ok=ok)
                        if not ok:
                            v["errata"].append(
                                f"seal {seal} does not match the SAID "
                                f"{target['sad'].get('d')} of {target['id']}")
                        if target["sad"]["t"] in ("dip", "drt"):
                            dip = events.get((seal["i"], "0"))
                            di = dip["sad"].get("di") if dip else None
                            if di is not None and di != pre:
                                v["errata"].append(
                                    f"seals delegated event {target['id']} "
                                    f"whose delegator is {di}, not {pre}")
                    links.setdefault("seals", []).append(entry)
            if ilk == "drt":
                dip = events.get((pre, "0"))
                anchor = None
                if dip is not None:
                    di = dip["sad"].get("di")
                    for (p2, _), e in events.items():
                        for seal in e["sad"].get("a", []) or []:
                            if (isinstance(seal, dict) and p2 == di and
                                    seal.get("i") == pre and
                                    seal.get("s") == sn):
                                anchor = e
                if anchor is None:
                    links["delegator_anchor"] = {"ok": None,
                                                 "note": "no printed delegator "
                                                         "event seals it"}
                else:
                    links["delegator_anchor"] = {"event": anchor["id"],
                                                 "ok": True}
        # receipts point at a printed event
        for v in group:
            sad = v["sad"]
            if sad.get("t") == "rct":
                target = events.get((sad.get("i"), sad.get("s")))
                links = v["checks"].setdefault("links", {})
                if target is None:
                    links["receipted"] = {"ok": None,
                                          "note": "receipted event not printed"}
                else:
                    ok = target["sad"].get("d") == sad.get("d")
                    links["receipted"] = {"event": target["id"], "ok": ok}
                    if not ok:
                        v["errata"].append(f"receipt d does not match the "
                                           f"SAID of {target['id']}")
        # an exchange message binds to the transaction it continues
        xips = {v["sad"].get("d"): v for v in group
                if v["sad"].get("t") == "xip"}
        for v in group:
            sad = v["sad"]
            if sad.get("t") == "exn":
                links = v["checks"].setdefault("links", {})
                target = xips.get(sad.get("x"))
                if target is None:
                    links["exchange"] = {"ok": None,
                                         "note": "xip of x not printed"}
                    continue
                problems = []
                if sad.get("p") != target["sad"]["d"]:
                    problems.append(f"p {sad.get('p')} is not the SAID of the "
                                    f"prior message {target['id']}")
                if {sad.get("i"), sad.get("ri")} != {target["sad"].get("i"),
                                                     target["sad"].get("ri")}:
                    problems.append(f"exn sender and receiver are not the "
                                    f"parties of {target['id']}")
                links["exchange"] = {"event": target["id"],
                                     "ok": not problems}
                v["errata"] += problems


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def collect(lines, file):
    orders, conflicts = {}, []
    for n, line in enumerate(lines, 1):
        for m in ORDER.finditer(line):
            ilk = m.group(1)
            fields = [f.strip() for f in m.group(2).split(",") if f.strip()]
            if ilk in orders and orders[ilk] != fields:
                conflicts.append(f"{ilk} declared as {orders[ilk]} (line "
                                 f"{orders[ilk + '@line']}) and as {fields} "
                                 f"(line {n})")
            orders.setdefault(ilk, fields)
            orders.setdefault(ilk + "@line", n)
    vectors, last_msg = [], None
    for line, lang, heads, label_order, text in blocks(lines):
        section = heads[-1] if heads else ""
        stripped = strip_assignment(text).strip()
        value, syntax = literal(stripped)
        if value is None:
            # `assert x == \` followed by the expected literal
            m = re.search(r"==\s*\\?\s*\n", stripped)
            if m:
                value, syntax = literal(stripped[m.end():].strip())
        base = {"section": section, "section_path": heads, "file": file,
                "line": line}
        same = last_msg is not None and last_msg["section_path"] == heads
        if isinstance(value, bytes):
            if same and "raw" not in last_msg:
                last_msg["raw"] = value.decode("utf-8")
                last_msg["raw_line"] = line
            continue
        if isinstance(value, dict) and isinstance(value.get("v"), str) and \
                value["v"].startswith("KERI"):
            vec = dict(type="message", **base, syntax=syntax, sad=value)
            if label_order is not None:
                vec["label_order"] = label_order
            vectors.append(vec)
            last_msg = vec
            continue
        if isinstance(value, dict) and value and set(value) <= SEAL_LABELS:
            vectors.append(dict(type="seal", **base, syntax=syntax,
                                sad=value))
            continue
        if lang == "json" and value is None and stripped.startswith("{"):
            # a field map that is neither JSON nor a Python literal
            vectors.append(dict(type="seal", **base, syntax=None,
                                text=stripped))
            continue
        if isinstance(value, list) and value and all(
                isinstance(x, (str, dict, list)) for x in value) and \
                any(isinstance(x, (dict, list)) or "/" in str(x)
                    for x in value):
            vectors.append(dict(type="threshold", **base, syntax=syntax,
                                value=value))
            continue
        if isinstance(value, list) and value and all(
                isinstance(x, str) and x.startswith("0A") for x in value):
            vectors.append(dict(type="uuid-list", **base, syntax=syntax,
                                value=value))
            continue
        if isinstance(value, list) and value and all(
                isinstance(x, str) and len(x) == 44 and x[0] in "BD"
                for x in value):
            vec = dict(type="key-list", **base, syntax=syntax, value=value)
            if same:
                vec["next_of"] = last_msg
            vectors.append(vec)
            continue
    vectors.extend(encodings(lines, file))
    return vectors, orders, conflicts


INLINE = re.compile(r"^\s*`([^`]+)`\s*$")


def encodings(lines, file):
    """Field value encodings printed as inline code in the CESR annex."""
    heads, found, blocks_in = [], {}, {}
    in_fence = False
    for n, line in enumerate(lines, 1):
        if FENCE.match(line):
            in_fence = not in_fence
            if in_fence:
                blocks_in.setdefault(tuple(heads), n + 1)
            continue
        if in_fence:
            continue
        h = HEADING.match(line)
        if h:
            level = len(h.group(1))
            heads = heads[:level - 1] + [h.group(2)]
            continue
        m = INLINE.match(line)
        if m:
            found.setdefault(tuple(heads), []).append((n, m.group(1)))
    out = []
    for heads, items in found.items():
        section = heads[-1] if heads else ""
        base = {"section": section, "section_path": list(heads),
                "file": file}
        title = section.lower()
        if "version" in title and len(items) == 1:
            n, text = items[0]
            out.append(dict(type="encoding", encoding="version", **base,
                            line=n, qb64=text))
        elif title.startswith("typed seal") and len(items) == 1:
            n, text = items[0]
            out.append(dict(type="encoding", encoding="seal-type", **base,
                            line=n, qb64=text))
        elif title == "datetime" and len(items) == 2:
            (n, value), (_, text) = items
            out.append(dict(type="encoding", encoding="datetime", **base,
                            line=n, value=value, b64=text))
        elif title.startswith("route") and len(items) == 2:
            (n, value), (_, text) = items
            out.append(dict(type="encoding", encoding="route", **base,
                            line=n, value=value, b64=text))
        elif title == "threshold" and len(items) == 1:
            n, text = items[0]
            start = blocks_in.get(heads)
            block = None
            if start is not None:
                j = start - 1
                body = []
                while j < len(lines) and not FENCE.match(lines[j]):
                    body.append(lines[j])
                    j += 1
                block, _ = literal("\n".join(body))
            out.append(dict(type="encoding", encoding="threshold", **base,
                            line=n, value=block, value_line=start, b64=text))
    return out


def strb64_qb64(text):
    """Fully qualified variable size Base64 string primitive (keripy Bexter)."""
    ws = (4 - len(text) % 4) % 4
    raw = b64decode("A" * ws + text)[ws * 3 // 4:]
    ls = (3 - len(raw) % 3) % 3
    chars = base64.urlsafe_b64encode(bytes(ls) + raw).decode()
    size = len(chars) // 4
    if size < 64 ** 2:
        return "456"[ls] + "A" + int_b64(size, 2) + chars
    return "789"[ls] + "AAA" + int_b64(size, 4) + chars


def threshold_b64(sith):
    """Base64 infix form of a weighted threshold (spec table, keripy limen)."""
    def weight(w):
        return w.replace("/", "s")

    def element(e):
        if isinstance(e, dict):
            (k, nested), = e.items()
            return weight(k) + "k" + "v".join(weight(w) for w in nested)
        return weight(e)
    clauses = sith if sith and isinstance(sith[0], list) else [sith]
    return "a".join("c".join(element(e) for e in clause) for clause in clauses)


def check_encoding(vec):
    kind, checks, errata = vec["encoding"], {}, []
    if kind == "version":
        _, value, text, end = primitive(vec["qb64"], 0)
        ok = end == len(vec["qb64"]) and text[:2] == "0O"
        parsed = parse_version(value + "JSONAAAA.") if ok else None
        checks.update(code="0O", decoded=parsed, ok=bool(parsed))
        if not parsed:
            errata.append(f"{vec['qb64']} is not a Tag10 version field")
    elif kind == "seal-type":
        _, value, text, end = primitive(vec["qb64"], 0)
        ok = end == len(vec["qb64"]) and text[0] == "Y" and len(value) == 7
        checks.update(code="Y", type=value[:4],
                      version=f"{b64int(value[4])}.{b64int(value[5:7])}",
                      ok=ok)
        if not ok:
            errata.append(f"{vec['qb64']} is not a Tag7 seal type")
    elif kind == "datetime":
        b64 = vec["value"].translate(str.maketrans(":.+", "cdp"))
        ok = b64 == vec["b64"]
        checks.update(computed=b64, qb64="1AAG" + b64, ok=ok)
        if not ok:
            errata.append(f"encoding of {vec['value']} is {b64}, not "
                          f"{vec['b64']}")
    elif kind == "route":
        b64 = "-".join(vec["value"].split("/"))
        ok = b64 == vec["b64"]
        checks.update(computed=b64, qb64=strb64_qb64(b64), ok=ok)
        if not ok:
            errata.append(f"encoding of {vec['value']} is {b64}, not "
                          f"{vec['b64']}")
    elif kind == "threshold":
        if vec.get("value") is None:
            errata.append("no threshold printed in the section to compare")
        else:
            b64 = threshold_b64(vec["value"])
            ok = b64 == vec["b64"]
            checks.update(computed=b64, qb64=strb64_qb64(b64), ok=ok,
                          printed_decodes_to=weights(vec["b64"]))
            if not ok:
                errata.append(f"infix encoding of the threshold is {b64}, "
                              f"the specification prints {vec['b64']}")
    return checks, errata


TRAIT_ROW = re.compile(r"^\|\s*`(\w+)`\s*\|([^|]*)\|\s*(True|False)\s*\|")


def config_traits(lines):
    """Configuration traits the specification defines: code -> inception only."""
    out = {}
    for line in lines:
        m = TRAIT_ROW.match(line)
        if m:
            out[m.group(1)] = {"title": m.group(2).strip(),
                               "inception_only": m.group(3) == "True"}
    return out


def threshold_problems(sith, keys, label):
    """Problems of threshold sith over a key list of length keys."""
    if isinstance(sith, str):
        if not re.match(r"^(0|[1-9a-f][0-9a-f]*)$", sith):
            return [f"{label} {sith!r} is not lower case hex without leading "
                    f"zeros"]
        n = int(sith, 16)
        if n > keys:
            return [f"{label} {n} exceeds the {keys} keys"]
        if n < 1 and keys:
            return [f"{label} 0 with {keys} keys"]
        return []
    if isinstance(sith, list):
        try:
            count, sums = flat_weights(sith)
        except (ValueError, ZeroDivisionError, TypeError) as ex:
            return [f"{label} {sith!r} is not a weighted threshold: {ex}"]
        problems = []
        if count != keys:
            problems.append(f"{label} has {count} weights for {keys} keys")
        problems += [f"{label} clause {n} sums to {s} < 1"
                     for n, s in enumerate(sums) if s < 1]
        return problems
    return [f"{label} {sith!r} is neither hex nor a weight list"]


def rules(vectors, traits):
    """Key event rules of the specification applied to the printed KELs."""
    groups = {}
    for v in vectors:
        if v["type"] == "message" and v["sad"].get("t") in (
                "icp", "dip", "rot", "drt", "ixn"):
            kind = (v["checks"].get("version") or {}).get("kind")
            groups.setdefault(kind, []).append(v)
    for group in groups.values():
        events = {(v["sad"].get("i"), v["sad"].get("s")): v for v in group}
        for v in group:
            sad, problems, notes = v["sad"], [], []
            ilk, sn = sad["t"], sad.get("s")
            if not isinstance(sn, str) or not re.match(
                    r"^(0|[1-9a-f][0-9a-f]*)$", sn):
                problems.append(f"s {sn!r} is not lower case hex without "
                                f"leading zeros")
                sn = "0"
            if ilk in ("icp", "dip") and sn != "0":
                problems.append(f"{ilk} has s {sn}, not 0")
            if ilk in ("icp", "dip", "rot", "drt"):
                problems += threshold_problems(sad.get("kt"),
                                               len(sad.get("k", [])), "kt")
                problems += threshold_problems(sad.get("nt"),
                                               len(sad.get("n", [])), "nt")
                if not sad.get("k"):
                    problems.append("empty current key list k")
                for trait in sad.get("c", []):
                    if trait not in traits:
                        problems.append(f"config trait {trait!r} is not "
                                        f"defined")
                    elif ilk in ("rot", "drt") and \
                            traits[trait]["inception_only"]:
                        problems.append(f"inception-only config trait "
                                        f"{trait!r} in {ilk}")
            # walk back to the latest establishment event for backers and EO
            prior_est = None
            for back in range(int(sn, 16) - 1, -1, -1):
                e = events.get((sad.get("i"), format(back, "x")))
                if e and e["sad"]["t"] in ("icp", "dip", "rot", "drt"):
                    prior_est = e
                    break
            if ilk in ("icp", "dip"):
                backers = list(sad.get("b", []))
                if len(set(backers)) != len(backers):
                    problems.append("duplicate backers in b")
            elif ilk in ("rot", "drt"):
                if prior_est is None:
                    backers = None
                    notes.append("prior backer list not printed")
                else:
                    current = backer_list(prior_est, events)
                    br, ba = sad.get("br", []), sad.get("ba", [])
                    missing = [w for w in br if w not in current]
                    if missing:
                        problems.append(f"br removes backers {missing} that "
                                        f"are not current")
                    kept = [w for w in current if w not in br]
                    dup = [w for w in ba if w in kept]
                    if dup or len(set(ba)) != len(ba):
                        problems.append(f"ba adds backers {dup or ba} that are "
                                        f"current or repeated")
                    backers = kept + list(ba)
            else:
                backers = None
                if prior_est is not None and "EO" in prior_est["sad"].get(
                        "c", []):
                    problems.append("interaction event in an "
                                    "establishment-only KEL")
            if backers is not None:
                bt = sad.get("bt")
                if not isinstance(bt, str) or not re.match(
                        r"^(0|[1-9a-f][0-9a-f]*)$", bt):
                    problems.append(f"bt {bt!r} is not lower case hex")
                elif int(bt, 16) > len(backers):
                    problems.append(f"bt {int(bt, 16)} exceeds the "
                                    f"{len(backers)} backers")
                elif backers and int(bt, 16) == 0:
                    problems.append(f"bt 0 with {len(backers)} backers")
            if ilk == "dip":
                problem = valid_qb64(sad.get("di"))
                if problem:
                    problems.append(f"di: {problem}")
            entry = {"ok": not problems}
            if backers is not None:
                entry["backers"] = backers
            if notes:
                entry["notes"] = notes
            if problems:
                entry["problems"] = problems
            v["checks"]["rules"] = entry
            v["errata"] += problems


def backer_list(est, events):
    """Backer list after establishment event est."""
    chain, e = [], est
    while e is not None:
        chain.append(e)
        if e["sad"]["t"] in ("icp", "dip"):
            break
        prior = None
        for back in range(int(e["sad"]["s"], 16) - 1, -1, -1):
            c = events.get((e["sad"]["i"], format(back, "x")))
            if c and c["sad"]["t"] in ("icp", "dip", "rot", "drt"):
                prior = c
                break
        e = prior
    if chain[-1]["sad"]["t"] not in ("icp", "dip"):
        return []
    backers = list(chain[-1]["sad"].get("b", []))
    for e in reversed(chain[:-1]):
        backers = [w for w in backers if w not in e["sad"].get("br", [])]
        backers += list(e["sad"].get("ba", []))
    return backers


def counterparts(vectors):
    """Compare the native CESR annex examples with their JSON originals.

    The annex says its examples are identical to the JSON examples of the
    body except for the serialization kind, so after mapping each JSON SAID
    to its CESR SAID every other field must match."""
    msgs = [v for v in vectors if v["type"] == "message"]
    json_by_ilk, cesr_by_ilk = {}, {}
    for v in msgs:
        kind = (v["checks"].get("version") or {}).get("kind")
        ilk = v["sad"].get("t")
        if kind == "JSON":
            json_by_ilk.setdefault(ilk, v)
        elif kind == "CESR":
            cesr_by_ilk.setdefault(ilk, v)
    pairs = [(json_by_ilk[k], cesr_by_ilk[k]) for k in cesr_by_ilk
             if k in json_by_ilk]
    subst = {}
    for j, c in pairs:
        for f in ("d", "i"):
            a, b = j["sad"].get(f), c["sad"].get(f)
            if isinstance(a, str) and isinstance(b, str) and a != b and \
                    a[:1] == "E":
                subst.setdefault(a, b)

    def mapped(value):
        if isinstance(value, str):
            return subst.get(value, value)
        if isinstance(value, list):
            return [mapped(x) for x in value]
        if isinstance(value, dict):
            return {k: mapped(x) for k, x in value.items()}
        return value

    for j, c in pairs:
        js, cs = j["sad"], c["sad"]
        labels = list(dict.fromkeys(list(js) + list(cs)))
        diff = [k for k in labels if k != "v" and
                mapped(js.get(k, "<missing>")) != cs.get(k, "<missing>")]
        c["checks"]["counterpart"] = {"of": j["id"], "ok": not diff,
                                      "fields": diff}
        if diff:
            c["errata"].append(
                f"fields {diff} differ from the JSON example {j['id']} the "
                f"annex says it is identical to")


def seal_orders(lines):
    """Seal field orders the specification declares, by section heading."""
    out, section = {}, None
    for line in lines:
        h = HEADING.match(line)
        if h:
            section = h.group(2)
        m = re.search(r"MUST appear in the following order\s*`\[([^\]]*)\]`",
                      line)
        if m and section and "top-level" not in line:
            out[section] = [f.strip() for f in m.group(1).split(",")]
    return out


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    spec, out = sys.argv[1], sys.argv[2]
    specdir = os.path.join(spec, "spec")
    try:
        revision = subprocess.run(["git", "-C", spec, "rev-parse", "HEAD"],
                                  capture_output=True, text=True,
                                  check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        revision = "unknown"

    vectors, orders, sorders, conflicts, traits, files = [], {}, {}, [], {}, []
    for name in sorted(os.listdir(specdir)):
        if not name.endswith(".md"):
            continue
        with open(os.path.join(specdir, name), encoding="utf-8") as f:
            lines = f.read().splitlines()
        found, found_orders, found_conflicts = collect(lines, f"spec/{name}")
        if found:
            files.append(f"spec/{name}")
        for k, v in found_orders.items():
            orders.setdefault(k, v)
        conflicts.extend(found_conflicts)
        for k, v in seal_orders(lines).items():
            sorders.setdefault(k, v)
        traits.update(config_traits(lines))
        vectors.extend(found)

    vectors.sort(key=lambda v: (v["file"], v["line"]))

    # names and ids: from the section, stable across unrelated edits
    seen = {}
    for vec in vectors:
        if vec["type"] == "message":
            sad = vec["sad"]
            vs = parse_version(sad["v"]) or {}
            kind = (vs.get("kind") or "unknown").lower()
            name = slug(vec["section"])
            if str(sad.get("t")) not in name.split("-"):
                name = f"{name}-{sad.get('t')}"
            name = f"{name}-{kind}"
        elif vec["type"] == "key-list" and "next_of" in vec:
            name = f"next-keys-of-{vec['next_of']['name']}"
        elif vec["type"] == "encoding":
            name = vec["encoding"]
        else:
            name = slug(vec["section"])
        seen[(vec["type"], name)] = seen.get((vec["type"], name), 0) + 1
        count = seen[(vec["type"], name)]
        vec["name"] = name if count == 1 else f"{name}-{count}"
        vec["id"] = f"spec/{vec['type']}/{vec['name']}"

    for vec in vectors:
        if vec["type"] == "message":
            vec["checks"], vec["errata"] = check_message(vec, orders)
        elif vec["type"] == "seal":
            if "sad" in vec:
                vec["checks"], vec["errata"] = check_seal(vec, sorders)
            else:
                vec["checks"] = {}
                vec["errata"] = ["block is marked json but is neither JSON "
                                 "nor a literal"]
        elif vec["type"] == "threshold":
            vec["checks"], vec["errata"] = check_threshold(vec, orders)
        elif vec["type"] == "uuid-list":
            vec["checks"], vec["errata"] = check_uuids(vec, orders)
        elif vec["type"] == "encoding":
            vec["checks"], vec["errata"] = check_encoding(vec)
        elif vec["type"] == "key-list":
            vec["checks"], vec["errata"] = {}, []
            msg = vec.get("next_of")
            if msg is not None:
                digs = [blake3_qb64(k.encode()) for k in vec["value"]]
                ok = digs == msg["sad"].get("n")
                vec["checks"]["next_digests"] = {"of": msg["id"],
                                                 "computed": digs, "ok": ok}
                if not ok:
                    vec["errata"].append(f"digests of these keys do not "
                                         f"match the n field of {msg['id']}")
    link(vectors)
    rules(vectors, traits)
    counterparts(vectors)

    records = []
    for vec in vectors:
        if "next_of" in vec:
            vec["next_of"] = vec["next_of"]["id"]
        rec = {"id": vec["id"], "type": vec["type"], "name": vec["name"],
               "section": vec["section"], "section_path": vec["section_path"],
               "file": vec["file"], "line": vec["line"]}
        for key in ("encoding", "syntax", "label_order", "next_of", "sad",
                    "value", "value_line", "text", "raw", "raw_line", "b64",
                    "qb64"):
            if key in vec:
                rec[key] = vec[key]
        if rec["type"] == "message":
            rec["kind"] = (vec["checks"].get("version") or {}).get("kind")
        rec["checks"] = vec["checks"]
        rec["consistent"] = not vec["errata"]
        rec["errata"] = vec["errata"]
        records.append(rec)

    ids = [r["id"] for r in records]
    dups = sorted({i for i in ids if ids.count(i) > 1})
    if dups:
        sys.exit(f"duplicate vector ids {dups}")

    gen = {"tool": "extract.py", "version": TOOL_VERSION,
           "source": {"implementation": "KERI specification",
                      "repository": "https://github.com/trustoverip/"
                                    "kswg-keri-specification",
                      "revision": revision, "files": files}}
    counts = {}
    for r in records:
        counts[r["type"]] = counts.get(r["type"], 0) + 1
    inconsistent = sorted(r["id"] for r in records if not r["consistent"])
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "examples.json"), "w", encoding="utf-8") as f:
        json.dump({"schema": "keri-spec-example/1", "generator": gen,
                   "declared": {
                       "message_field_orders": {
                           k: v for k, v in orders.items()
                           if not k.endswith("@line")},
                       "seal_field_orders": sorders,
                       "config_traits": traits,
                       "conflicts": conflicts},
                   "vectors": records}, f, indent=1, ensure_ascii=False)
        f.write("\n")
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump({"source": "spec", "revision": revision, "generator": gen,
                   "files": {"examples.json": len(records)},
                   "vector_counts": counts,
                   "inconsistent": inconsistent}, f, indent=1,
                  sort_keys=True)
        f.write("\n")
    print(f"{len(records)} examples ({len(inconsistent)} inconsistent) from "
          f"{', '.join(files)} ({revision})")


if __name__ == "__main__":
    main()
