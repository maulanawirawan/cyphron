"""Minimal YAML subset parser — the ONLY YAML parser in Cyphron (no PyYAML).

Supports exactly what .kimchi/agent-config.yaml uses: nested mappings,
lists of mappings, inline string lists, quoted strings (incl. doubled
single-quote escapes), integers, floats, booleans, and '>' folded block
scalars. Anything exotic raises YamliteError so callers fail loudly.
"""

from __future__ import annotations


class YamliteError(ValueError):
    pass


def _parse_scalar(raw: str):
    s = raw.strip()
    if s == "":
        return None
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        items, buf, quote = [], "", None
        for ch in inner:
            if quote:
                if ch == quote:
                    quote = None
                else:
                    buf += ch
            elif ch in ('"', "'"):
                quote = ch
            elif ch == ",":
                items.append(buf.strip())
                buf = ""
            else:
                buf += ch
        items.append(buf.strip())
        return [_unquote(i) for i in items if i != ""]
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    if len(s) >= 2 and s.startswith("'") and s.endswith("'"):
        return s[1:-1].replace("''", "'")
    low = s.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~"):
        return None
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1].replace("''", "'")
    return s


def _split_key_value(content: str):
    """Split 'key: value' at the first colon outside quotes followed by
    space or end-of-line (keys in this config never contain ': ')."""
    in_quote = None
    for i, ch in enumerate(content):
        if in_quote:
            if ch == in_quote:
                in_quote = None
        elif ch in ('"', "'"):
            in_quote = ch
        elif ch == ":" and (i + 1 >= len(content) or content[i + 1] in " \t"):
            return content[:i].strip(), content[i + 1:].strip()
    return None, None


def parse(text: str):
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if raw.strip() == "" or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))
    if not lines:
        return {}
    value, idx = _parse_block(lines, 0, lines[0][0])
    if idx != len(lines):
        raise YamliteError(f"unconsumed YAML near line {idx}: {lines[idx][1]!r}")
    return value


def _parse_block(lines, i, indent):
    if i >= len(lines):
        return None, i
    if lines[i][1].startswith("- "):
        return _parse_list(lines, i, indent)
    return _parse_mapping(lines, i, indent)


def _parse_mapping(lines, i, indent):
    out: dict = {}
    while i < len(lines):
        cur_indent, content = lines[i]
        if cur_indent < indent or content.startswith("- "):
            break
        if cur_indent > indent:
            raise YamliteError(f"unexpected indent at line {i}: {content!r}")
        key, val = _split_key_value(content)
        if key is None:
            raise YamliteError(f"cannot parse mapping line {i}: {content!r}")
        if val in (">", "|", ">-", "|-"):
            block, i = _parse_block_scalar(lines, i + 1, cur_indent)
            out[key] = block
            continue
        if val != "":
            out[key] = _parse_scalar(val)
            i += 1
            continue
        if i + 1 < len(lines) and (lines[i + 1][0] > cur_indent or
                                   lines[i + 1][1].startswith("- ")):
            out[key], i = _parse_block(lines, i + 1, lines[i + 1][0])
        else:
            out[key] = None
            i += 1
    return out, i


def _parse_list(lines, i, indent):
    out: list = []
    while i < len(lines):
        cur_indent, content = lines[i]
        if cur_indent != indent or not content.startswith("-"):
            break
        item_content = content[1:].strip()
        if item_content == "":
            if i + 1 < len(lines) and lines[i + 1][0] > cur_indent:
                val, i = _parse_block(lines, i + 1, lines[i + 1][0])
                out.append(val)
            else:
                out.append(None)
                i += 1
            continue
        key, val = _split_key_value(item_content)
        if key is None:
            out.append(_parse_scalar(item_content))
            i += 1
            continue
        item: dict = {}
        if val != "":
            item[key] = _parse_scalar(val)
            i += 1
        elif val in (">", "|"):
            block, i = _parse_block_scalar(lines, i + 1, cur_indent)
            item[key] = block
        else:
            if i + 1 < len(lines) and lines[i + 1][0] > cur_indent:
                item[key], i = _parse_block(lines, i + 1, lines[i + 1][0])
            else:
                item[key] = None
                i += 1
        while i < len(lines) and lines[i][0] > cur_indent and not lines[i][1].startswith("- "):
            k2, v2 = _split_key_value(lines[i][1])
            if k2 is None:
                raise YamliteError(f"bad list-item continuation at line {i}: {lines[i][1]!r}")
            if v2 in (">", "|"):
                block, i = _parse_block_scalar(lines, i + 1, lines[i][0])
                item[k2] = block
            elif v2 != "":
                item[k2] = _parse_scalar(v2)
                i += 1
            elif i + 1 < len(lines) and lines[i + 1][0] > lines[i][0]:
                item[k2], i = _parse_block(lines, i + 1, lines[i + 1][0])
            else:
                item[k2] = None
                i += 1
        out.append(item)
    return out, i


def _parse_block_scalar(lines, i, parent_indent):
    chunk: list[str] = []
    block_indent = None
    while i < len(lines) and lines[i][0] > parent_indent:
        if block_indent is None:
            block_indent = lines[i][0]
        chunk.append(" " * max(0, lines[i][0] - block_indent) + lines[i][1])
        i += 1
    return "\n".join(chunk).strip(), i
