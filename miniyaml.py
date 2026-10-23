# Minimal YAML loader for this tool (supports the subset used in config.example.yaml).
# If you prefer, replace this with PyYAML and add it to requirements.txt.
import re

def _strip_quotes(s: str) -> str:
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s

def load_min_yaml(text: str):
    lines = []
    for raw in text.splitlines():
        # remove comments, keep inside quotes (simple)
        if '#' in raw:
            # only strip if comment begins after some whitespace and not in quotes
            # naive but works for our config shape
            parts = raw.split('#', 1)
            if parts[0].count('"') % 2 == 0 and parts[0].count("'") % 2 == 0:
                raw = parts[0]
        if raw.strip() == "":
            continue
        lines.append(raw.rstrip())

    # This loader handles mappings, lists, and scalars. Indentation must be consistent (2 spaces).
    idx = 0

    def parse_block(indent=0):
        nonlocal idx
        obj = None
        while idx < len(lines):
            line = lines[idx]
            cur_indent = len(line) - len(line.lstrip(' '))
            if cur_indent < indent:
                break
            if cur_indent > indent:
                raise ValueError(f"Invalid indentation at line: {line}")
            stripped = line.strip()
            if stripped.startswith('- '):
                if obj is None:
                    obj = []
                if not isinstance(obj, list):
                    raise ValueError("Mixing list and dict at same indent")
                item = stripped[2:].strip()
                idx += 1
                if item == "" or item.endswith(':'):
                    # complex item
                    # if "key:" inline
                    if item.endswith(':') and item != ":":
                        key = item[:-1].strip()
                        sub = parse_block(indent + 2)
                        obj.append({key: sub})
                    else:
                        sub = parse_block(indent + 2)
                        obj.append(sub)
                else:
                    obj.append(_parse_scalar(item))
                continue

            # mapping
            if obj is None:
                obj = {}
            if not isinstance(obj, dict):
                raise ValueError("Mixing dict and list at same indent")

            if ':' not in stripped:
                raise ValueError(f"Expected key: value at line: {line}")
            key, rest = stripped.split(':', 1)
            key = key.strip()
            rest = rest.strip()
            idx += 1
            if rest == "":
                val = parse_block(indent + 2)
            else:
                val = _parse_scalar(rest)
            # merge if key already exists and both are dicts (not needed here)
            obj[key] = val
        return obj

    def _parse_scalar(v: str):
        v = _strip_quotes(v)
        if v.lower() in ("true", "false"):
            return v.lower() == "true"
        if re.fullmatch(r'-?\d+', v):
            return int(v)
        if re.fullmatch(r'-?\d+\.\d+', v):
            return float(v)
        # list in brackets
        if v.startswith('[') and v.endswith(']'):
            inner = v[1:-1].strip()
            if inner == "":
                return []
            parts = [p.strip() for p in inner.split(',')]
            return [_parse_scalar(p) for p in parts]
        return v

    idx = 0
    return parse_block(0)
