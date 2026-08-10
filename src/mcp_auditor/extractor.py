"""Static extractor (spec §5).

Finds MCP tool definitions by *parsing*, never by running the target. Python is
parsed with the `ast` module; TypeScript/JS and JSON manifests are parsed with
robust text/JSON scanning. The target module is never imported.

Every shape normalizes into the uniform `Tool` list.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field

import yaml

from .types import Tool

# Sibling files (relative to a SKILL.md) whose text is folded into the skill
# body so code-level rules see bundled install/setup scripts.
_SKILL_SCRIPT_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".zsh", ".ps1")

# --- MCP detection signals -------------------------------------------------

_PY_MCP_IMPORT = re.compile(r"^\s*(from|import)\s+mcp(\.|\s|$)", re.MULTILINE)
# FastMCP was renamed MCPServer in SDK 2.0 (protocol 2026-07-28), and the module
# moved from mcp.server.fastmcp to mcp.server.mcpserver. Both names are kept: the
# import regex above still covers new servers, but relying on it alone would make
# an aliased or vendored SDK invisible -- and a scanner that misses a server
# reports it as clean rather than as unscanned.
_PY_FASTMCP = re.compile(r"\b(FastMCP|MCPServer)\b")
_TS_MCP_IMPORT = re.compile(r"""@modelcontextprotocol/(?:sdk|server)""")
_PY_EXT = (".py",)
_TS_EXT = (".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx")
_JSON_EXT = (".json",)

# Safety cap on how much text one JS/TS tool registration can capture as its
# body (scanned by code-level rules; never executed). The body itself is cut at
# the registration call's balanced closing paren, so one tool's body never
# swallows the next tool's code.
_TS_BODY_CAP = 20000


@dataclass
class ExtractionResult:
    is_mcp_server: bool
    tools: list[Tool] = field(default_factory=list)
    # True if an MCP SDK dependency/import was seen even when zero tools parsed.
    sdk_detected: bool = False
    # True if at least one agent skill (SKILL.md) was found and audited.
    skills_detected: bool = False


def extract(files: dict[str, str]) -> ExtractionResult:
    """Extract normalized tools from a mapping of {path: file_text}."""
    tools: list[Tool] = []
    sdk_detected = False

    for path, text in files.items():
        lower = path.lower()
        try:
            if lower.endswith(_PY_EXT):
                seen_sdk, found = _extract_python(path, text)
                sdk_detected = sdk_detected or seen_sdk
                tools.extend(found)
            elif lower.endswith(_TS_EXT):
                seen_sdk, found = _extract_typescript(path, text)
                sdk_detected = sdk_detected or seen_sdk
                tools.extend(found)
            elif lower.endswith(_JSON_EXT):
                tools.extend(_extract_manifest(path, text))
        except Exception:
            # Never let a single malformed file abort the whole audit.
            continue

    # Agent skills (SKILL.md) are the same trust surface as MCP tools: their
    # description is read at selection time and their instructions run with the
    # agent's privileges. Normalize each into a Tool so every rule applies.
    skills = _extract_skills(files)
    tools.extend(skills)

    is_mcp = bool(tools) or sdk_detected
    return ExtractionResult(
        is_mcp_server=is_mcp,
        tools=tools,
        sdk_detected=sdk_detected,
        skills_detected=bool(skills),
    )


# --- Agent skills (SKILL.md) ------------------------------------------------


def _parse_frontmatter(text: str) -> tuple[dict | None, str]:
    """Split a Markdown file into (YAML frontmatter dict, body). None if absent."""
    m = re.match(r"^﻿?---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.DOTALL)
    if not m:
        return None, text
    try:
        meta = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        meta = None
    return (meta if isinstance(meta, dict) else None), m.group(2)


def _dir_of(path: str) -> str:
    norm = path.replace("\\", "/")
    return norm.rsplit("/", 1)[0] if "/" in norm else ""


def _extract_skills(files: dict[str, str]) -> list[Tool]:
    """Turn each SKILL.md into a Tool: frontmatter name/description as metadata,
    the instruction body plus any sibling scripts as the (never-executed) body."""
    tools: list[Tool] = []
    for path, text in files.items():
        base = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if base != "skill.md":
            continue
        meta, body = _parse_frontmatter(text)
        if not isinstance(meta, dict) or not meta.get("name"):
            continue
        skill_dir = _dir_of(path)
        # Fold sibling scripts (same skill directory) into the scanned body.
        extra: list[str] = []
        for other_path, other_text in files.items():
            if other_path == path:
                continue
            other_dir = _dir_of(other_path)
            in_skill = other_dir == skill_dir or other_dir.startswith(skill_dir + "/") if skill_dir else False
            if in_skill and other_path.lower().endswith(_SKILL_SCRIPT_EXT):
                extra.append(other_text)
        full_body = body if not extra else body + "\n" + "\n".join(extra)
        # An agent reads and OBEYS the whole SKILL.md, so the instruction body is
        # part of the poisoning surface, not just the frontmatter description —
        # fold it in so metadata rules (TP-001 injection, PM-001 preference,
        # TP-003 secrets) see instructions hidden in the body. The `body` field
        # additionally carries bundled scripts for code-level rules.
        front_desc = str(meta.get("description", ""))
        instruction_surface = f"{front_desc}\n\n{body}".strip()
        tools.append(
            Tool(
                name=str(meta.get("name")),
                description=instruction_surface,
                schema={},
                location=path,
                body=full_body,
            )
        )
    return tools


# --- Python ----------------------------------------------------------------

_PY_TYPE_TO_JSON = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
}


def _extract_python(path: str, text: str) -> tuple[bool, list[Tool]]:
    sdk = bool(_PY_MCP_IMPORT.search(text) or _PY_FASTMCP.search(text))
    tools: list[Tool] = []

    # `@app.tool` is used by unrelated frameworks too. Without an MCP import or
    # FastMCP symbol, treating every such decorator as MCP creates high-noise
    # false positives in ordinary Python applications.
    #
    # This gate runs BEFORE ast.parse on purpose: parsing is the single most
    # expensive step of an audit, and in a repo where one file is the MCP server
    # every other Python file would otherwise be parsed only for the result to be
    # discarded here. The regex above already decided the answer.
    if not sdk:
        return False, []

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return sdk, tools

    lines = _source_lines(text)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _has_tool_decorator(node):
            continue
        name = _tool_name_from_decorator(node) or node.name
        description = ast.get_docstring(node) or ""
        schema = _schema_from_signature(node)
        # Capture the function source as TEXT (never executed) so code-level
        # rules like CI-001 can scan the body for dangerous sinks.
        body = _source_segment(lines, node)
        tools.append(
            Tool(
                name=name,
                description=description.strip(),
                schema=schema,
                location=f"{path}:{node.lineno}",
                body=body,
                annotations=_annotations_from_decorator(node),
            )
        )
    # A file using a tool decorator implies the SDK even if the import is aliased.
    if tools:
        sdk = True
    return sdk, tools


# Splits on \n, \r and \r\n only — matching how the Python parser counts lines.
# Deliberately does NOT split on \f, \v or the Unicode line separators that
# str.splitlines() also breaks on, since those would desynchronize the line
# numbers the AST reports.
_LINE_SPLIT = re.compile(r"[^\r\n]*(?:\r\n|[\r\n])")


def _source_lines(text: str) -> list[str]:
    lines = _LINE_SPLIT.findall(text)
    consumed = sum(map(len, lines))
    if consumed < len(text):
        lines.append(text[consumed:])  # trailing line with no terminator
    return lines


def _byte_slice(line: str, start: int, end: int | None) -> str:
    """AST columns are UTF-8 *byte* offsets, so a line containing non-ASCII must
    be sliced as bytes. ASCII lines take the cheap path."""
    if line.isascii():
        return line[start:end]
    return line.encode("utf-8")[start:end].decode("utf-8", "replace")


def _source_segment(lines: list[str], node: ast.AST) -> str:
    """`ast.get_source_segment` without re-splitting the file on every call.

    The stdlib helper splits the entire source into lines each time it runs,
    making body capture O(tools x file size) — a server with dozens of tools in
    one module pays for that repeatedly. The line list is built once per file by
    the caller and only sliced here.
    """
    end_lineno = getattr(node, "end_lineno", None)
    end_col = getattr(node, "end_col_offset", None)
    if end_lineno is None or end_col is None:
        return ""
    first, last = node.lineno - 1, end_lineno - 1
    if first < 0 or last >= len(lines):
        return ""
    if first == last:
        return _byte_slice(lines[first], node.col_offset, end_col)
    segment = [_byte_slice(lines[first], node.col_offset, None)]
    segment.extend(lines[first + 1:last])
    segment.append(_byte_slice(lines[last], 0, end_col))
    return "".join(segment)


def _has_tool_decorator(node: ast.AST) -> bool:
    for dec in getattr(node, "decorator_list", []):
        attr = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(attr, ast.Attribute) and attr.attr == "tool":
            return True
        if isinstance(attr, ast.Name) and attr.id == "tool":
            return True
    return False


def _tool_name_from_decorator(node: ast.AST):
    for dec in getattr(node, "decorator_list", []):
        if not isinstance(dec, ast.Call):
            continue
        for kw in dec.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
        for arg in dec.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
    return None


# The four MCP ToolAnnotations behavioural hints. They are untrusted claims by
# design — CP-001/002/003 exist to compare them against the observed handler.
_ANNOTATION_HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def _annotations_from_decorator(node: ast.AST) -> dict:
    """Read ToolAnnotations off an `@app.tool(...)` decorator.

    Without this the Python path produced tools with empty `annotations`, so
    CP-001/002/003 — which fire only on a declared hint — could never trigger on
    a Python server, the most common kind. Both SDK-accepted shapes are read:
    `annotations=ToolAnnotations(readOnlyHint=True)` and the plain
    `annotations={"readOnlyHint": True}`.
    """
    for dec in getattr(node, "decorator_list", []):
        if not isinstance(dec, ast.Call):
            continue
        for kw in dec.keywords:
            if kw.arg == "annotations":
                return _annotation_mapping(kw.value)
    return {}


def _annotation_mapping(value: ast.AST) -> dict:
    """Only literal booleans count. A computed hint is not a claim we can check
    statically, and guessing at one would weaken the CP rules' evidence."""
    out: dict = {}
    pairs: list[tuple] = []
    if isinstance(value, ast.Call):  # ToolAnnotations(readOnlyHint=True)
        pairs = [(kw.arg, kw.value) for kw in value.keywords]
    elif isinstance(value, ast.Dict):  # {"readOnlyHint": True}
        pairs = [
            (key.value, val)
            for key, val in zip(value.keys, value.values)
            if isinstance(key, ast.Constant)
        ]
    for name, val in pairs:
        if name in _ANNOTATION_HINTS and isinstance(val, ast.Constant) and isinstance(val.value, bool):
            out[name] = val.value
    return out


def _schema_from_signature(node: ast.AST) -> dict:
    props: dict[str, dict] = {}
    required: list[str] = []
    args = node.args
    defaulted = {a.arg for a in args.args[len(args.args) - len(args.defaults):]} if args.defaults else set()
    for arg in args.args:
        if arg.arg in ("self", "cls", "ctx", "context"):
            continue
        json_type = _annotation_to_json_type(arg.annotation)
        prop: dict = {}
        if json_type:
            prop["type"] = json_type
        props[arg.arg] = prop
        if arg.arg not in defaulted:
            required.append(arg.arg)
    schema: dict = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def _annotation_to_json_type(annotation):
    if annotation is None:
        return None
    if isinstance(annotation, ast.Name):
        return _PY_TYPE_TO_JSON.get(annotation.id)
    if isinstance(annotation, ast.Subscript) and isinstance(annotation.value, ast.Name):
        return _PY_TYPE_TO_JSON.get(annotation.value.id)
    return None


# --- TypeScript / JavaScript ----------------------------------------------

# Matches server.tool("name", "description", { schema }, handler) and the
# registerTool("name", { description, inputSchema }, handler) shapes.
_TS_TOOL_STRING = re.compile(
    r"""[A-Za-z_$][\w$]*\.tool\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*["'`]([^"'`]*)["'`]""",
    re.DOTALL,
)
_TS_REGISTER = re.compile(
    r"""[A-Za-z_$][\w$]*\.registerTool\s*\(\s*["'`]([^"'`]+)["'`]""",
    re.DOTALL,
)
_TS_LOW_LEVEL_LIST = re.compile(
    r"""setRequestHandler\s*\(\s*(?:["'`]tools/list["'`]|ListToolsRequestSchema)""",
    re.DOTALL,
)


def _extract_typescript(path: str, text: str) -> tuple[bool, list[Tool]]:
    sdk = bool(_TS_MCP_IMPORT.search(text))
    tools: list[Tool] = []

    # registerTool/setRequestHandler are generic names. Require the official SDK
    # package signal before interpreting their call shapes as MCP definitions.
    if not sdk:
        return False, []

    for m in _TS_TOOL_STRING.finditer(text):
        name, desc = m.group(1), m.group(2)
        line = text.count("\n", 0, m.start()) + 1
        schema = _ts_schema_after(text, m.end())
        body = _ts_call_span(text, m.start())
        tools.append(Tool(name=name, description=desc, schema=schema, location=f"{path}:{line}", body=body))

    for m in _TS_REGISTER.finditer(text):
        name = m.group(1)
        line = text.count("\n", 0, m.start()) + 1
        # v2 uses registerTool(name, {description, inputSchema, annotations}, handler).
        config = _ts_object_after(text, m.end(), max_distance=600)
        dm = re.search(r"""description\s*:\s*["'`]([^"'`]*)["'`]""", config, re.DOTALL)
        desc = dm.group(1) if dm else ""
        body = _ts_call_span(text, m.start())
        tools.append(
            Tool(
                name=name,
                description=desc,
                schema=_ts_register_schema(config),
                location=f"{path}:{line}",
                body=body,
                annotations=_ts_annotations(config),
            )
        )

    # Low-level SDK form: setRequestHandler("tools/list", () => ({tools: [...]})).
    # The descriptors are extractable, but tools/call dispatch may be dynamic, so
    # these tools intentionally carry no implementation body unless a dedicated
    # handler can be associated in a future interprocedural pass.
    for m in _TS_LOW_LEVEL_LIST.finditer(text):
        call = _ts_call_span(text, m.start())
        tools.extend(_extract_low_level_tool_list(path, text, m.start(), call))

    if tools:
        sdk = True
    return sdk, tools


def _ts_call_span(text: str, start: int) -> str:
    """Capture one tool-registration call as text, ending at its balanced `)`.

    String-aware paren matching so a `)` inside a quoted/template literal does
    not close the call early. Falls back to a capped slice if the call never
    closes (malformed source).
    """
    open_idx = text.find("(", start)
    if open_idx == -1:
        return text[start: start + _TS_BODY_CAP]
    depth = 0
    quote: str | None = None
    prev = ""
    end_limit = min(len(text), start + _TS_BODY_CAP)
    for i in range(open_idx, end_limit):
        ch = text[i]
        if quote:
            if ch == quote and prev != "\\":
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start: i + 1]
        prev = ch
    return text[start:end_limit]


def _balanced_delimited(text: str, start: int, opener: str, closer: str) -> str:
    """Return one balanced JS/TS delimited span, aware of strings/comments."""
    if start < 0 or start >= len(text) or text[start] != opener:
        return ""
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    i = start
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        elif ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1
    return ""


def _ts_object_after(text: str, pos: int, max_distance: int = 300) -> str:
    brace = text.find("{", pos, min(len(text), pos + max_distance))
    return _balanced_delimited(text, brace, "{", "}") if brace != -1 else ""


def _ts_register_schema(config: str) -> dict:
    """Extract common v2 inputSchema forms without evaluating JavaScript."""
    marker = re.search(r"\binputSchema\s*:", config)
    if not marker:
        return {}
    tail = config[marker.end():]
    # z.object({ path: z.string() }) and Standard Schema object literals both
    # expose a first object containing the parameter keys.
    obj = _ts_object_after(tail, 0, max_distance=240)
    if not obj:
        return {}
    props: dict[str, dict] = {}
    for key in re.findall(r"(?:^|[,{}])\s*([A-Za-z_$][\w$]*)\s*:", obj):
        if key not in {"type", "properties", "required", "description", "title", "$schema"}:
            props.setdefault(key, {})
    # Raw JSON Schema nests actual fields below `properties`; prefer those when
    # the common marker is present.
    pm = re.search(r"\bproperties\s*:", obj)
    if pm:
        pobj = _ts_object_after(obj, pm.end(), max_distance=80)
        nested = {
            key: {}
            for key in re.findall(r"(?:^|[,{}])\s*([A-Za-z_$][\w$]*)\s*:", pobj)
            if key not in {"type", "description", "title", "format", "pattern"}
        }
        if nested:
            props = nested
    return {"type": "object", "properties": props} if props else {}


def _ts_annotations(config: str) -> dict:
    marker = re.search(r"\bannotations\s*:", config)
    if not marker:
        return {}
    obj = _ts_object_after(config, marker.end(), max_distance=80)
    if not obj:
        return {}
    out: dict[str, bool] = {}
    for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
        match = re.search(rf"\b{key}\s*:\s*(true|false)\b", obj, re.IGNORECASE)
        if match:
            out[key] = match.group(1).lower() == "true"
    return out


def _top_level_objects(array_text: str) -> list[str]:
    out: list[str] = []
    depth = 0
    start = -1
    quote: str | None = None
    escaped = False
    for i, ch in enumerate(array_text):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                out.append(array_text[start:i + 1])
                start = -1
    return out


def _extract_low_level_tool_list(path: str, full_text: str, call_start: int, call: str) -> list[Tool]:
    marker = re.search(r"\btools\s*:\s*\[", call)
    if not marker:
        return []
    bracket = call.find("[", marker.start())
    array = _balanced_delimited(call, bracket, "[", "]")
    tools: list[Tool] = []
    for obj in _top_level_objects(array[1:-1] if array else ""):
        nm = re.search(r"\bname\s*:\s*[" + "\"'`" + r"]([^\"'`]+)[\"'`]", obj)
        if not nm:
            continue
        dm = re.search(r"\bdescription\s*:\s*[\"'`]([^\"'`]*)[\"'`]", obj, re.DOTALL)
        absolute = call_start + call.find(obj)
        line = full_text.count("\n", 0, max(call_start, absolute)) + 1
        tools.append(
            Tool(
                name=nm.group(1),
                description=dm.group(1) if dm else "",
                schema=_ts_register_schema(obj),
                location=f"{path}:{line}",
                annotations=_ts_annotations(obj),
            )
        )
    return tools


def _ts_schema_after(text: str, pos: int) -> dict:
    """Best-effort: capture parameter names from the schema object literal that
    follows a tool registration, e.g. `{ dir: z.string() }` -> properties.dir."""
    rest = text[pos:]
    brace = rest.find("{")
    if brace == -1 or brace > 200:
        return {}
    # Find the matching closing brace.
    depth = 0
    end = -1
    for i, ch in enumerate(rest[brace:], start=brace):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end == -1:
        return {}
    block = rest[brace + 1: end]
    props = {}
    for key in re.findall(r"""([A-Za-z_$][\w$]*)\s*:""", block):
        props[key] = {}
    return {"type": "object", "properties": props} if props else {}


# --- JSON manifest ---------------------------------------------------------


def _extract_manifest(path: str, text: str) -> list[Tool]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    raw_tools = None
    if isinstance(data, dict) and isinstance(data.get("tools"), list):
        raw_tools = data["tools"]
    elif isinstance(data, list):
        raw_tools = data
    if not raw_tools:
        return []

    tools: list[Tool] = []
    for entry in raw_tools:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not name:
            continue
        schema = entry.get("inputSchema") or entry.get("input_schema") or entry.get("schema") or {}
        tools.append(
            Tool(
                name=str(name),
                description=str(entry.get("description", "")),
                schema=schema if isinstance(schema, dict) else {},
                location=path,
                annotations=entry.get("annotations") if isinstance(entry.get("annotations"), dict) else {},
            )
        )
    return tools
