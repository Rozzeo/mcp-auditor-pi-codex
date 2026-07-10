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
_PY_FASTMCP = re.compile(r"\bFastMCP\b")
_TS_MCP_IMPORT = re.compile(r"""@modelcontextprotocol/sdk""")
_TS_TOOL_CALL = re.compile(r"\b(?:server|mcp)\.tool\s*\(|registerTool\s*\(|setRequestHandler\s*\(")

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
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return sdk, tools

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
        body = ast.get_source_segment(text, node) or ""
        tools.append(
            Tool(
                name=name,
                description=description.strip(),
                schema=schema,
                location=f"{path}:{node.lineno}",
                body=body,
            )
        )
    # A file using a tool decorator implies the SDK even if the import is aliased.
    if tools:
        sdk = True
    return sdk, tools


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
    r"""(?:server|mcp)\.tool\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*["'`]([^"'`]*)["'`]""",
    re.DOTALL,
)
_TS_REGISTER = re.compile(
    r"""registerTool\s*\(\s*["'`]([^"'`]+)["'`]""",
    re.DOTALL,
)


def _extract_typescript(path: str, text: str) -> tuple[bool, list[Tool]]:
    sdk = bool(_TS_MCP_IMPORT.search(text) or _TS_TOOL_CALL.search(text))
    tools: list[Tool] = []

    for m in _TS_TOOL_STRING.finditer(text):
        name, desc = m.group(1), m.group(2)
        line = text.count("\n", 0, m.start()) + 1
        schema = _ts_schema_after(text, m.end())
        body = _ts_call_span(text, m.start())
        tools.append(Tool(name=name, description=desc, schema=schema, location=f"{path}:{line}", body=body))

    for m in _TS_REGISTER.finditer(text):
        name = m.group(1)
        line = text.count("\n", 0, m.start()) + 1
        # Pull description from a `description:` field in the config object if present.
        tail = text[m.end(): m.end() + 600]
        dm = re.search(r"""description\s*:\s*["'`]([^"'`]*)["'`]""", tail)
        desc = dm.group(1) if dm else ""
        body = _ts_call_span(text, m.start())
        tools.append(Tool(name=name, description=desc, schema={}, location=f"{path}:{line}", body=body))

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
            )
        )
    return tools
