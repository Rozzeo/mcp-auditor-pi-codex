"""Static extractor (spec §5).

Finds MCP tool definitions by *parsing*, never by running the target. Python is
parsed with the `ast` module; WordPress/PHP, TypeScript/JS and JSON manifests
are parsed with robust text/JSON scanning. The target module is never imported.

Every shape normalizes into the uniform `Tool` list.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field

import yaml

from .jsscan import balanced_delimited as _balanced_delimited
from .source_roles import deployed_files
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
_PHP_EXT = (".php",)
_TS_EXT = (".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx")
_JSON_EXT = (".json",)

# Safety cap on how much text one JS/TS tool registration can capture as its
# body (scanned by code-level rules; never executed). The body itself is cut at
# the registration call's balanced closing paren, so one tool's body never
# swallows the next tool's code.
_TS_BODY_CAP = 20000


@dataclass(frozen=True)
class CoverageGap:
    """A registration the extractor recognized but could not resolve.

    Reported rather than guessed at: inventing a tool name would corrupt the
    inventory, and silently dropping the construct would make an unscanned
    surface look like a clean one.
    """

    construct: str
    location: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"construct": self.construct, "location": self.location, "reason": self.reason}


@dataclass
class ExtractionResult:
    is_mcp_server: bool
    tools: list[Tool] = field(default_factory=list)
    # True if an MCP SDK dependency/import was seen even when zero tools parsed.
    sdk_detected: bool = False
    # True if at least one agent skill (SKILL.md) was found and audited.
    skills_detected: bool = False
    # Registration constructs seen but not resolvable into a tool.
    coverage_gaps: list[CoverageGap] = field(default_factory=list)


def extract(files: dict[str, str]) -> ExtractionResult:
    """Extract normalized tools from a mapping of {path: file_text}."""
    tools: list[Tool] = []
    gaps: list[CoverageGap] = []
    sdk_detected = False

    php_mcp_repo = _php_repo_uses_mcp(files)
    sdk_detected = sdk_detected or php_mcp_repo

    # The MCP import lives in the module that builds the server; in any project
    # large enough to split its tools across modules, the files that actually
    # carry `@mcp.tool()` import the server object instead. Deciding the gate
    # per file therefore discarded every tool in exactly the servers most worth
    # reviewing -- silently, since a dropped file leaves no gap behind. The
    # question "is this repository an MCP server" is a property of the tree, so
    # it is answered once, over the tree.
    py_mcp_repo = _py_repo_uses_mcp(files)
    sdk_detected = sdk_detected or py_mcp_repo

    # Tools registered inside tests and fixtures exercise the SDK; they are not
    # part of the surface a reviewer approves. Counting them adds phantom rows
    # to the capability matrix and phantom gaps to the coverage report.
    for path, text in deployed_files(files).items():
        lower = path.lower()
        try:
            if lower.endswith(_PY_EXT):
                seen_sdk, found, found_gaps = _extract_python(path, text, repository_mcp=py_mcp_repo)
                sdk_detected = sdk_detected or seen_sdk
                tools.extend(found)
                gaps.extend(found_gaps)
            elif lower.endswith(_PHP_EXT):
                seen_sdk, found = _extract_php(path, text, repository_mcp=php_mcp_repo)
                sdk_detected = sdk_detected or seen_sdk
                tools.extend(found)
            elif lower.endswith(_TS_EXT):
                seen_sdk, found, found_gaps = _extract_typescript(path, text)
                sdk_detected = sdk_detected or seen_sdk
                tools.extend(found)
                gaps.extend(found_gaps)
            elif lower.endswith(_JSON_EXT):
                tools.extend(_extract_manifest(path, text))
        except Exception as exc:
            # Never let a single malformed file abort the whole audit -- but a
            # file we could not read is a file we did not audit, and saying
            # nothing about it lets an unreadable tree report a perfect score.
            gaps.append(CoverageGap(
                construct="file",
                location=path,
                reason=f"could not be analyzed ({type(exc).__name__}: {exc}); "
                       f"any tool definitions it contains were not reviewed",
            ))
            continue

    # A FastMCP server can mount sub-servers under a namespace, and the name a
    # client calls is then `<namespace>_<function>`. The mount usually lives in
    # a different module from the decorators, so it is resolved here, across the
    # whole tree, rather than per file.
    _apply_namespaces(tools, _mounted_namespaces(files))

    # A ListTools handler seldom holds its descriptor array inline: it binds it
    # to a const first, or calls a factory defined in another module. Those are
    # resolved across the whole tree, and only when the tree actually contains
    # such a handler - otherwise any array of named objects would become tools.
    known = {tool.name for tool in tools}
    for tool in _indirect_tool_arrays(files):
        if tool.name not in known:
            known.add(tool.name)
            tools.append(tool)

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
        coverage_gaps=gaps,
    )


# --- WordPress / PHP -------------------------------------------------------

_PHP_ABILITY_CALL = re.compile(r"\bwp_register_ability\s*\(", re.IGNORECASE)
_PHP_MCP_REPO_SIGNALS = (
    "wordpress/mcp-adapter",
    "wordpress/php-mcp-schema",
    "wp\\mcp\\",
    "mcp_adapter",
)
_PHP_SCHEMA_RESERVED = {
    "type", "properties", "required", "description", "title", "default",
    "items", "enum", "minimum", "maximum", "format", "pattern",
    "additionalproperties",
}


def _php_repo_uses_mcp(files: dict[str, str]) -> bool:
    """Recognize an adapter repo without treating every WordPress ability as MCP.

    `wp_register_ability` belongs to WordPress itself. It only becomes an MCP
    surface when the repository depends on/implements the adapter, or when the
    individual ability explicitly opts into MCP exposure.
    """
    for text in files.values():
        lower = text.lower()
        if any(signal in lower for signal in _PHP_MCP_REPO_SIGNALS):
            return True
    return False


def _extract_php(path: str, text: str, *, repository_mcp: bool) -> tuple[bool, list[Tool]]:
    tools: list[Tool] = []
    saw_ability = False

    # Registration calls in PHPUnit fixtures exercise the adapter but are not
    # part of the deployed server surface. Counting them produces a plausible,
    # dangerously inflated approval matrix.
    path_parts = {part.lower() for part in path.replace("\\", "/").split("/")[:-1]}
    if path_parts.intersection({"test", "tests", "fixture", "fixtures"}):
        return repository_mcp, []

    for match in _PHP_ABILITY_CALL.finditer(text):
        open_paren = text.find("(", match.start())
        call = _balanced_delimited(text, open_paren, "(", ")")
        if not call:
            continue
        saw_ability = True

        name_match = re.match(r"\(\s*(['\"])(.*?)\1\s*,", call, re.DOTALL)
        if not name_match:
            continue

        meta = _php_value_for_key(call, "meta")
        mcp_meta = _php_value_for_key(meta, "mcp") if meta else ""
        explicitly_public = (
            _php_bool_for_key(mcp_meta, "public") is True
            or _php_bool_for_key(meta, "public") is True
        )
        ability_type = _php_string_for_key(mcp_meta, "type") or "tool"
        if (not repository_mcp and not explicitly_public) or ability_type != "tool":
            continue

        raw_name = name_match.group(2)
        line = text.count("\n", 0, match.start()) + 1
        tools.append(
            Tool(
                name=_sanitize_mcp_name(raw_name),
                description=_php_string_for_key(call, "description") or "",
                schema=_php_input_schema(call),
                location=f"{path}:{line}",
                body=call,
                annotations=_php_annotations(call),
            )
        )

    return repository_mcp or saw_ability and bool(tools), tools


def _sanitize_mcp_name(name: str) -> str:
    """Mirror the adapter's observable slash-to-hyphen name normalization."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", name.strip())


def _php_value_for_key(container: str, key: str) -> str:
    if not container:
        return ""
    marker = re.search(rf"(['\"]){re.escape(key)}\1\s*=>\s*", container, re.IGNORECASE)
    if not marker:
        return ""
    pos = marker.end()
    while pos < len(container) and container[pos].isspace():
        pos += 1
    if container[pos:pos + 5].lower() == "array":
        opener = container.find("(", pos + 5)
        return _balanced_delimited(container, opener, "(", ")") if opener != -1 else ""
    if pos < len(container) and container[pos] == "[":
        return _balanced_delimited(container, pos, "[", "]")
    if pos < len(container) and container[pos] in ("'", '"'):
        quote = container[pos]
        escaped = False
        for end in range(pos + 1, len(container)):
            ch = container[end]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                return container[pos:end + 1]
        return ""
    end = container.find(",", pos)
    return container[pos:end if end != -1 else len(container)].strip()


def _php_string_for_key(container: str, key: str) -> str | None:
    value = _php_value_for_key(container, key)
    if len(value) < 2 or value[0] not in ("'", '"') or value[-1] != value[0]:
        return None
    return value[1:-1].replace("\\'", "'").replace('\\"', '"')


def _php_bool_for_key(container: str, key: str) -> bool | None:
    if not container:
        return None
    marker = re.search(
        rf"(['\"]){re.escape(key)}\1\s*=>\s*(true|false)\b",
        container,
        re.IGNORECASE,
    )
    if marker:
        return marker.group(2).lower() == "true"
    return None


def _php_input_schema(call: str) -> dict:
    schema_block = _php_value_for_key(call, "input_schema")
    if not schema_block:
        return {}
    properties_block = _php_value_for_key(schema_block, "properties")
    properties: dict[str, dict] = {}
    if properties_block:
        for match in re.finditer(r"(['\"])([A-Za-z_][A-Za-z0-9_.-]*)\1\s*=>", properties_block):
            name = match.group(2)
            if name.lower() in _PHP_SCHEMA_RESERVED:
                continue
            value = _php_value_for_key(properties_block, name)
            prop_type = _php_string_for_key(value, "type")
            properties.setdefault(name, {"type": prop_type} if prop_type else {})

    schema: dict = {"type": _php_string_for_key(schema_block, "type") or "object"}
    if properties:
        schema["properties"] = properties
    required_block = _php_value_for_key(schema_block, "required")
    if required_block:
        required = [
            value
            for _quote, value in re.findall(r"(['\"])([A-Za-z_][A-Za-z0-9_.-]*)\1", required_block)
        ]
        if required:
            schema["required"] = required
    return schema


def _php_annotations(call: str) -> dict:
    block = _php_value_for_key(call, "annotations")
    mapping = {
        "readonly": "readOnlyHint",
        "destructive": "destructiveHint",
        "idempotent": "idempotentHint",
        "open_world": "openWorldHint",
    }
    out: dict[str, bool] = {}
    for php_name, mcp_name in mapping.items():
        value = _php_bool_for_key(block, php_name)
        if value is not None:
            out[mcp_name] = value
    return out


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


# A registration this file might carry. Cheap enough to run over every Python
# file, and the only thing that earns a file the cost of `ast.parse`.
_PY_TOOL_HINT = re.compile(r"@[\w.]*\btool\b|\badd_tool\s*\(|\bcall_tool\b|\blist_tools\b")


def _py_repo_uses_mcp(files: dict[str, str]) -> bool:
    """Whether any Python file in the tree imports the MCP SDK."""
    return any(
        path.lower().endswith(_PY_EXT)
        and (_PY_MCP_IMPORT.search(text) or _PY_FASTMCP.search(text))
        for path, text in files.items()
    )


def _extract_python(
    path: str, text: str, repository_mcp: bool = False
) -> tuple[bool, list[Tool], list[CoverageGap]]:
    sdk = bool(_PY_MCP_IMPORT.search(text) or _PY_FASTMCP.search(text))
    tools: list[Tool] = []

    # `@app.tool` is used by unrelated frameworks too. Without an MCP signal
    # somewhere in the tree, treating every such decorator as MCP creates
    # high-noise false positives in ordinary Python applications.
    #
    # This gate runs BEFORE ast.parse on purpose: parsing is the single most
    # expensive step of an audit, and a repo where one file is the MCP server
    # should not pay to parse files that register nothing. So a file earns
    # parsing by carrying the SDK itself, or by carrying a registration in a
    # tree that does.
    if not sdk and not (repository_mcp and _PY_TOOL_HINT.search(text)):
        return False, [], []

    gaps: list[CoverageGap] = []
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        # Silently discarding an unparseable file is how an auditor running on
        # 3.10 reports a clean bill of health for a server written for 3.12.
        gaps.append(CoverageGap(
            construct="python file",
            location=f"{path}:{exc.lineno or 1}",
            reason=f"could not be parsed ({exc.msg}); any tool definitions it "
                   f"contains were not reviewed",
        ))
        return sdk, tools, gaps

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
                registry=_tool_decorator_registry(node) or "",
            )
        )
    # Low-level SDK shape: tools are declared as Tool(...) descriptors returned
    # from an @server.list_tools() coroutine and dispatched by name inside
    # @server.call_tool(). Only the declarations are read here; the dispatch
    # function is deliberately not attributed to any tool (see below).
    if _py_has_list_tools(tree):
        found, low_gaps = _extract_py_low_level(path, tree)
        known = {tool.name for tool in tools}
        tools.extend(tool for tool in found if tool.name not in known)
        gaps.extend(low_gaps)

    # A file using a tool decorator implies the SDK even if the import is aliased.
    if tools:
        sdk = True
    return sdk, tools, gaps


_TS_DESCRIPTOR = re.compile(r"\bname\s*:\s*[\"'`]([^\"'`]+)[\"'`]")


def _indirect_tool_arrays(path_texts: dict[str, str]) -> list[Tool]:
    """Tool descriptors from an array the ListTools handler reaches indirectly.

    Only runs when some file in the tree registers a ListTools handler, and only
    accepts an array whose every top-level object carries both a name and an
    inputSchema. That pairing is what separates a tool descriptor list from the
    many other arrays of named objects a server contains.
    """
    if not any(_TS_LOW_LEVEL_LIST.search(text) for text in path_texts.values()):
        return []

    found: list[Tool] = []
    for path, text in path_texts.items():
        if not path.lower().endswith(_TS_EXT):
            continue
        # An assignment, a call argument, or a `return` - the three ways a
        # descriptor array reaches the handler.
        for match in re.finditer(r"(?:[=(]|\breturn)\s*\[", text):
            array = _balanced_delimited(text, match.end() - 1, "[", "]")
            if not array or len(array) > _TS_BODY_CAP:
                continue
            objects = _top_level_objects(array[1:-1])
            if not objects or len(objects) < 1:
                continue
            if not all(
                _TS_DESCRIPTOR.search(obj) and re.search(r"\binputSchema\s*:", obj)
                for obj in objects
            ):
                continue
            for obj in objects:
                name = _TS_DESCRIPTOR.search(obj)
                description = re.search(
                    r"\bdescription\s*:\s*[\"\'`]([^\"\'`]*)[\"\'`]", obj, re.DOTALL
                )
                line = text.count("\n", 0, match.start() + array.find(obj)) + 1
                found.append(Tool(
                    name=name.group(1),
                    description=description.group(1) if description else "",
                    schema=_ts_register_schema(obj),
                    location=f"{path}:{line}",
                    annotations=_ts_annotations(obj),
                ))
    return found


def _mounted_namespaces(files: dict[str, str]) -> dict[str, str]:
    """Map each mounted server object to the namespace it is mounted under.

    Both spellings are recognized: `mount(server, namespace="jira")` and the
    positional `mount("jira", server)`. A mount with no namespace prefixes
    nothing, and is deliberately not recorded.
    """
    namespaces: dict[str, str] = {}
    for path, text in files.items():
        if not path.lower().endswith(_PY_EXT):
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in ("mount", "import_server")):
                continue
            server = prefix = None
            for keyword in node.keywords:
                if keyword.arg in ("namespace", "prefix") and isinstance(keyword.value, ast.Constant):
                    prefix = keyword.value.value
            positional = list(node.args)
            if positional and isinstance(positional[0], ast.Constant):
                prefix = prefix or positional[0].value
                positional = positional[1:]
            for argument in positional:
                if isinstance(argument, ast.Name):
                    server = argument.id
                    break
            if server and isinstance(prefix, str) and prefix:
                namespaces[server] = prefix
    return namespaces


def _apply_namespaces(tools: list[Tool], namespaces: dict[str, str]) -> None:
    """Rewrite each mounted tool's name to the one a client would call."""
    if not namespaces:
        return
    for tool in tools:
        prefix = namespaces.get(tool.registry)
        if not prefix or tool.name.startswith(f"{prefix}_"):
            continue
        tool.name = f"{prefix}_{tool.name}"


def _py_has_list_tools(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        for dec in getattr(node, "decorator_list", []):
            attr = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(attr, ast.Attribute) and attr.attr == "list_tools":
                return True
    return False


def _py_str_enum_members(tree: ast.AST) -> dict[str, str]:
    """Map `ClassName.MEMBER` to its string value for str-Enum tool registries.

    The reference git and time servers name their tools through such members
    rather than literals, so without this the declarations resolve to nothing.
    """
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for stmt in node.body:
            if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
                continue
            target = stmt.targets[0]
            if isinstance(target, ast.Name) and isinstance(stmt.value, ast.Constant):
                if isinstance(stmt.value.value, str):
                    out[f"{node.name}.{target.id}"] = stmt.value.value
    return out


def _py_module_strings(tree: ast.AST) -> dict[str, str]:
    out: dict[str, str] = {}
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str):
                    out[target.id] = node.value.value
    return out


def _py_tool_name(node: ast.AST, enums: dict[str, str], constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.Attribute):
        dotted = ast.unparse(node)
        # `TimeTools.GET_CURRENT_TIME.value` names the same member as
        # `TimeTools.GET_CURRENT_TIME`.
        if dotted.endswith(".value"):
            dotted = dotted[: -len(".value")]
        return enums.get(dotted)
    return None


def _extract_py_low_level(path: str, tree: ast.AST) -> tuple[list[Tool], list[CoverageGap]]:
    enums = _py_str_enum_members(tree)
    constants = _py_module_strings(tree)
    tools: list[Tool] = []
    gaps: list[CoverageGap] = []

    dispatch = _py_dispatch_branches(tree, enums, constants)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if called != "Tool":
            continue
        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        if "name" not in keywords:
            continue

        name = _py_tool_name(keywords["name"], enums, constants)
        if name is None:
            gaps.append(CoverageGap(
                construct="list_tools",
                location=f"{path}:{node.lineno}",
                reason=f"Tool name expression {ast.unparse(keywords['name'])!r} does not "
                       f"resolve to a string literal, module constant, or str-Enum member.",
            ))
            continue

        description = keywords.get("description")
        schema = keywords.get("inputSchema")
        tools.append(
            Tool(
                name=name,
                description=(
                    description.value.strip()
                    if isinstance(description, ast.Constant) and isinstance(description.value, str)
                    else ""
                ),
                schema=_py_literal_schema(schema),
                location=f"{path}:{node.lineno}",
                # Only this tool's own branch of the shared call_tool dispatcher,
                # never the whole dispatcher: that would give every tool every
                # other tool's sinks. Empty when the branch cannot be identified.
                body=dispatch.get(name, ""),
            )
        )

    # A dispatcher with one declared tool and no branching implements that tool
    # outright, so there is nothing it could be confused with.
    if len(tools) == 1 and not dispatch and _py_dispatcher_body(tree):
        tools[0].body = _py_dispatcher_body(tree)
    return tools, gaps


def _py_dispatcher(tree: ast.AST):
    """The @server.call_tool() coroutine, if the module declares one."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            attr = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(attr, ast.Attribute) and attr.attr == "call_tool":
                return node
    return None


def _py_dispatcher_body(tree: ast.AST) -> str:
    node = _py_dispatcher(tree)
    return ast.unparse(node) if node is not None else ""


def _py_dispatch_branches(
    tree: ast.AST,
    enums: dict[str, str],
    constants: dict[str, str],
) -> dict[str, str]:
    """Map each declared tool name to the dispatcher branch that implements it.

    The prologue - everything the dispatcher runs before it branches, such as
    opening the repository or validating a path - is prepended to every branch,
    because it genuinely runs for every tool. What is never shared is one
    branch's body with another branch's tool.
    """
    node = _py_dispatcher(tree)
    if node is None:
        return {}

    branches: dict[str, str] = {}
    prologue_statements: list[ast.stmt] = []
    for statement in node.body:
        if isinstance(statement, ast.Match):
            for case in statement.cases:
                body = "\n".join(ast.unparse(inner) for inner in case.body)
                for name in _py_match_names(case.pattern, enums, constants):
                    branches[name] = body
            break
        if isinstance(statement, ast.If) and _py_compares_name(statement.test):
            _py_collect_if_chain(statement, enums, constants, branches)
            break
        prologue_statements.append(statement)

    if not branches:
        return {}
    prologue = "\n".join(ast.unparse(statement) for statement in prologue_statements)
    return {name: f"{prologue}\n{body}" if prologue else body for name, body in branches.items()}


def _py_compares_name(test: ast.AST) -> bool:
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "name"
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
    )


def _py_collect_if_chain(
    statement: ast.If,
    enums: dict[str, str],
    constants: dict[str, str],
    branches: dict[str, str],
) -> None:
    while True:
        if _py_compares_name(statement.test):
            name = _py_tool_name(statement.test.comparators[0], enums, constants)
            if name:
                branches[name] = "\n".join(ast.unparse(inner) for inner in statement.body)
        if len(statement.orelse) == 1 and isinstance(statement.orelse[0], ast.If):
            statement = statement.orelse[0]
            continue
        return


def _py_match_names(
    pattern: ast.AST,
    enums: dict[str, str],
    constants: dict[str, str],
) -> list[str]:
    if isinstance(pattern, ast.MatchOr):
        names: list[str] = []
        for alternative in pattern.patterns:
            names.extend(_py_match_names(alternative, enums, constants))
        return names
    if isinstance(pattern, ast.MatchValue):
        name = _py_tool_name(pattern.value, enums, constants)
        return [name] if name else []
    return []


def _py_literal_schema(node: ast.AST | None) -> dict:
    """Return an inputSchema dict only when it is a literal.

    Pydantic forms such as `Fetch.model_json_schema()` cannot be resolved
    without importing the target, which the auditor never does.
    """
    if not isinstance(node, ast.Dict):
        return {}
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return {}
    return value if isinstance(value, dict) else {}


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
    return _tool_decorator_registry(node) is not None


def _tool_decorator_registry(node: ast.AST) -> str | None:
    """The server object a tool decorator was applied to, if any.

    Returns the bare name for `@jira_mcp.tool()`, and an empty string for a
    plain `@tool()` where there is no object to attribute it to.
    """
    for dec in getattr(node, "decorator_list", []):
        attr = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(attr, ast.Attribute) and attr.attr == "tool":
            return attr.value.id if isinstance(attr.value, ast.Name) else ""
        if isinstance(attr, ast.Name) and attr.id == "tool":
            return ""
    return None


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
    """The JSON Schema a handler's signature implies.

    Positional-only and keyword-only parameters count. Reading `args.args`
    alone did not merely miss them -- it emitted `properties: {}`, an
    affirmative claim that the tool takes no arguments, which switched off
    every schema-driven rule (OP-002, DB-001, AT-001) for any handler that
    used `*,`.
    """
    props: dict[str, dict] = {}
    required: list[str] = []
    args = node.args
    positional = [*args.posonlyargs, *args.args]
    defaulted = (
        {a.arg for a in positional[len(positional) - len(args.defaults):]}
        if args.defaults
        else set()
    )
    defaulted |= {
        a.arg for a, default in zip(args.kwonlyargs, args.kw_defaults) if default is not None
    }
    for arg in [*positional, *args.kwonlyargs]:
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
# Matches both `server.registerTool("name", ...)` and the variable-bound form
# `server.registerTool(name, config, handler)` used when each tool lives in its
# own module, plus the dotted experimental task API
# `server.experimental.tasks.registerToolTask(...)`. Group 1 is a literal name,
# group 2 an identifier that still has to be resolved against the file.
_TS_REGISTER = re.compile(
    r"""[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.registerTool(?:Task)?\s*\(\s*"""
    r"""(?:["'`]([^"'`]+)["'`]|([A-Za-z_$][\w$]*)\s*,)""",
    re.DOTALL,
)
# `const name = "echo"` / `const config = {...}` bindings, resolved within one
# file only. Cross-module resolution is deliberately out of scope: it would need
# import following, and a wrong binding is worse than a reported gap.
_TS_BINDING = re.compile(r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=\s*""")
_TS_LOW_LEVEL_LIST = re.compile(
    r"""setRequestHandler\s*\(\s*(?:["'`]tools/list["'`]|ListToolsRequestSchema)""",
    re.DOTALL,
)


def _extract_typescript(path: str, text: str) -> tuple[bool, list[Tool], list[CoverageGap]]:
    sdk = bool(_TS_MCP_IMPORT.search(text))
    tools: list[Tool] = []
    gaps: list[CoverageGap] = []

    # registerTool/setRequestHandler are generic names. Require the official SDK
    # package signal before interpreting their call shapes as MCP definitions.
    if not sdk:
        return False, [], []

    for m in _TS_TOOL_STRING.finditer(text):
        name, desc = m.group(1), m.group(2)
        line = text.count("\n", 0, m.start()) + 1
        schema = _ts_schema_after(text, m.end())
        body = _ts_call_span(text, m.start())
        tools.append(Tool(name=name, description=desc, schema=schema, location=f"{path}:{line}", body=body))

    bindings = _ts_bindings(text)
    for m in _TS_REGISTER.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        identifier = m.group(2)
        name = m.group(1) if m.group(1) is not None else _ts_string_binding(bindings, identifier)
        if name is None:
            gaps.append(CoverageGap(
                construct="registerTool",
                location=f"{path}:{line}",
                reason=f"Tool name is bound to {identifier!r}, which is not a string "
                       f"constant in this file (imported or computed).",
            ))
            continue
        # v2 uses registerTool(name, {description, inputSchema, annotations}, handler).
        # With the variable form the config is an identifier too, so resolve it
        # before reading the description/schema/annotations out of it.
        config = _ts_registration_config(text, m.end(), bindings)
        dm = re.search(r"""description\s*:\s*["'`]([^"'`]*)["'`]""", config, re.DOTALL)
        desc = dm.group(1) if dm else ""
        body = _ts_call_span(text, m.start())
        tools.append(
            Tool(
                name=name,
                description=desc,
                schema=_ts_register_schema(config, bindings),
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
    return sdk, tools, gaps


def _ts_bindings(text: str) -> dict[str, str]:
    """Map every top-level `const NAME = <value>` to its value text."""
    out: dict[str, str] = {}
    for m in _TS_BINDING.finditer(text):
        out.setdefault(m.group(1), _ts_value_span(text, m.end()))
    return out


def _ts_value_span(text: str, pos: int, cap: int = _TS_BODY_CAP) -> str:
    """Capture one initializer, ending at the `;`/newline that closes it.

    Nesting and string state are tracked so a newline inside an object literal
    or a `z.object(...)` call does not cut the value short.
    """
    end = min(len(text), pos + cap)
    depth = 0
    quote: str | None = None
    escaped = False
    i = pos
    while i < end:
        ch = text[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and ch in ";\n":
            break
        i += 1
    return text[pos:i].strip()


def _ts_string_binding(bindings: dict[str, str], identifier: str | None) -> str | None:
    """Resolve an identifier to its string literal, or None if it is not one."""
    value = bindings.get(identifier or "", "")
    if len(value) >= 2 and value[0] in "'\"`" and value[-1] == value[0]:
        inner = value[1:-1]
        # A template literal with an interpolation is not a stable tool name.
        return inner if "${" not in inner else None
    return None


def _ts_registration_config(text: str, pos: int, bindings: dict[str, str]) -> str:
    """Return the registration's config object, following one identifier hop."""
    ident = re.match(r"\s*([A-Za-z_$][\w$]*)\s*[,)]", text[pos:pos + 120])
    if ident:
        value = bindings.get(ident.group(1), "")
        return value if value.startswith("{") else ""
    return _ts_object_after(text, pos, max_distance=600)


def _ts_call_span(text: str, start: int) -> str:
    """Capture one tool-registration call as text, ending at its balanced `)`.

    String/comment-aware paren matching so punctuation inside literals and
    comments cannot open or close the call. Falls back to a capped slice if the
    call never closes (malformed source).
    """
    open_idx = text.find("(", start)
    if open_idx == -1:
        return text[start: start + _TS_BODY_CAP]
    end_limit = min(len(text), start + _TS_BODY_CAP)
    call = _balanced_delimited(text[:end_limit], open_idx, "(", ")")
    if call:
        return text[start:open_idx + len(call)]
    return text[start:end_limit]


def _ts_object_after(text: str, pos: int, max_distance: int = 300) -> str:
    brace = text.find("{", pos, min(len(text), pos + max_distance))
    return _balanced_delimited(text, brace, "{", "}") if brace != -1 else ""


def _ts_register_schema(config: str, bindings: dict[str, str] | None = None) -> dict:
    """Extract common v2 inputSchema forms without evaluating JavaScript."""
    marker = re.search(r"\binputSchema\s*:", config)
    if not marker:
        return {}
    tail = config[marker.end():]
    # `inputSchema: EchoSchema` — follow one hop to the zod/object constant so
    # the parameter names are not silently read from whatever object comes next.
    ident = re.match(r"\s*([A-Za-z_$][\w$]*)\s*[,}\n]", tail)
    if ident and bindings:
        tail = bindings.get(ident.group(1), tail)
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
