"""Static capability inference for extracted MCP tool handlers.

This module is the bridge between the research-facing Threat Atlas and an
organization-facing privilege policy.  It does not claim to prove runtime
behaviour: every result carries the exact observable, location, and confidence
that produced it.  Target code is never imported or executed.

The scanner deliberately recognizes both Python and JavaScript/TypeScript APIs
without requiring Node or a native parser at runtime.  A small lexical pass
removes comments before API-call matching; this is substantially less noisy
than scanning raw text while preserving strings for SQL/URL evidence.  The
method is named honestly in the resulting confidence (medium unless the syntax
is especially unambiguous).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from .callgraph import CallIndex, build_index, find_guards, is_guard_chain, walk
from .types import CapabilityEvidence, Tool


# Stable policy vocabulary. New values are additive so stored departmental
# policies and JSON baselines remain valid.
CAPABILITIES = {
    "filesystem.read",
    "filesystem.write",
    "filesystem.delete",
    "database.read",
    "database.write",
    "database.raw-query",
    "database.destructive",
    "network.outbound",
    "process.execute",
    "environment.read",
    "secrets.read",
}

MUTATING_CAPABILITIES = {
    "filesystem.write",
    "filesystem.delete",
    "database.write",
    "database.raw-query",  # may carry writes; conservative until SQL is known
    "database.destructive",
    "process.execute",
}

DESTRUCTIVE_CAPABILITIES = {
    "filesystem.delete",
    "database.destructive",
    "process.execute",
}


_API_PATTERNS: tuple[tuple[str, re.Pattern[str], bool, str], ...] = (
    (
        "filesystem.read",
        re.compile(
            r"\b(?:fs(?:\.promises)?\.)?"
            r"(?:readFile|readFileSync|createReadStream|readdir|readdirSync"
            # Metadata is content too: stat/lstat/realpath answer questions
            # about a path the caller supplied.
            r"|stat|statSync|lstat|lstatSync|realpath|realpathSync)\s*\("
            r"|\bos\.(?:stat|lstat|listdir|scandir|walk)\s*\("
            r"|\bPath\([^\n)]*\)\.(?:stat|iterdir|glob|rglob)\s*\("
            r"|\bPath\([^\n)]*\)\.(?:read_text|read_bytes)\s*\("
            r"|\bopen\s*\([^\n)]*\)\.read\s*\(",
            re.IGNORECASE,
        ),
        False,
        "medium",
    ),
    (
        "filesystem.write",
        re.compile(
            r"\b(?:fs(?:\.promises)?\.)?"
            r"(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream"
            # Creating a directory, copying onto a path, and renaming all put
            # bytes at a path the caller chose. Classifying rename as a delete
            # alone described only half of what move_file does.
            r"|mkdir|mkdirSync|copyFile|copyFileSync|cp|cpSync|rename|renameSync)\s*\("
            r"|\bPath\([^\n)]*\)\.(?:write_text|write_bytes|mkdir)\s*\("
            r"|\bos\.(?:mkdir|makedirs|rename|replace)\s*\("
            r"|\bshutil\.(?:copy|copy2|copyfile|copytree|move)\s*\("
            r"|\bopen\s*\([^\n,]+,\s*[\"'][wax][^\"']*[\"']"
            # A commit, an add, a checkout or a reset all change bytes on disk -
            # in .git and often in the working tree. A reviewer asking what a
            # tool can alter needs these named.
            r"|\brepo\.index\.(?:commit|add|remove|move|reset|write)\s*\("
            r"|\brepo\.git\.(?:add|commit|checkout|reset|rm|mv|merge|rebase|apply|clean|stash)\s*\("
            r"|\brepo\.(?:create_head|delete_head|create_tag|clone_from)\s*\(",
            re.IGNORECASE,
        ),
        False,
        "high",
    ),
    (
        "filesystem.delete",
        re.compile(
            # Qualified only. A bare `remove(` is far more often a collection
            # operation - `sessionResources.remove(uri)`, `items.remove(name)` -
            # than a file deletion, and matching it put a destructive capability
            # on tools that never touch disk.
            r"\bfs(?:\.promises)?\."
            r"(?:unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|rename|renameSync)\s*\("
            r"|\bos\.(?:remove|unlink|rmdir|removedirs|rename|replace)\s*\("
            r"|\bPath\([^\n)]*\)\.(?:unlink|rmdir)\s*\("
            r"|\bshutil\.(?:rmtree|move)\s*\("
            r"|\brepo\.(?:index\.remove|git\.(?:rm|clean))\s*\(",
            re.IGNORECASE,
        ),
        True,
        "high",
    ),
    (
        "network.outbound",
        re.compile(
            r"\bfetch\s*\(|\baxios(?:\.(?:get|post|put|patch|delete|request))?\s*\("
            r"|\b(?:https?|https?x?)\.(?:get|post|put|patch|request)\s*\("
            r"|\brequests\.(?:get|post|put|patch|delete|request)\s*\("
            r"|\burlopen\s*\(|\bsocket\.connect\s*\("
            # Modern async clients are constructed first and called through a
            # local name, so neither `httpx.get` nor `requests.get` appears.
            r"|\b(?:httpx\.)?Async(?:Client|HTTPTransport)\s*\("
            r"|\baiohttp\.ClientSession\s*\("
            r"|\bclient\.(?:get|post|put|patch|delete|request|stream|send)\s*\(",
            re.IGNORECASE,
        ),
        False,
        "high",
    ),
    (
        "process.execute",
        re.compile(
            r"\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|fork)\s*\("
            r"|\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\("
            r"|\bos\.(?:system|popen)\s*\(|\bDeno\.Command\s*\(|\bBun\.spawn\s*\(",
            re.IGNORECASE,
        ),
        True,
        "high",
    ),
    (
        "environment.read",
        re.compile(
            r"\bprocess\.env\b"
            r"|\bos\.(?:environ|getenv)\b|\b(?:dotenv|load_dotenv)\b",
            re.IGNORECASE,
        ),
        False,
        "medium",
    ),
    (
        "secrets.read",
        re.compile(
            r"\bprocess\.env(?:\.|\s*\[\s*[\"'])"
            r"[A-Za-z0-9_]*(?:secret|token|password|passwd|api[_-]?key|credential|private[_-]?key)"
            r"[A-Za-z0-9_]*"
            r"|\bos\.getenv\s*\(\s*[\"'][^\"']*"
            r"(?:secret|token|password|passwd|api[_-]?key|credential|private[_-]?key)[^\"']*[\"']",
            re.IGNORECASE,
        ),
        False,
        "high",
    ),
)

# Helpers whose job is to decide, not to act. A path validator resolving a
# realpath to enforce an allow-list is the guard working correctly; charging the
# tool with "filesystem.read" for it would put a read on every single guarded
# tool and make the matrix useless.
#
# The exemption is one-directional on purpose. Only read-only effects are
# dropped: a helper called `checkAndPurge` that deletes is precisely the case a
# reviewer must never lose, so mutating, destructive and outbound effects
# propagate out of a guard exactly like any other call.
_GUARD_EXEMPT = frozenset({"filesystem.read", "database.read", "environment.read"})


_DB_CALL = re.compile(
    r"\b(?:cursor|db|database|client|pool|connection|conn)?\.?(?:query|execute|executemany|executescript)\s*\("
    r"|\b(?:db|database)\.(?:run|all|get|exec)\s*\(",
    re.IGNORECASE,
)
_SQL_READ = re.compile(r"\bselect\b", re.IGNORECASE)
_SQL_WRITE = re.compile(r"\b(?:insert|update|upsert|replace)\b", re.IGNORECASE)
_SQL_DESTRUCTIVE = re.compile(
    r"\b(?:delete\s+from|drop\s+(?:table|database|schema|index)|truncate|"
    r"alter\s+(?:table|user|role|database)|grant\b)",
    re.IGNORECASE,
)


def _without_comments(text: str, *, hash_comments: bool) -> str:
    """Replace comments with spaces while preserving strings and offsets."""
    out = list(text)
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if line_comment:
            if ch == "\n":
                line_comment = False
            else:
                out[i] = " "
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                block_comment = False
                i += 2
            else:
                if ch != "\n":
                    out[i] = " "
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
            i += 1
            continue
        if ch == "/" and nxt == "/":
            out[i] = out[i + 1] = " "
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            block_comment = True
            i += 2
            continue
        if hash_comments and ch == "#":
            out[i] = " "
            line_comment = True
        i += 1
    return "".join(out)


def _location(tool: Tool, body: str, pos: int) -> str:
    path, sep, raw_line = tool.location.rpartition(":")
    if not sep or not raw_line.isdigit():
        return tool.location
    return f"{path}:{int(raw_line) + body.count(chr(10), 0, pos)}"


def _short_evidence(match: re.Match[str]) -> str:
    return " ".join(match.group(0).split())[:120]


def _add(
    out: list[CapabilityEvidence],
    seen: set[tuple[str, str]],
    tool: Tool,
    body: str,
    capability: str,
    match: re.Match[str],
    *,
    confidence: str,
    destructive: bool = False,
) -> None:
    evidence = _short_evidence(match)
    key = (capability, evidence.lower())
    if key in seen:
        return
    seen.add(key)
    out.append(
        CapabilityEvidence(
            capability=capability,
            evidence=evidence,
            location=_location(tool, body, match.start()),
            confidence=confidence,
            destructive=destructive,
        )
    )


def _scan(
    out: list[CapabilityEvidence],
    seen: set[tuple[str, str]],
    code: str,
    *,
    location: str,
    chain: tuple[str, ...] = (),
) -> None:
    """Match every sink pattern in one body and record it against `location`.

    `chain` is the sequence of calls that led here from the handler. It is
    written into the evidence so a reviewer can see the effect is one or more
    hops away rather than in the tool itself.
    """
    path, sep, raw_line = location.rpartition(":")
    base = int(raw_line) if sep and raw_line.isdigit() else 0
    trail = " -> ".join(chain)

    guarded = is_guard_chain(chain)

    def record(capability: str, match: re.Match[str], confidence: str, destructive: bool) -> None:
        if guarded and capability in _GUARD_EXEMPT:
            return
        evidence = _short_evidence(match)
        key = (capability, evidence.lower())
        if key in seen:
            return
        seen.add(key)
        out.append(
            CapabilityEvidence(
                capability=capability,
                evidence=f"{evidence} (via {trail})" if trail else evidence,
                location=f"{path}:{base + code.count(chr(10), 0, match.start())}" if sep else location,
                # An effect reached through a call chain is real but indirect;
                # it never claims the confidence of a sink in the handler.
                confidence="medium" if trail and confidence == "high" else confidence,
                destructive=destructive,
            )
        )

    for capability, pattern, destructive, confidence in _API_PATTERNS:
        for match in pattern.finditer(code):
            record(capability, match, confidence, destructive)

    db_call = _DB_CALL.search(code)
    if db_call:
        destructive = _SQL_DESTRUCTIVE.search(code)
        write = _SQL_WRITE.search(code)
        read = _SQL_READ.search(code)
        if destructive:
            record("database.destructive", destructive, "high", True)
        elif write:
            record("database.write", write, "high", False)
        elif read:
            record("database.read", read, "high", False)
        else:
            record("database.raw-query", db_call, "medium", False)


def infer_capabilities(tool: Tool, index: CallIndex | None = None) -> list[CapabilityEvidence]:
    """Infer a deterministic, evidence-backed capability list for one tool.

    With a `CallIndex`, sinks reached through resolvable helper calls are
    attributed too, each carrying the chain that led to it. Without one, only
    the handler body is read - the behaviour every caller had before P2.
    """
    body = tool.body or ""
    if not body:
        return []
    is_python = tool.location.rpartition(":")[0].lower().endswith(".py")
    code = _without_comments(body, hash_comments=is_python)
    out: list[CapabilityEvidence] = []
    seen: set[tuple[str, str]] = set()

    if index is not None:
        reached, unresolved = walk(code, index)
        tool.unresolved_calls = unresolved
        tool.guards = find_guards(code, index)
        for hop in reached:
            hop_python = hop.definition.location.rpartition(":")[0].lower().endswith(".py")
            hop_code = _without_comments(hop.definition.body, hash_comments=hop_python)
            _scan(out, seen, hop_code, location=hop.definition.location, chain=hop.chain)

    for capability, pattern, destructive, confidence in _API_PATTERNS:
        for match in pattern.finditer(code):
            _add(
                out,
                seen,
                tool,
                body,
                capability,
                match,
                confidence=confidence,
                destructive=destructive,
            )

    db_call = _DB_CALL.search(code)
    if db_call:
        destructive = _SQL_DESTRUCTIVE.search(code)
        write = _SQL_WRITE.search(code)
        read = _SQL_READ.search(code)
        if destructive:
            _add(
                out, seen, tool, body, "database.destructive", destructive,
                confidence="high", destructive=True,
            )
        elif write:
            _add(out, seen, tool, body, "database.write", write, confidence="high")
        elif read:
            _add(out, seen, tool, body, "database.read", read, confidence="high")
        else:
            _add(out, seen, tool, body, "database.raw-query", db_call, confidence="medium")

    return sorted(out, key=lambda item: (item.capability, item.location, item.evidence))


def infer_all(tools: Iterable[Tool], files: dict[str, str] | None = None) -> None:
    """Populate each tool in place; kept separate so extraction remains pure.

    `files` enables helper-call propagation. It is optional so callers holding
    only a tool list keep the direct-body behaviour rather than silently
    getting a different answer.
    """
    index = build_index(files) if files else None
    for tool in tools:
        tool.capabilities = infer_capabilities(tool, index)
