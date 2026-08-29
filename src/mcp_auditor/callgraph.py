"""Bounded, intra-repository call graph (spec P2).

Almost no real handler contains its own sinks. The reference filesystem server
reaches disk through `readFileContent`/`writeFileContent`, and every tool in the
reference memory server delegates to one `KnowledgeGraphManager` method. A
scanner that only reads handler bodies reports those servers as doing nothing.

The opposite failure is worse: attributing every sink in a file to every tool
declared in it makes a read-only tool look destructive and destroys the reason
to trust the matrix at all. So resolution here is deliberately conservative.

* One name resolves to one definition, or to none. An ambiguous name - two
  definitions in the repository - is never guessed at.
* Only definitions found in the audited files are followed. An import from
  outside the repository is a boundary, not a lead.
* Depth is capped, cycles terminate, and computed dispatch stops the walk.
* Everything the walk could not resolve is recorded, so the gap is visible
  rather than silently absorbed into a clean-looking result.

Nothing here executes, imports, or evaluates the target. Definitions are located
by parsing (Python) or balanced-delimiter scanning (TypeScript/JavaScript).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .jsscan import balanced_delimited

# How many hops past the handler a sink may sit and still be attributed. Three
# covers handler -> manager method -> private loader/saver, which is the deepest
# real chain in the reference servers, without letting a long utility chain pull
# in effects a reviewer would not recognize as this tool's.
MAX_DEPTH = 3

_PY_EXT = (".py",)
_TS_EXT = (".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx")

# Control-flow and declaration keywords that are followed by `(` and would
# otherwise read as calls.
_NOT_CALLS = frozenset({
    # `async` earns its place: `async (args) => {}` on its own indented line
    # reads as a method named `async`, and two registrations in one file then
    # make that name ambiguous on every tool the file declares.
    "async", "case", "default", "export", "from", "as", "of",
    "if", "for", "while", "switch", "catch", "return", "typeof", "await", "yield",
    "function", "class", "new", "delete", "void", "throw", "super", "constructor",
    "import", "require", "def", "elif", "else", "print", "with", "assert", "and",
    "or", "not", "in", "is", "lambda", "try", "except", "finally", "raise",
    "String", "Number", "Boolean", "Array", "Object", "JSON", "Promise", "Error",
    "Math", "Date", "RegExp", "Set", "Map", "parseInt", "parseFloat", "isinstance",
    "len", "str", "int", "float", "list", "dict", "tuple", "range", "enumerate",
    "sorted", "any", "all", "zip", "map", "filter", "type", "repr", "format",
})

# Computed or reflective dispatch: the target is decided at runtime, so the walk
# stops and says so instead of following whichever branch happens to be nearby.
_DYNAMIC_CALL = re.compile(
    r"[A-Za-z_$\]\)][\w$]*\s*\[[^\]\n]+\]\s*\("      # handlers[name](...)
    r"|\bgetattr\s*\("
    r"|\beval\s*\(|\bexec\s*\("
    r"|\bnew\s+Function\s*\("
    r"|\.\s*(?:apply|call|bind)\s*\("
    r"|\bglobals\s*\(\s*\)\s*\[",
)

_CALL = re.compile(r"(?:\.\s*)?\b([A-Za-z_$][\w$]*)\s*\(")

# Names bound by an import from a package rather than a relative path. Following
# one would leave the repository, and reporting it as unresolved would describe
# a dependency as a hole in the audit. Either way it is a boundary, so the walk
# neither resolves nor complains about it - even when something in the tree
# happens to share the name.
_BARE_IMPORT = re.compile(
    r"import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*[\"'`](?![./])[^\"'`]+[\"'`]"
    r"|import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{([^}]*)\})?\s*from\s*[\"'`](?![./])[^\"'`]+[\"'`]"
    r"|from\s+([A-Za-z_][\w.]*)\s+import\s+([^\n#]+)",
)

# A guard's job is to decide, and its read-only internals are dropped from the
# capability result anyway. Running out of budget inside one is therefore not a
# gap worth sending a reviewer to ask the vendor about.
_GUARD_NAME = re.compile(
    r"^(?:validate|check|assert|ensure|verify|require|is|has|can)(?:[_A-Z]|$)"
)


def is_guard_chain(chain: tuple[str, ...]) -> bool:
    """True when a call chain passes through something whose job is to decide."""
    return any(_GUARD_NAME.match(name) for name in chain)


# `registerTool(name, config, readTextFileHandler)` - the handler is passed by
# reference, so the call scanner never sees it. Only a bare identifier in the
# final argument position counts: anything looser would start following
# identifiers that merely share a name with a function somewhere in the tree.
_HANDLER_REFERENCE = re.compile(r",\s*([A-Za-z_$][\w$]*)\s*,?\s*\)\s*;?\s*$")

_TS_FUNCTION = re.compile(
    r"(?:^|[\n;])\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*"
    r"([A-Za-z_$][\w$]*)\s*\(",
)
_TS_ARROW = re.compile(
    r"(?:^|[\n;])\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*"
    r"(?::[^=;\n]+)?=\s*(?:async\s+)?(?:\([^()]*\)|[A-Za-z_$][\w$]*)\s*"
    r"(?::[^=>{;\n]+)?=>",
)
_TS_METHOD = re.compile(
    r"\n[ \t]+(?:(?:private|public|protected|static|readonly|async|get|set)\s+)*"
    r"([A-Za-z_$][\w$]*)\s*\([^()]*\)",
)


@dataclass(frozen=True)
class Definition:
    """One statically located function/method body."""

    name: str
    location: str
    body: str


@dataclass
class CallIndex:
    """Every uniquely-named definition in the audited tree.

    A name mapping to more than one definition is dropped rather than
    arbitrated: see `ambiguous`.
    """

    definitions: dict[str, Definition] = field(default_factory=dict)
    ambiguous: set[str] = field(default_factory=set)
    external: set[str] = field(default_factory=set)
    # Which package each external name came from, so an unknown can say where
    # the effect went rather than only that it went somewhere.
    external_sources: dict[str, str] = field(default_factory=dict)

    def resolve(self, name: str) -> Definition | None:
        if name in self.ambiguous or name in self.external:
            return None
        return self.definitions.get(name)

    def add(self, definition: Definition) -> None:
        existing = self.definitions.get(definition.name)
        if existing is None:
            self.definitions[definition.name] = definition
        elif existing.location != definition.location:
            self.ambiguous.add(definition.name)


def build_index(files: dict[str, str]) -> CallIndex:
    """Index the function and method bodies defined across the audited files."""
    index = CallIndex()
    for path, text in files.items():
        lower = path.lower()
        try:
            imported = _imported_from_packages(text)
            index.external.update(imported)
            index.external_sources.update(imported)
            derived = _externally_derived(text, imported)
            index.external_sources.update(derived)
            if lower.endswith(_PY_EXT):
                _index_python(index, path, text)
            elif lower.endswith(_TS_EXT):
                _index_typescript(index, path, text)
        except Exception:
            # One unparsable file must never abort the walk.
            continue
    return index


def _imported_from_packages(text: str) -> dict[str, str]:
    """Names this file binds from an installed package, mapped to the package.

    A sibling module reached by a relative import is not external: it is part of
    the audited tree and the walk should follow it.
    """
    names: dict[str, str] = {}
    for match in _BARE_IMPORT.finditer(text):
        package = _package_of(match.group(0))
        for group in match.groups():
            if not group:
                continue
            for part in group.split(","):
                name = part.split(" as ")[-1].strip().strip("()")
                if name and name.isidentifier():
                    names[name] = package
    return names


# `client = Jira(...)` / `const client = new Chroma(...)`: an object built from
# an imported symbol carries that symbol's boundary with it, so calls made on it
# leave the repository just as directly as calls on the symbol itself.
_DERIVED_BINDING = re.compile(
    r"(?:^|\n)\s*(?:const|let|var\s)?\s*([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*"
    r"(?:new\s+|await\s+)?([A-Za-z_$][\w$]*)\s*\(",
)


def _externally_derived(text: str, imported: dict[str, str]) -> dict[str, str]:
    """Names bound to an object constructed from an imported symbol."""
    derived: dict[str, str] = {}
    for match in _DERIVED_BINDING.finditer(text):
        target, source = match.group(1), match.group(2)
        if source in imported and target not in imported:
            derived[target] = imported[source]
    return derived


def _package_of(statement: str) -> str:
    """The package an import statement names."""
    quoted = re.search(r"[\"'`]([^\"'`]+)[\"'`]", statement)
    if quoted:
        return quoted.group(1)
    dotted = re.search(r"\bfrom\s+([A-Za-z_][\w.]*)", statement)
    return dotted.group(1) if dotted else "an external package"


def _index_python(index: CallIndex, path: str, text: str) -> None:
    tree = ast.parse(text)
    lines = text.splitlines(keepends=True)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = getattr(node, "end_lineno", None) or node.lineno
        body = "".join(lines[node.lineno - 1: end])
        index.add(Definition(node.name, f"{path}:{node.lineno}", body))


def _index_typescript(index: CallIndex, path: str, text: str) -> None:
    # Only the `function` form leaves the match inside the parameter list; the
    # arrow and method patterns already end past it.
    for pattern, skip_parameters, strict in (
        (_TS_FUNCTION, True, False), (_TS_ARROW, False, False), (_TS_METHOD, False, True)
    ):
        for match in pattern.finditer(text):
            name = match.group(1)
            if name in _NOT_CALLS:
                continue
            body = _ts_body_after(text, match.end(), skip_parameters, strict)
            if not body:
                continue
            line = text.count("\n", 0, match.start(1)) + 1
            index.add(Definition(name, f"{path}:{line}", body))


# What may sit between a method's parameter list and its body: whitespace and a
# return-type annotation, which in TypeScript can carry braces and semicolons of
# its own (`Promise<{ entityName: string; added: string[] }[]>`). What it can
# never carry is another call. `runResearchProcess(\n ...\n).catch(err => {` is
# a call, and reading its callback as the function's body registered a second
# definition of a name that exists once - which made the real one "ambiguous"
# and turned a plainly readable tool into an UNKNOWN.
_SIGNATURE_GAP = re.compile(r"^[^()=]*$")


def _ts_body_after(text: str, pos: int, skip_parameters: bool, strict: bool = False) -> str:
    """Return the balanced `{...}` block that follows a signature."""
    if skip_parameters:
        # `pos` sits just past the opening paren of the parameter list; scan the
        # balanced list from that paren so a default value like `= '(utf-8'`
        # cannot unbalance it.
        params = balanced_delimited(text, pos - 1, "(", ")")
        if not params:
            return ""
        pos = pos - 1 + len(params)
    brace = _body_brace(text, pos)
    if brace == -1:
        return ""
    if strict and not _SIGNATURE_GAP.match(text[pos:brace]):
        return ""
    return balanced_delimited(text, brace, "{", "}")


def _body_brace(text: str, pos: int, limit: int = 400) -> int:
    """Index of the brace that opens a body, or -1.

    A return-type annotation can contain braces of its own - TypeScript's
    `Promise<{ entityName: string }[]>` is ordinary in the reference memory
    server - so angle-bracket depth is tracked and any brace inside a generic
    is skipped. Stopping at the first brace instead indexed the type literal as
    the function body, which reads as a helper that does nothing at all.
    """
    angle = 0
    end = min(len(text), pos + limit)
    for i in range(pos, end):
        ch = text[i]
        if ch == "<":
            angle += 1
        elif ch == ">":
            angle = max(0, angle - 1)
        elif ch == ";" and angle == 0:
            return -1          # a declaration or overload signature, no body
        elif ch == "{" and angle == 0:
            return i
    return -1


_RECEIVER_CALL = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\("
)
_MCP_REGISTRATION_METHODS = {"registerTool", "registerToolTask", "tool", "setRequestHandler"}


def external_receivers(body: str, index: "CallIndex") -> list[tuple[str, str]]:
    """Calls this body makes on something that came from outside the tree.

    Both `Jira(...)` used directly and `client.issue(...)` where `client` was
    built from an imported `Jira` count: the effect is real, and it is somewhere
    this analysis cannot see.
    """
    found: dict[str, str] = {}
    for match in _RECEIVER_CALL.finditer(body):
        receiver, method = match.groups()
        package = index.external_sources.get(receiver)
        if (
            package
            and "modelcontextprotocol" in package.lower()
            and method in _MCP_REGISTRATION_METHODS
        ):
            # The extractor currently keeps the complete registration call as
            # the handler surface. Registering the handler is framework setup,
            # not an effect performed when the tool itself runs.
            continue
        if package:
            found.setdefault(receiver, package)
    for name in called_names(body):
        package = index.external_sources.get(name)
        if package:
            found.setdefault(name, package)
    return sorted(found.items())


def called_names(body: str) -> list[str]:
    """Names invoked in a body, plus a handler referenced by name."""
    seen: dict[str, None] = {}
    for match in _CALL.finditer(body):
        name = match.group(1)
        if name not in _NOT_CALLS:
            seen.setdefault(name, None)
    reference = _HANDLER_REFERENCE.search(body.rstrip())
    if reference and reference.group(1) not in _NOT_CALLS:
        seen.setdefault(reference.group(1), None)
    return list(seen)


@dataclass
class Reached:
    """One helper body the walk resolved, with the path taken to reach it."""

    definition: Definition
    chain: tuple[str, ...]


def walk(body: str, index: CallIndex, max_depth: int = MAX_DEPTH) -> tuple[list[Reached], list[str]]:
    """Follow resolvable calls out of `body`.

    Returns the helper bodies reached and a list of notes describing what the
    walk refused to follow, so an incomplete answer never looks complete.
    """
    reached: list[Reached] = []
    unresolved: list[str] = []
    visited: set[str] = set()
    # (body, chain-so-far, depth)
    frontier: list[tuple[str, tuple[str, ...], int]] = [(body, (), 0)]

    while frontier:
        current, chain, depth = frontier.pop(0)
        if _DYNAMIC_CALL.search(current):
            note = "dynamic dispatch" + (f" via {' -> '.join(chain)}" if chain else "")
            if note not in unresolved:
                unresolved.append(note)
        if depth >= max_depth:
            # Stop, but say so when there was still something resolvable here -
            # unless the truncated chain runs through a guard, whose internals
            # are excluded from the result anyway.
            if not is_guard_chain(chain) and any(
                index.resolve(name) for name in called_names(current)
            ):
                note = f"call depth limit of {max_depth} reached via {' -> '.join(chain)}"
                if note not in unresolved:
                    unresolved.append(note)
            continue

        for name in called_names(current):
            if name in index.external:
                continue
            if name in index.ambiguous:
                note = f"{name} (ambiguous: defined more than once)"
                if note not in unresolved:
                    unresolved.append(note)
                continue
            definition = index.resolve(name)
            if definition is None:
                continue
            if definition.location in visited:
                continue
            visited.add(definition.location)
            next_chain = chain + (name,)
            reached.append(Reached(definition, next_chain))
            frontier.append((definition.body, next_chain, depth + 1))

    return reached, unresolved


# --- verified input guards ---------------------------------------------------

# A guard earns the name by doing two things: turning the caller's input into a
# canonical form, and then checking that the result stays inside a boundary.
# Either half alone proves nothing - resolving a path without checking it is
# just resolving a path, and a null check constrains nothing at all.
_PATH_CANONICALIZE = re.compile(
    r"\brealpath(?:Sync)?\s*\(|\bpath\.resolve\s*\(|\bpath\.normalize\s*\("
    r"|\bos\.path\.(?:realpath|abspath|normpath)\s*\(|\bPath\([^\n)]*\)\.resolve\s*\(",
)
_PATH_CONTAINMENT = re.compile(
    r"\.startsWith\s*\(|\bpath\.relative\s*\(|\bos\.path\.commonpath\s*\("
    r"|\.is_relative_to\s*\(|\brelative_to\s*\("
    r"|\ballowed(?:Directories|Dirs|Paths|Roots)\b|\ballowed_(?:directories|dirs|paths|roots)\b",
)


def find_guards(body: str, index: CallIndex, max_depth: int = MAX_DEPTH) -> list[dict[str, str]]:
    """Verified guards reachable from a handler body.

    Recognition is structural: the function is reached by a real call, and its
    body both canonicalizes and bounds the value. There is deliberately no way
    to mark a server, a package, or a tool name as trusted - a guard is only
    ever credited when the evidence for it is in the source.
    """
    guards: list[dict[str, str]] = []
    seen: set[str] = set()
    reached, _ = walk(body, index, max_depth)
    for hop in reached:
        definition = hop.definition
        if definition.location in seen:
            continue
        canonical = _PATH_CANONICALIZE.search(definition.body)
        containment = _PATH_CONTAINMENT.search(definition.body)
        if not (canonical and containment):
            continue
        seen.add(definition.location)
        guards.append({
            "name": definition.name,
            "parameter_kind": "path",
            "location": definition.location,
            "evidence": " ".join(
                f"{canonical.group(0)} then {containment.group(0)}".split()
            ),
        })
    return guards
