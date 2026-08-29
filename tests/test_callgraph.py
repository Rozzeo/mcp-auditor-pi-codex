"""P2: attribute effects that sit behind a helper call, and only those.

The reference servers put almost every sink one hop away from the handler:
the filesystem server through `readFileContent`/`writeFileContent`, the memory
server through a `KnowledgeGraphManager` method. Following that hop is the whole
point; following it too eagerly reintroduces the cross-tool leakage P1 closed.
"""

from mcp_auditor.capabilities import infer_all
from mcp_auditor.extractor import extract


def _tools(files: dict[str, str]):
    extraction = extract(files)
    infer_all(extraction.tools, files=files)
    return {tool.name: tool for tool in extraction.tools}


def _caps(tool) -> set[str]:
    return {evidence.capability for evidence in tool.capabilities}


TS_HEADER = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'

SAME_FILE_HELPER = TS_HEADER + '''
async function readFileContent(p) {
  return await fs.readFile(p, "utf-8");
}

server.registerTool("read_report", { description: "Read." }, async (args) => {
  return await readFileContent(args.path);
});

server.registerTool("ping", { description: "Ping." }, async () => {
  return "pong";
});
'''


def test_a_sink_one_hop_away_is_attributed_to_the_calling_tool():
    tools = _tools({"index.ts": SAME_FILE_HELPER})

    assert "filesystem.read" in _caps(tools["read_report"])


def test_a_sibling_tool_that_does_not_call_the_helper_stays_clean():
    """The leakage guard: same file, same registration shape, no call."""
    tools = _tools({"index.ts": SAME_FILE_HELPER})

    assert _caps(tools["ping"]) == set()


def test_the_evidence_names_the_helper_that_actually_holds_the_sink():
    tools = _tools({"index.ts": SAME_FILE_HELPER})
    evidence = next(e for e in tools["read_report"].capabilities if e.capability == "filesystem.read")

    assert "readFileContent" in evidence.evidence
    assert "index.ts" in evidence.location


CROSS_FILE_INDEX = TS_HEADER + '''
import { writeFileContent } from "./lib.js";

server.registerTool("write_report", { description: "Write." }, async (args) => {
  await writeFileContent(args.path, args.body);
});
'''

CROSS_FILE_LIB = '''
export async function writeFileContent(p, body) {
  await fs.writeFile(p, body);
}
'''


def test_a_helper_in_another_file_of_the_same_repository_resolves():
    tools = _tools({"index.ts": CROSS_FILE_INDEX, "lib.ts": CROSS_FILE_LIB})

    assert "filesystem.write" in _caps(tools["write_report"])


MEMORY_SHAPE = TS_HEADER + '''
class KnowledgeGraphManager {
  private async loadGraph() {
    const data = await fs.readFile(this.memoryFilePath, "utf-8");
    return JSON.parse(data);
  }

  async saveGraph(graph) {
    await fs.writeFile(this.memoryFilePath, JSON.stringify(graph));
  }

  async createEntities(entities) {
    const graph = await this.loadGraph();
    await this.saveGraph(graph);
    return entities;
  }

  async readGraph() {
    return this.loadGraph();
  }
}

const knowledgeGraphManager = new KnowledgeGraphManager();

server.registerTool("create_entities", { description: "Create." }, async (args) => {
  return await knowledgeGraphManager.createEntities(args.entities);
});

server.registerTool("read_graph", { description: "Read." }, async () => {
  return await knowledgeGraphManager.readGraph();
});
'''


def test_a_class_method_two_hops_deep_is_attributed():
    """The P2 exit criterion, in miniature: the memory server's shape."""
    tools = _tools({"index.ts": MEMORY_SHAPE})

    assert "filesystem.write" in _caps(tools["create_entities"])
    assert "filesystem.read" in _caps(tools["create_entities"])


def test_a_read_only_method_does_not_pick_up_its_siblings_write():
    tools = _tools({"index.ts": MEMORY_SHAPE})

    assert "filesystem.read" in _caps(tools["read_graph"])
    assert "filesystem.write" not in _caps(tools["read_graph"])


DEEP_CHAIN = TS_HEADER + '''
function level4(p) { return fs.unlink(p); }
function level3(p) { return level4(p); }
function level2(p) { return level3(p); }
function level1(p) { return level2(p); }

server.registerTool("deep", { description: "Deep." }, async (args) => {
  return level1(args.path);
});
'''


def test_propagation_stops_at_the_configured_depth_instead_of_guessing():
    tools = _tools({"index.ts": DEEP_CHAIN})

    assert "filesystem.delete" not in _caps(tools["deep"])
    assert tools["deep"].unresolved_calls


def test_a_shallower_chain_within_the_budget_still_resolves():
    files = {"index.ts": DEEP_CHAIN.replace("return level1(args.path);", "return level3(args.path);")}
    tools = _tools(files)

    assert "filesystem.delete" in _caps(tools["deep"])


AMBIGUOUS_A = '''
export async function process(p) { await fs.rm(p); }
'''
AMBIGUOUS_B = '''
export async function process(p) { return p.trim(); }
'''
AMBIGUOUS_INDEX = TS_HEADER + '''
server.registerTool("run", { description: "Run." }, async (args) => {
  return await process(args.path);
});
'''


def test_an_ambiguous_helper_name_is_not_guessed_at():
    """Two definitions, one destructive. Picking either would be a coin flip."""
    tools = _tools({"index.ts": AMBIGUOUS_INDEX, "a.ts": AMBIGUOUS_A, "b.ts": AMBIGUOUS_B})

    assert _caps(tools["run"]) == set()
    assert "process" in " ".join(tools["run"].unresolved_calls)


CYCLE = TS_HEADER + '''
function alpha(p) { return beta(p); }
function beta(p) { return alpha(p) || fs.writeFile(p, ""); }

server.registerTool("cyclic", { description: "Cycle." }, async (args) => {
  return alpha(args.path);
});
'''


def test_a_call_cycle_terminates():
    tools = _tools({"index.ts": CYCLE})

    assert "filesystem.write" in _caps(tools["cyclic"])


PY_HELPER = '''
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


def _persist(path, body):
    with open(path, "w") as fh:
        fh.write(body)


@mcp.tool()
def save_note(path: str, body: str) -> str:
    """Save a note."""
    _persist(path, body)
    return "ok"


@mcp.tool()
def greet(name: str) -> str:
    """Greet someone."""
    return f"hello {name}"
'''


def test_a_python_helper_call_is_followed():
    tools = _tools({"server.py": PY_HELPER})

    assert "filesystem.write" in _caps(tools["save_note"])
    assert _caps(tools["greet"]) == set()


DYNAMIC = TS_HEADER + '''
const handlers = { write: (p) => fs.writeFile(p, "") };

server.registerTool("dispatch", { description: "Dispatch." }, async (args) => {
  return handlers[args.action](args.path);
});
'''


def test_dynamic_dispatch_is_recorded_as_unknown_not_resolved():
    tools = _tools({"index.ts": DYNAMIC})

    assert "filesystem.write" not in _caps(tools["dispatch"])
    assert any("dynamic" in note for note in tools["dispatch"].unresolved_calls)


def test_capabilities_still_work_without_a_file_map():
    """Callers that only have tools keep the direct-body behaviour."""
    extraction = extract({"index.ts": SAME_FILE_HELPER})
    infer_all(extraction.tools)
    tools = {tool.name: tool for tool in extraction.tools}

    assert _caps(tools["read_report"]) == set()


NAMED_HANDLER = TS_HEADER + '''
const readTextFileHandler = async (args) => {
  const validPath = await validatePath(args.path);
  return await fs.readFile(validPath, "utf-8");
};

server.registerTool("read_file", { description: "Deprecated alias." }, readTextFileHandler);
server.registerTool("read_text_file", { description: "Read text." }, readTextFileHandler);
server.registerTool("ping", { description: "Ping." }, async () => "pong");
'''


def test_a_handler_passed_by_name_is_followed():
    """Two registrations sharing one named handler is not leakage: both tools
    really do run that code."""
    tools = _tools({"index.ts": NAMED_HANDLER})

    assert "filesystem.read" in _caps(tools["read_file"])
    assert "filesystem.read" in _caps(tools["read_text_file"])


def test_an_inline_sibling_does_not_pick_up_the_named_handler():
    tools = _tools({"index.ts": NAMED_HANDLER})

    assert _caps(tools["ping"]) == set()


def test_reading_file_metadata_counts_as_a_filesystem_read():
    source = TS_HEADER + '''
async function getFileStats(p) {
  const stats = await fs.stat(p);
  return stats;
}

server.registerTool("get_file_info", { description: "Info." }, async (args) => {
  return await getFileStats(args.path);
});
'''
    tools = _tools({"index.ts": source})

    assert "filesystem.read" in _caps(tools["get_file_info"])


GUARDED = TS_HEADER + '''
async function validatePath(requested) {
  const real = await fs.realpath(requested);
  if (!real.startsWith(allowedRoot)) throw new Error("denied");
  return real;
}

async function checkAndPurge(p) {
  await fs.rm(p);
  return true;
}

server.registerTool("create_directory", { description: "Create." }, async (args) => {
  const validPath = await validatePath(args.path);
  await fs.mkdir(validPath, { recursive: true });
});

server.registerTool("purge", { description: "Purge." }, async (args) => {
  return await checkAndPurge(args.path);
});
'''


def test_a_path_guard_does_not_hand_the_tool_a_read_capability():
    """`validatePath` calls realpath to enforce an allow-list. That is the
    guard doing its job, not an ability the tool offers its caller."""
    tools = _tools({"index.ts": GUARDED})

    assert "filesystem.write" in _caps(tools["create_directory"])
    assert "filesystem.read" not in _caps(tools["create_directory"])


def test_a_guard_that_actually_mutates_is_still_reported():
    """The exemption only covers read-only effects: a `check...` helper that
    deletes is exactly the case a reviewer must not lose."""
    tools = _tools({"index.ts": GUARDED})

    assert "filesystem.delete" in _caps(tools["purge"])


MULTILINE_REGISTRATION = TS_HEADER + '''
server.registerTool(
  "alpha",
  { description: "Alpha." },
  async (args) => {
    return args.value;
  }
);

server.registerTool(
  "beta",
  { description: "Beta." },
  async (args) => {
    return args.value;
  }
);
'''


def test_an_indented_async_arrow_is_not_read_as_a_call():
    """`async (args) => {` on its own indented line matched the *method*
    pattern as a function literally named `async`. Two registrations then made
    that name ambiguous, and every tool in the file reported an unresolved
    call it does not have."""
    tools = _tools({"index.ts": MULTILINE_REGISTRATION})

    assert tools["alpha"].unresolved_calls == []
    assert tools["beta"].unresolved_calls == []


def test_language_keywords_never_become_unresolved_calls():
    source = TS_HEADER + '''
server.registerTool("k", { description: "K." }, async (args) => {
  switch (args.mode) {
    case "a": break;
  }
  for (const x of args.items) { await Promise.resolve(x); }
  try { return await Promise.all([]); } catch (e) { throw new Error("x"); }
});
'''
    tools = _tools({"index.ts": source})

    assert tools["k"].unresolved_calls == []


GUARD_DEPTH = TS_HEADER + '''
function expandHome(p) { return p.replace("~", home); }
function normalizePath(p) { return expandHome(p.toLowerCase()); }
function resolveAgainstAllowed(p) { return normalizePath(p); }
async function validatePath(requested) {
  const real = await fs.realpath(resolveAgainstAllowed(requested));
  if (!real.startsWith(allowedRoot)) throw new Error("denied");
  return real;
}

server.registerTool("read_it", { description: "Read." }, async (args) => {
  return await fs.readFile(await validatePath(args.path), "utf-8");
});
'''


def test_running_out_of_depth_inside_a_guard_is_not_reported_as_unknown():
    """The walk stops three hops into `validatePath`. Whatever is down there is
    guard internals, whose read-only effects are dropped anyway - reporting it
    told the reviewer to go ask the vendor about nothing."""
    tools = _tools({"index.ts": GUARD_DEPTH})

    assert tools["read_it"].unresolved_calls == []
    assert "filesystem.read" in _caps(tools["read_it"])


EXTERNAL_IMPORT = TS_HEADER + '''
import { minimatch } from "minimatch";

server.registerTool("search", { description: "Search." }, async (args) => {
  return files.filter((f) => minimatch(f, args.pattern));
});
'''

EXTERNAL_SHADOWED = {
    "index.ts": EXTERNAL_IMPORT,
    "vendor/shim.ts": "export function minimatch(a, b) { return fs.readFile(a); }\n",
    "other/shim.ts": "export function minimatch(a, b) { return false; }\n",
}


def test_a_name_imported_from_a_package_is_a_boundary_not_an_unknown():
    """`minimatch` comes from node_modules. Two same-named shims in the tree
    made it 'ambiguous', which read as a gap in the audit rather than as what
    it is: a dependency, out of scope by design."""
    tools = _tools(EXTERNAL_SHADOWED)

    assert tools["search"].unresolved_calls == []
    assert _caps(tools["search"]) == set()


INDENTED_CALL = TS_HEADER + '''
async function runResearch(query, depth) {
  return await fs.readFile(query, "utf-8");
}

server.registerTool("research", { description: "Research." }, async (args) => {
  runResearch(
    args.query,
    args.depth
  ).catch((error) => {
    console.error(error);
  });
  return await runResearch(args.query, 1);
});
'''


def test_an_indented_multi_line_call_is_not_indexed_as_a_definition():
    """`runResearch(\n  arg,\n  {...}\n)` is a call. Indexing it as a second
    definition made the real function ambiguous, and the tool then reported an
    unknown instead of the read it plainly performs."""
    tools = _tools({"index.ts": INDENTED_CALL})

    assert tools["research"].unresolved_calls == []
    assert "filesystem.read" in _caps(tools["research"])
