"""P1: registration shapes the extractor has to recognize, and the ones it must
report as gaps instead of guessing at.

The sources here mirror the reference servers at the pinned benchmark commit:
the `everything` server binds a tool's name and config to module-level consts,
and the Python servers declare tools in a low-level `list_tools()` return value.
"""

from mcp_auditor.extractor import extract


TS_VARIABLE_REGISTRATION = '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export const EchoSchema = z.object({
  message: z.string().describe("Message to echo"),
});

const name = "echo";
const config = {
  title: "Echo Tool",
  description: "Echoes back the input string",
  inputSchema: EchoSchema,
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
  },
};

export const registerEchoTool = (server: McpServer) => {
  server.registerTool(name, config, async (args) => {
    return { content: [{ type: "text", text: `Echo: ${args.message}` }] };
  });
};
'''

TS_TWO_VARIABLE_TOOLS = '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const readerName = "read_report";
const readerConfig = { description: "Read the report." };
const writerName = "write_report";
const writerConfig = { description: "Write the report." };

export const registerReader = (server: McpServer) => {
  server.registerTool(readerName, readerConfig, async (args) => {
    return await fs.readFile(args.path, "utf-8");
  });
};

export const registerWriter = (server: McpServer) => {
  server.registerTool(writerName, writerConfig, async (args) => {
    await fs.writeFile(args.path, args.body);
  });
};
'''

TS_TASK_REGISTRATION = '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const registerResearch = (server: McpServer) => {
  server.experimental.tasks.registerToolTask(
    "simulate-research-query",
    {
      description: "Run a simulated research query.",
      inputSchema: { query: z.string() },
    },
    async (args) => ({ content: [] })
  );
};
'''

TS_UNRESOLVABLE_NAME = '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { toolName, toolConfig } from "./generated/registry.js";

export const registerGenerated = (server: McpServer) => {
  server.registerTool(toolName, toolConfig, async () => ({ content: [] }));
};
'''


def _tools(source: str, path: str = "index.ts"):
    return {tool.name: tool for tool in extract({path: source}).tools}


def test_a_tool_registered_through_const_bindings_is_extracted():
    tool = _tools(TS_VARIABLE_REGISTRATION)["echo"]

    assert tool.description == "Echoes back the input string"
    assert tool.annotations == {"readOnlyHint": True, "destructiveHint": False}


def test_an_input_schema_bound_to_a_zod_const_resolves_to_its_parameters():
    tool = _tools(TS_VARIABLE_REGISTRATION)["echo"]

    assert tool.schema["properties"] == {"message": {}}


def test_each_variable_registration_keeps_its_own_handler_body():
    tools = _tools(TS_TWO_VARIABLE_TOOLS)

    assert "readFile" in tools["read_report"].body
    assert "writeFile" not in tools["read_report"].body
    assert "writeFile" in tools["write_report"].body
    assert "readFile" not in tools["write_report"].body


def test_registration_line_points_at_the_call_not_the_const():
    tool = _tools(TS_VARIABLE_REGISTRATION)["echo"]
    line = int(tool.location.rsplit(":", 1)[1])

    assert TS_VARIABLE_REGISTRATION.splitlines()[line - 1].strip().startswith(
        "server.registerTool(name, config,"
    )


def test_the_experimental_task_registration_api_is_extracted():
    tool = _tools(TS_TASK_REGISTRATION)["simulate-research-query"]

    assert tool.description == "Run a simulated research query."
    assert tool.schema["properties"] == {"query": {}}


def test_an_unresolvable_registration_is_reported_not_invented():
    result = extract({"index.ts": TS_UNRESOLVABLE_NAME})

    assert result.tools == []
    assert len(result.coverage_gaps) == 1
    gap = result.coverage_gaps[0]
    assert gap.location.startswith("index.ts:")
    assert "toolName" in gap.reason


PY_LOW_LEVEL = '''
from mcp.server import Server
from mcp.types import Tool

server = Server("fetch")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="fetch",
            description="Fetch a URL and return its contents.",
            inputSchema={"type": "object", "properties": {"url": {"type": "string"}}},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list:
    return await do_fetch(arguments["url"])
'''

PY_LOW_LEVEL_ENUM = '''
from enum import Enum

from mcp.server import Server
from mcp.types import Tool


class GitTools(str, Enum):
    STATUS = "git_status"
    COMMIT = "git_commit"


class TimeTools(str, Enum):
    GET_CURRENT_TIME = "get_current_time"


server = Server("git")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(name=GitTools.STATUS, description="Show status.", inputSchema=GitStatus.model_json_schema()),
        Tool(name=GitTools.COMMIT, description="Record changes.", inputSchema={}),
        Tool(name=TimeTools.GET_CURRENT_TIME.value, description="Current time.", inputSchema={}),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list:
    repo.index.commit(arguments["message"])
    return []
'''

PY_LOW_LEVEL_UNRESOLVABLE = '''
from mcp.server import Server
from mcp.types import Tool

server = Server("generated")

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(name=registry.entry, description="", inputSchema={})]
'''


def test_a_low_level_list_tools_declaration_is_extracted():
    tool = _tools(PY_LOW_LEVEL, path="server.py")["fetch"]

    assert tool.description == "Fetch a URL and return its contents."
    assert tool.schema["properties"] == {"url": {"type": "string"}}


def test_a_low_level_tool_name_resolves_through_a_str_enum_member():
    tools = _tools(PY_LOW_LEVEL_ENUM, path="server.py")

    assert set(tools) == {"git_status", "git_commit", "get_current_time"}


def test_a_low_level_tool_carries_no_dispatch_body():
    """call_tool holds every tool's sinks. Attributing it would make each tool
    inherit all of them, which is exactly the leakage P1 must not introduce."""
    tools = _tools(PY_LOW_LEVEL_ENUM, path="server.py")

    assert all(tool.body == "" for tool in tools.values())


def test_a_low_level_declaration_points_at_its_own_line():
    tools = _tools(PY_LOW_LEVEL_ENUM, path="server.py")
    lines = PY_LOW_LEVEL_ENUM.splitlines()

    for name, marker in (("git_status", "GitTools.STATUS"), ("git_commit", "GitTools.COMMIT")):
        line = int(tools[name].location.rsplit(":", 1)[1])
        assert marker in lines[line - 1]


def test_an_unresolvable_low_level_name_is_reported_not_invented():
    result = extract({"server.py": PY_LOW_LEVEL_UNRESOLVABLE})

    assert result.tools == []
    assert len(result.coverage_gaps) == 1
    assert "registry.entry" in result.coverage_gaps[0].reason


def test_the_fastmcp_decorator_shape_still_works_alongside_the_low_level_one():
    source = PY_LOW_LEVEL + '''

@server.tool()
def extra(city: str) -> str:
    """A decorated tool in the same file."""
    return "sunny"
'''
    tools = _tools(source, path="server.py")

    assert set(tools) == {"fetch", "extra"}
    assert tools["extra"].body != ""


PY_DISPATCH_MATCH = '''
from enum import Enum
from mcp.server import Server
from mcp.types import Tool


class Tools(str, Enum):
    READ = "read_note"
    PURGE = "purge_notes"


server = Server("notes")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(name=Tools.READ, description="Read.", inputSchema={}),
        Tool(name=Tools.PURGE, description="Purge.", inputSchema={}),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list:
    root = validate_root(arguments["root"])
    match name:
        case Tools.READ:
            return open(root).read()
        case Tools.PURGE:
            return os.remove(root)
'''

PY_DISPATCH_IF = PY_DISPATCH_MATCH.replace('''    match name:
        case Tools.READ:
            return open(root).read()
        case Tools.PURGE:
            return os.remove(root)''', '''    if name == Tools.READ:
        return open(root).read()
    elif name == "purge_notes":
        return os.remove(root)''')

PY_SINGLE_TOOL = '''
from mcp.server import Server
from mcp.types import Tool

server = Server("fetch")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(name="fetch", description="Fetch.", inputSchema={})]


@server.call_tool()
async def call_tool(name, arguments: dict) -> list:
    async with AsyncClient() as client:
        response = await client.get(arguments["url"])
    return response.text
'''


def _with_caps(source: str):
    from mcp_auditor.capabilities import infer_all
    files = {"server.py": source}
    result = extract(files)
    infer_all(result.tools, files=files)
    return {t.name: {e.capability for e in t.capabilities} for t in result.tools}


def test_a_match_dispatch_branch_is_attributed_to_its_own_tool():
    caps = _with_caps(PY_DISPATCH_MATCH)

    assert "filesystem.delete" in caps["purge_notes"]
    assert "filesystem.delete" not in caps["read_note"]


def test_an_if_elif_dispatch_branch_is_attributed_to_its_own_tool():
    caps = _with_caps(PY_DISPATCH_IF)

    assert "filesystem.delete" in caps["purge_notes"]
    assert "filesystem.delete" not in caps["read_note"]


def test_a_single_tool_server_owns_its_whole_dispatcher():
    """With one declared tool there is nothing to confuse it with."""
    caps = _with_caps(PY_SINGLE_TOOL)

    assert "network.outbound" in caps["fetch"]


def test_an_http_client_call_is_outbound_network():
    from mcp_auditor.capabilities import infer_all
    from mcp_auditor.types import Tool as T

    tool = T(name="t", description="", location="server.py:1",
             body="async with AsyncClient(proxy=p) as client:\n    r = await client.get(url)\n")
    infer_all([tool])

    assert {e.capability for e in tool.capabilities} == {"network.outbound"}


def test_a_gitpython_mutation_is_a_filesystem_write():
    from mcp_auditor.capabilities import infer_all
    from mcp_auditor.types import Tool as T

    tool = T(name="t", description="", location="server.py:1",
             body="commit = repo.index.commit(message)\n")
    infer_all([tool])

    assert "filesystem.write" in {e.capability for e in tool.capabilities}


def test_reading_git_history_is_not_a_write():
    from mcp_auditor.capabilities import infer_all
    from mcp_auditor.types import Tool as T

    tool = T(name="t", description="", location="server.py:1",
             body="return list(repo.iter_commits(max_count=10))\n")
    infer_all([tool])

    assert "filesystem.write" not in {e.capability for e in tool.capabilities}
