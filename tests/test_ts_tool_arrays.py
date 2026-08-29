"""A ListTools handler rarely holds its descriptor array inline.

The scanner read `setRequestHandler(ListToolsRequestSchema, () => ({tools: [...]}))`
and nothing else. Real servers bind the array to a const first, or build it in a
factory in another module and return the call. Both were complete misses: the
server is detected, and reports zero tools.
"""

from mcp_auditor.extractor import extract


HEADER = 'import { Tool } from "@modelcontextprotocol/sdk/types.js";\n'

INLINE = HEADER + '''
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    { name: "alpha", description: "A.", inputSchema: { type: "object" } },
    { name: "beta", description: "B.", inputSchema: { type: "object" } },
  ],
}));
'''

CONST_BOUND = HEADER + '''
this.server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools: Tool[] = [
    { name: "alpha", description: "A.", inputSchema: { type: "object" } },
    { name: "beta", description: "B.", inputSchema: { type: "object" } },
  ];
  return { tools };
});
'''

FACTORY = {
    "src/tools.ts": HEADER + '''
export function createToolDefinitions() {
  return [
    { name: "alpha", description: "A.", inputSchema: { type: "object" } },
    { name: "beta", description: "B.", inputSchema: { type: "object" } },
  ];
}
''',
    "src/requestHandler.ts": '''
import { createToolDefinitions } from "./tools";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: createToolDefinitions(),
}));
''',
}


def _names(files):
    return sorted(tool.name for tool in extract(files).tools)


def test_the_inline_array_still_works():
    assert _names({"index.ts": INLINE}) == ["alpha", "beta"]


def test_an_array_bound_to_a_const_is_read():
    assert _names({"index.ts": CONST_BOUND}) == ["alpha", "beta"]


def test_an_array_built_by_a_factory_in_another_module_is_read():
    assert _names(FACTORY) == ["alpha", "beta"]


def test_descriptions_and_schemas_survive_the_indirection():
    tool = next(t for t in extract({"index.ts": CONST_BOUND}).tools if t.name == "alpha")

    assert tool.description == "A."


def test_an_unrelated_array_of_named_objects_is_not_a_tool_list():
    """A server full of named config objects must not turn them into tools."""
    source = HEADER + '''
const routes = [
  { name: "home", path: "/" },
  { name: "about", path: "/about" },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{ name: "alpha", description: "A.", inputSchema: { type: "object" } }],
}));
'''
    assert _names({"index.ts": source}) == ["alpha"]


def test_a_repository_with_no_list_tools_handler_yields_nothing():
    source = HEADER + '''
const tools = [
  { name: "alpha", description: "A.", inputSchema: { type: "object" } },
];
'''
    assert _names({"index.ts": source}) == []
