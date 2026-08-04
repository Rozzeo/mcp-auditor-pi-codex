# Department privilege policies

`mcp-auditor` separates two questions that are often incorrectly collapsed:

1. **What can the MCP implementation apparently do?** Static source evidence.
2. **May this employee and agent do it?** An organization-owned policy decision.

The target is allowed to declare MCP ToolAnnotations, but those annotations are
untrusted hints under the MCP specification. They never grant authorization.

## Identity hierarchy

```text
organization
└── department capability ceiling
    └── employee role
        └── employee-specific narrowing
            └── main/parent agent
                └── helper profile
                    └── agent-specific narrowing
```

Policy resolution has three security invariants:

- every allow layer is an intersection, so a more specific identity can only
  narrow privileges;
- every deny is accumulated and wins over allow;
- a child/helper must belong to the same employee as its parent.

Unknown capabilities, identity references, inheritance cycles, and cross-user
parent relationships make the policy invalid instead of silently falling back.

## Usage

Start from [`examples/department-policy.yaml`](../examples/department-policy.yaml):

```bash
mcp-audit ./my-server \
  --policy examples/department-policy.yaml \
  --agent alice-main

mcp-audit ./my-server \
  --policy examples/department-policy.yaml \
  --agent alice-helper
```

An agent selects its employee automatically. For an employee-level decision
without an agent profile:

```bash
mcp-audit ./my-server \
  --policy examples/department-policy.yaml \
  --employee alice
```

The same identity options work in diff mode, so a release that gains a new
forbidden capability becomes a new `PV-001` finding:

```bash
mcp-audit diff baseline.json ./updated-server \
  --policy examples/department-policy.yaml \
  --agent alice-helper
```

## Capability vocabulary

| Capability | Static observables (examples) |
|---|---|
| `filesystem.read` | `fs.readFile`, `createReadStream`, `Path.read_text` |
| `filesystem.write` | `fs.writeFile`, `appendFile`, `Path.write_text` |
| `filesystem.delete` | `fs.rm`, `unlink`, `rmdir`, `os.remove` |
| `database.read` | database execution call plus static `SELECT` |
| `database.write` | database execution call plus `INSERT`/`UPDATE` |
| `database.raw-query` | execution call whose SQL cannot be resolved statically |
| `database.destructive` | `DELETE`, `DROP`, `TRUNCATE`, `ALTER`, `GRANT` |
| `network.outbound` | `fetch`, Axios, HTTP clients, sockets |
| `process.execute` | child processes, shell execution, `Deno.Command`, `Bun.spawn` |
| `environment.read` | `process.env`, `os.environ`, dotenv loaders |
| `secrets.read` | environment access whose name identifies a token/key/password/secret |

Each capability contains the matched API/source fragment, source location, and
confidence. The complete handler body is not stored in JSON baselines.

## Policy decision and coverage

- `allow`: every observed capability is in the effective allow list.
- `deny`: at least one observed capability is not allowed; every mismatch emits
  a traceable `PV-001` finding linked to MCP-T11 in the Threat Atlas.
- `manual_review`: no violation was proven, but at least one tool definition had
  no statically associable implementation (for example a low-level dynamic
  `tools/call` dispatcher or a JSON manifest).

An `allow` result means "allowed within the observed static capability set," not
"safe under every runtime condition." Reports therefore carry coverage and
limitations alongside the decision.

## Scientific traceability

The policy layer does not replace the Threat Atlas. `CP-001` through `CP-003`
test the MCP specification's annotation claims against source observables;
`PV-001` maps inferred over-privilege to MCP-T11 and its cited research. The
method remains deterministic and reproducible under a recorded signature
version, policy version, evidence location, and confidence.

Future calibration should report precision/recall separately for each
capability and language/runtime shape. Dynamic imports, wrapper functions, and
runtime-generated handlers are explicit current limitations, not silently
treated as clean.
