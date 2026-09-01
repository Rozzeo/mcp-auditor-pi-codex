"""Auditor-side hierarchical privilege policies.

Policies are explicit inputs, never discovered inside an audited target.  The
hierarchy is intentionally narrowing-only:

    department ceiling -> employee role -> employee override -> parent agent
    -> agent profile -> agent override

Every allow layer intersects the previous layer; every deny is accumulated and
wins.  A helper therefore cannot silently gain a capability unavailable to its
parent/main agent or employee.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .capabilities import CAPABILITIES
from .types import Finding, Tool


class PolicyError(ValueError):
    """Raised for malformed or unresolved privilege policies."""


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be a mapping")
    return value


def _capability_set(value: Any, label: str, *, required: bool = False) -> set[str] | None:
    if value is None and not required:
        return None
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"{label} must be a list of capability strings")
    result = set(CAPABILITIES) if "*" in value else set(value)
    unknown = result - CAPABILITIES
    if unknown:
        raise PolicyError(f"{label} contains unknown capabilities: {', '.join(sorted(unknown))}")
    return result


def load_policy(path: str | Path) -> dict[str, Any]:
    """Load and structurally validate an auditor-supplied YAML policy."""
    target = Path(path)
    if not target.exists():
        raise PolicyError(f"Privilege policy not found: {target}")
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"Privilege policy is not valid YAML: {exc}") from exc
    root = _mapping(data, "privilege policy")
    if root.get("version") != 1:
        raise PolicyError("privilege policy version must be 1")

    departments = _mapping(root.get("departments"), "departments")
    employees = _mapping(root.get("employees"), "employees")
    agents = _mapping(root.get("agents", {}), "agents")
    if not departments:
        raise PolicyError("departments must contain at least one department")

    for dept_name, raw_dept in departments.items():
        dept = _mapping(raw_dept, f"departments.{dept_name}")
        ceiling = _mapping(dept.get("capability_ceiling"), f"departments.{dept_name}.capability_ceiling")
        _capability_set(ceiling.get("allow"), f"departments.{dept_name}.capability_ceiling.allow", required=True)
        _capability_set(ceiling.get("deny", []), f"departments.{dept_name}.capability_ceiling.deny", required=True)
        roles = _mapping(dept.get("roles"), f"departments.{dept_name}.roles")
        if not roles:
            raise PolicyError(f"departments.{dept_name}.roles must not be empty")
        for role_name, raw_role in roles.items():
            role = _mapping(raw_role, f"departments.{dept_name}.roles.{role_name}")
            _capability_set(role.get("allow"), f"departments.{dept_name}.roles.{role_name}.allow", required=True)
            _capability_set(role.get("deny", []), f"departments.{dept_name}.roles.{role_name}.deny", required=True)

    for employee_name, raw_employee in employees.items():
        employee = _mapping(raw_employee, f"employees.{employee_name}")
        department_name = employee.get("department")
        role_name = employee.get("role")
        if department_name not in departments:
            raise PolicyError(f"employees.{employee_name} references unknown department {department_name!r}")
        roles = departments[department_name].get("roles", {})
        if role_name not in roles:
            raise PolicyError(f"employees.{employee_name} references unknown role {role_name!r}")
        _capability_set(employee.get("allow"), f"employees.{employee_name}.allow")
        _capability_set(employee.get("deny", []), f"employees.{employee_name}.deny", required=True)

    for agent_name, raw_agent in agents.items():
        agent = _mapping(raw_agent, f"agents.{agent_name}")
        employee_name = agent.get("employee")
        if employee_name not in employees:
            raise PolicyError(f"agents.{agent_name} references unknown employee {employee_name!r}")
        profile = agent.get("profile")
        if profile is not None:
            employee = employees[employee_name]
            roles = departments[employee["department"]]["roles"]
            if profile not in roles:
                raise PolicyError(f"agents.{agent_name} references unknown profile {profile!r}")
        parent = agent.get("parent")
        if parent is not None and parent not in agents:
            raise PolicyError(f"agents.{agent_name} references unknown parent {parent!r}")
        _capability_set(agent.get("allow"), f"agents.{agent_name}.allow")
        _capability_set(agent.get("deny", []), f"agents.{agent_name}.deny", required=True)

    # Resolve every agent once to catch cycles and cross-employee inheritance.
    for agent_name in agents:
        resolve_policy(root, agent=agent_name)
    return root


@dataclass(frozen=True)
class ResolvedPolicy:
    department: str
    employee: str
    role: str
    agent: str | None
    effective_allow: frozenset[str]
    denied: frozenset[str]
    layers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "department": self.department,
            "employee": self.employee,
            "role": self.role,
            "agent": self.agent,
            "effective_allow": sorted(self.effective_allow),
            "denied": sorted(self.denied),
            "layers": list(self.layers),
        }


def resolve_policy(
    policy: dict[str, Any],
    *,
    employee: str | None = None,
    agent: str | None = None,
    _stack: tuple[str, ...] = (),
) -> ResolvedPolicy:
    """Resolve the narrowing-only effective privilege set for one identity."""
    employees = policy.get("employees", {})
    agents = policy.get("agents", {})
    agent_record: dict[str, Any] | None = None
    if agent is not None:
        if agent in _stack:
            raise PolicyError(f"agent inheritance cycle: {' -> '.join((*_stack, agent))}")
        agent_record = agents.get(agent)
        if not isinstance(agent_record, dict):
            raise PolicyError(f"unknown agent {agent!r}")
        agent_employee = agent_record.get("employee")
        if employee is not None and employee != agent_employee:
            raise PolicyError(f"agent {agent!r} belongs to {agent_employee!r}, not {employee!r}")
        employee = agent_employee
    if employee is None:
        raise PolicyError("a privilege policy requires --employee or --agent")
    employee_record = employees.get(employee)
    if not isinstance(employee_record, dict):
        raise PolicyError(f"unknown employee {employee!r}")

    department_name = employee_record["department"]
    role_name = employee_record["role"]
    department = policy["departments"][department_name]
    ceiling = department["capability_ceiling"]
    role = department["roles"][role_name]

    allowed = _capability_set(ceiling.get("allow"), "capability_ceiling.allow", required=True) or set()
    denied = _capability_set(ceiling.get("deny", []), "capability_ceiling.deny", required=True) or set()
    layers = [f"department:{department_name}", f"role:{role_name}"]

    role_allow = _capability_set(role.get("allow"), f"role:{role_name}.allow", required=True) or set()
    allowed &= role_allow
    denied |= _capability_set(role.get("deny", []), f"role:{role_name}.deny", required=True) or set()

    employee_allow = _capability_set(employee_record.get("allow"), f"employee:{employee}.allow")
    if employee_allow is not None:
        allowed &= employee_allow
    denied |= _capability_set(employee_record.get("deny", []), f"employee:{employee}.deny", required=True) or set()
    layers.append(f"employee:{employee}")

    if agent_record is not None:
        parent_name = agent_record.get("parent")
        if parent_name:
            parent_record = agents[parent_name]
            if parent_record.get("employee") != employee:
                raise PolicyError(f"agent {agent!r} cannot inherit from another employee's agent")
            parent = resolve_policy(
                policy,
                employee=employee,
                agent=parent_name,
                _stack=(*_stack, agent),
            )
            allowed &= set(parent.effective_allow)
            denied |= set(parent.denied)
            layers.append(f"parent:{parent_name}")

        profile_name = agent_record.get("profile")
        if profile_name:
            profile = department["roles"][profile_name]
            profile_allow = _capability_set(
                profile.get("allow"), f"profile:{profile_name}.allow", required=True
            ) or set()
            allowed &= profile_allow
            denied |= _capability_set(
                profile.get("deny", []), f"profile:{profile_name}.deny", required=True
            ) or set()
            layers.append(f"profile:{profile_name}")

        agent_allow = _capability_set(agent_record.get("allow"), f"agent:{agent}.allow")
        if agent_allow is not None:
            allowed &= agent_allow
        denied |= _capability_set(
            agent_record.get("deny", []), f"agent:{agent}.deny", required=True
        ) or set()
        layers.append(f"agent:{agent}")

    allowed -= denied
    return ResolvedPolicy(
        department=department_name,
        employee=employee,
        role=role_name,
        agent=agent,
        effective_allow=frozenset(allowed),
        denied=frozenset(denied),
        layers=tuple(layers),
    )


def evaluate_policy(
    tools: list[Tool],
    resolved: ResolvedPolicy,
    rule: dict[str, Any],
) -> tuple[list[Finding], dict[str, Any]]:
    """Turn capability/policy mismatches into normal traceable findings."""
    findings: list[Finding] = []
    requested: set[str] = set()
    implementation_available = 0
    for tool in tools:
        if tool.body:
            implementation_available += 1
        for evidence in tool.capabilities:
            capability = evidence.capability
            requested.add(capability)
            if capability in resolved.effective_allow:
                continue
            findings.append(
                Finding(
                    id="PV-001",
                    category=rule["category"],
                    severity=rule["severity"],
                    tool_name=tool.name,
                    location=evidence.location or tool.location,
                    message=rule["message"],
                    evidence=(
                        f"{capability} via {evidence.evidence}; not allowed by "
                        f"{resolved.department}/{resolved.employee}/{resolved.agent or resolved.role}"
                    ),
                    recommendation=rule["recommendation"],
                    threat_id=rule.get("threat"),
                    confidence=rule.get("confidence"),
                )
            )

    unclassified = sorted(tool.name for tool in tools if not tool.body)
    decision = "deny" if findings else ("manual_review" if unclassified else "allow")
    report = resolved.to_dict()
    report.update(
        {
            "decision": decision,
            "requested": sorted(requested),
            "violations": len(findings),
            "coverage": {
                "method": "syntax-aware static source analysis",
                "implementation_available": implementation_available,
                "tools_total": len(tools),
                "unclassified_tools": unclassified,
                "limitations": [
                    "dynamic imports and runtime-generated handlers may be missed",
                    "wrapper functions require interprocedural analysis",
                    "MCP ToolAnnotations are untrusted hints, not authorization",
                ],
            },
        }
    )
    return findings, report
