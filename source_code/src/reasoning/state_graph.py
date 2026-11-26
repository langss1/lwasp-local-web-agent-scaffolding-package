"""State graph + backtracking. New contribution described in plan.md 4.4.

Each pentest condition becomes a node. When a branch goes cold (too many
consecutive failures), the agent can jump back to the most promising
unexplored node instead of grinding the same dead branch.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any


@dataclass
class StateGraphNode:
    node_id: str
    parent_id: str | None
    depth: int
    state: dict[str, Any]
    action_taken: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    children: list[str] = field(default_factory=list)
    status: str = "unexplored"   # unexplored | exploring | explored | dead
    score: float = 0.5
    consecutive_fails: int = 0


class StateGraph:
    def __init__(self, max_depth: int = 6, max_branching: int = 3, fail_threshold: int = 3):
        self.max_depth = max_depth
        self.max_branching = max_branching
        self.fail_threshold = fail_threshold
        self.nodes: dict[str, StateGraphNode] = {}
        self._id_counter = itertools.count(0)
        self.root_id: str | None = None
        self.current_id: str | None = None

    def _new_id(self) -> str:
        return f"n{next(self._id_counter)}"

    def add_root(self, state: dict[str, Any]) -> StateGraphNode:
        node = StateGraphNode(node_id=self._new_id(), parent_id=None, depth=0, state=state,
                               status="exploring")
        self.nodes[node.node_id] = node
        self.root_id = node.node_id
        self.current_id = node.node_id
        return node

    def add_node(self, parent_id: str, action: dict[str, Any],
                 state: dict[str, Any] | None = None) -> StateGraphNode | None:
        """Add a child node under parent_id. Returns None (and does not add a
        node) if that would violate max_depth or max_branching -- the caller
        should treat that as "this branch cannot go further".
        """
        parent = self.nodes[parent_id]
        if parent.depth + 1 > self.max_depth:
            return None
        if len(parent.children) >= self.max_branching:
            return None
        merged_state = dict(parent.state)
        if state:
            merged_state.update(state)
        node = StateGraphNode(
            node_id=self._new_id(),
            parent_id=parent_id,
            depth=parent.depth + 1,
            state=merged_state,
            action_taken=action,
            status="exploring",
        )
        self.nodes[node.node_id] = node
        parent.children.append(node.node_id)
        self.current_id = node.node_id
        return node

    def update_node(self, node_id: str, result: dict[str, Any]) -> None:
        node = self.nodes[node_id]
        node.result = result
        node.status = "explored"
        success = bool(result.get("success"))
        node.score = float(result.get("score", 0.0 if not success else 1.0))
        if success:
            node.consecutive_fails = 0
        else:
            parent_fails = self.nodes[node.parent_id].consecutive_fails if node.parent_id else 0
            node.consecutive_fails = parent_fails + 1

    def branch_dead(self, node_id: str) -> bool:
        node = self.nodes[node_id]
        if node.consecutive_fails >= self.fail_threshold:
            return True
        if node.depth >= self.max_depth and not self._unexplored_descendants(node_id):
            return True
        return False

    def _unexplored_descendants(self, node_id: str) -> list[str]:
        return [cid for cid in self.nodes[node_id].children
                if self.nodes[cid].status == "unexplored"]

    def unexplored_nodes(self) -> list[StateGraphNode]:
        return [n for n in self.nodes.values() if n.status in ("unexplored", "explored")
                and len(n.children) < self.max_branching and n.depth < self.max_depth
                and n.consecutive_fails < self.fail_threshold]

    def backtrack(self, from_node_id: str) -> StateGraphNode | None:
        """Return the highest-scoring node (ancestor or sibling subtree) that
        still has room to explore, marking it current. Returns None if no
        viable node remains anywhere in the graph.
        """
        candidates = self.unexplored_nodes()
        candidates = [n for n in candidates if n.node_id != from_node_id]
        if not candidates:
            return None
        best = max(candidates, key=lambda n: (n.score, -n.depth))
        self.current_id = best.node_id
        return best

    def backtrack_if_needed(self, node_id: str) -> str:
        if self.branch_dead(node_id):
            target = self.backtrack(node_id)
            if target is not None:
                return target.node_id
        return node_id

    # -- explicit time-jump (agent-driven) ---------------------------------

    def jumpable_nodes(self, exclude_id: str | None = None) -> list[StateGraphNode]:
        """Nodes the agent may jump to right now: any visited state (including
        the root) that still has room for another branch and is not a dead end.
        This generalises backtracking -- the agent is not limited to ancestors
        of the current node, it can return to any promising past state.

        Defined independently of unexplored_nodes() so it can include the root
        and other "exploring" nodes, which jump_to() accepts as valid targets
        but unexplored_nodes() (used by backtrack) deliberately excludes.
        """
        out = []
        for n in self.nodes.values():
            if n.node_id == exclude_id:
                continue
            if (n.status == "dead"
                    or n.consecutive_fails >= self.fail_threshold
                    or len(n.children) >= self.max_branching
                    or n.depth >= self.max_depth):
                continue
            out.append(n)
        return out

    def jump_to(self, node_id: str) -> StateGraphNode | None:
        """Move the current pointer to `node_id` so the next attempt branches
        from there. Returns the node, or None if it does not exist or is not a
        viable jump target (dead, full, or at max depth).
        """
        node = self.nodes.get(node_id)
        if node is None:
            return None
        if (node.status == "dead"
                or node.consecutive_fails >= self.fail_threshold
                or len(node.children) >= self.max_branching
                or node.depth >= self.max_depth):
            return None
        node.status = "exploring"   # re-open a previously explored state
        self.current_id = node_id
        return node

    def summary(self, max_nodes: int = 20) -> str:
        """Short textual summary of the graph for prompt context. Nodes marked
        [jumpable] can be reached with a JUMP_STATE action to try a new branch
        from that earlier state.
        """
        jumpable = {n.node_id for n in self.jumpable_nodes(exclude_id=self.current_id)}
        lines = []
        for node in list(self.nodes.values())[-max_nodes:]:
            outcome = "?" if node.result is None else ("OK" if node.result.get("success") else "FAIL")
            mark = " [jumpable]" if node.node_id in jumpable else ""
            here = " <- current" if node.node_id == self.current_id else ""
            lines.append(
                f"- {node.node_id} (depth={node.depth}, status={node.status}, "
                f"score={node.score:.2f}, outcome={outcome}): "
                f"{node.action_taken.get('type') if node.action_taken else 'ROOT'}{mark}{here}"
            )
        return "\n".join(lines) if lines else "(graph empty)"
