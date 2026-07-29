"""Grammar-based symbol anchoring, the parser counterpart to the text baseline.

``static_analysis.hunk_to_symbol`` answers "which symbol encloses this changed
line?" with a stack of regexes. That is the always-available arm of the
static-analysis ablation, and it is wrong often enough to matter: it cannot see
a receiver, it mistakes a call three lines below a ``func`` header for the
function itself, and it silently returns ``<file>`` whenever the enclosing
construct does not match one of its patterns.

This module answers the same question from a real parse tree. The adjudicator
already learned, the hard way, that structural facts must come from a source of
truth rather than from an approximation of one -- the whole ``cite`` tool exists
because the model re-deriving line numbers from hunk headers was "the single
largest source of lost findings." Symbol anchoring is the same problem one axis
over, and tree-sitter is the same kind of fix.

The public surface mirrors ``static_analysis`` so the two are directly
swappable in the ablation harness:

    enclosing_symbol(source, line, path) -> SymbolAnchor | None
    enumerate_symbols(source, path)      -> list[SymbolSpan]
    is_cosmetic_change(before, after, path) -> bool | None

Every entry point returns ``None`` (never a wrong answer) when the language is
unsupported or the parser is unavailable, so a caller can fall back to the text
baseline without a try/except.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from .static_analysis import SymbolAnchor

__all__ = [
    "SUPPORTED_LANGUAGES",
    "SymbolSpan",
    "available",
    "enclosing_symbol",
    "enumerate_symbols",
    "is_cosmetic_change",
    "language_for_path",
]

#: Extension -> tree-sitter grammar name. Kept deliberately close to
#: ``language._EXTENSIONS`` so the pilot covers the same languages the
#: adjudicator already ships prompt appendices for.
_EXTENSIONS: dict[str, str] = {
    ".go": "go",
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
}

SUPPORTED_LANGUAGES = frozenset({"go", "python", "javascript", "typescript", "tsx"})

#: Node types that define a *named* callable, per grammar. The enclosing one of
#: these is what a changed line is "in".
_FUNCTION_NODES: dict[str, frozenset[str]] = {
    "go": frozenset({"function_declaration", "method_declaration"}),
    "python": frozenset({"function_definition"}),
    "javascript": frozenset(
        {"function_declaration", "method_definition", "generator_function_declaration"}
    ),
    "typescript": frozenset(
        {"function_declaration", "method_definition", "generator_function_declaration"}
    ),
    "tsx": frozenset(
        {"function_declaration", "method_definition", "generator_function_declaration"}
    ),
}

#: Node types that define a *type* / *class* -- the fallback anchor for a line
#: that lives in a type body but not inside any method.
_TYPE_NODES: dict[str, frozenset[str]] = {
    "go": frozenset({"type_declaration", "type_spec"}),
    "python": frozenset({"class_definition"}),
    "javascript": frozenset({"class_declaration"}),
    "typescript": frozenset({"class_declaration", "interface_declaration"}),
    "tsx": frozenset({"class_declaration", "interface_declaration"}),
}

#: Classes contribute a dotted prefix to a method's qualified name (Python/JS).
_CLASS_NODES: dict[str, frozenset[str]] = {
    "python": frozenset({"class_definition"}),
    "javascript": frozenset({"class_declaration"}),
    "typescript": frozenset({"class_declaration"}),
    "tsx": frozenset({"class_declaration"}),
}


def language_for_path(path: str) -> str | None:
    """The tree-sitter grammar name for a path's extension, or ``None``."""
    return _EXTENSIONS.get(Path(path.lower()).suffix)


@cache
def _parser(language: str) -> Any | None:
    """A cached tree-sitter parser, or ``None`` if the pack cannot supply one."""
    try:
        from tree_sitter_language_pack import get_parser
    except ImportError:
        return None
    try:
        return get_parser(language)  # type: ignore[arg-type]
    except LookupError, OSError, ValueError:
        return None


def available(path: str | None = None) -> bool:
    """Whether tree-sitter can parse ``path`` (or anything, if ``path`` is None)."""
    if path is None:
        return _parser("python") is not None
    language = language_for_path(path)
    return language is not None and _parser(language) is not None


@dataclass(frozen=True, slots=True)
class SymbolSpan:
    """A named definition and the inclusive 1-based line range it occupies."""

    name: str
    kind: str  # "function" | "method" | "type"
    start_line: int
    end_line: int
    receiver: str = ""

    def contains(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line


def _node_name(node: Any) -> str:
    field = node.child_by_field_name("name")
    return field.text.decode("utf-8", "replace") if field is not None else ""


def _go_receiver_type(node: Any) -> str:
    """Extract ``*Server`` / ``Server`` from a Go method's receiver node.

    A method's identity is the pair (receiver type, name): ``(*Buffer).Write``
    and ``(*Reader).Write`` are different functions that the text baseline both
    reports as ``Write``. Recovering the receiver is the single clearest
    correctness win tree-sitter has over the regex on Go.
    """
    receiver = node.child_by_field_name("receiver")
    if receiver is None:
        return ""
    pointer = False
    type_name = ""
    stack = [receiver]
    while stack:
        current = stack.pop()
        if current.type == "pointer_type":
            pointer = True
        if current.type == "type_identifier" and not type_name:
            type_name = current.text.decode("utf-8", "replace")
        stack.extend(reversed(current.children))
    if not type_name:
        return ""
    return f"*{type_name}" if pointer else type_name


def _qualified_name(node: Any, language: str, source_bytes: bytes) -> tuple[str, str, str]:
    """Return ``(qualified_name, kind, receiver)`` for a definition node."""
    name = _node_name(node)
    if language == "go" and node.type == "method_declaration":
        receiver = _go_receiver_type(node)
        qualified = f"({receiver}).{name}" if receiver.startswith("*") else f"{receiver}.{name}"
        return (qualified if receiver else name), "method", receiver
    if node.type in _FUNCTION_NODES.get(language, frozenset()):
        # Prefix enclosing class names (Python/JS methods) so ``A.Inner.deep``
        # is distinguishable from a module-level ``deep``.
        prefix = _class_prefix(node, language)
        kind = "method" if prefix else "function"
        return (f"{prefix}.{name}" if prefix else name), kind, ""
    # A type/class: qualify with any enclosing class(es) too, so a nested
    # ``Inner`` reads as ``A.Inner`` and matches the way its methods are named.
    prefix = _class_prefix(node, language)
    return (f"{prefix}.{name}" if prefix else name), "type", ""


def _class_prefix(node: Any, language: str) -> str:
    classes = _CLASS_NODES.get(language, frozenset())
    if not classes:
        return ""
    names: list[str] = []
    parent = node.parent
    while parent is not None:
        if parent.type in classes:
            class_name = _node_name(parent)
            if class_name:
                names.append(class_name)
        parent = parent.parent
    return ".".join(reversed(names))


def _iter_definitions(root: Any, language: str) -> Iterator[Any]:
    functions = _FUNCTION_NODES.get(language, frozenset())
    types = _TYPE_NODES.get(language, frozenset())
    wanted = functions | types
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in wanted:
            yield node
        stack.extend(reversed(node.children))


def enumerate_symbols(source: str, path: str) -> list[SymbolSpan] | None:
    """Every named definition in ``source`` with its line span, or ``None``.

    This is the ground-truth generator for the accuracy harness: the structural
    fact "definition D spans lines a..b" is exactly what a grammar exists to
    compute, so it is treated as truth and spot-checked, not re-derived.
    """
    language = language_for_path(path)
    if language is None:
        return None
    parser = _parser(language)
    if parser is None:
        return None
    source_bytes = source.encode("utf-8")
    tree = parser.parse(source_bytes)
    spans: list[SymbolSpan] = []
    for node in _iter_definitions(tree.root_node, language):
        # A Go ``type_declaration`` wraps one or more ``type_spec`` children;
        # the name lives on the spec, so skip the wrapper to avoid a nameless
        # duplicate span.
        if language == "go" and node.type == "type_declaration":
            continue
        name, kind, receiver = _qualified_name(node, language, source_bytes)
        if not name:
            continue
        spans.append(
            SymbolSpan(
                name=name,
                kind=kind,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                receiver=receiver,
            )
        )
    return spans


#: Line-comment / block-comment openers per grammar family, for attaching a
#: doc comment to the definition it precedes.
_COMMENT_PREFIXES: dict[str, tuple[str, ...]] = {
    "go": ("//", "/*", "*"),
    "javascript": ("//", "/*", "*"),
    "typescript": ("//", "/*", "*"),
    "tsx": ("//", "/*", "*"),
    "python": ("#",),
}


def _attach_leading_comment(
    source: str,
    target: int,
    def_starts: dict[int, Any],
    language: str,
) -> Any | None:
    """The definition a contiguous comment run at ``target`` documents, if any.

    Returns the node whose start line follows an unbroken run of comment lines
    beginning at ``target``. A blank line breaks the run (matching Go's doc rule
    and ordinary reading), so a comment separated from the next definition is
    left unattached.
    """
    prefixes = _COMMENT_PREFIXES.get(language)
    if not prefixes:
        return None
    lines = source.splitlines()
    if not (1 <= target <= len(lines)):
        return None
    if not lines[target - 1].strip().startswith(prefixes):
        return None
    cursor = target
    while cursor <= len(lines) and lines[cursor - 1].strip().startswith(prefixes):
        cursor += 1
    return def_starts.get(cursor)


def enclosing_symbol(source: str, line: int, *, path: str) -> SymbolAnchor | None:
    """The innermost named symbol that encloses ``line``, or ``None``.

    Mirrors ``static_analysis.hunk_to_symbol`` so a caller can swap arms. A
    function/method always wins over a type it is nested in; the deepest such
    definition wins over its ancestors. Returns a ``<file>`` anchor only when
    the parse genuinely finds no enclosing definition -- never as a giving-up
    fallback the way the regex does.
    """
    language = language_for_path(path)
    if language is None:
        return None
    parser = _parser(language)
    if parser is None:
        return None
    source_bytes = source.encode("utf-8")
    tree = parser.parse(source_bytes)
    functions = _FUNCTION_NODES.get(language, frozenset())
    types = _TYPE_NODES.get(language, frozenset())

    total_lines = source.count("\n") + 1
    target = min(max(1, int(line)), total_lines)

    best_function: Any | None = None
    best_type: Any | None = None
    def_starts: dict[int, Any] = {}
    for node in _iter_definitions(tree.root_node, language):
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        if node.type != "type_declaration":
            def_starts.setdefault(start, node)
        if not (start <= target <= end):
            continue
        if node.type in functions:
            # Deeper (later-starting) function wins: it is the innermost.
            if best_function is None or start >= best_function.start_point[0] + 1:
                best_function = node
        elif (
            node.type in types
            and node.type != "type_declaration"
            and (best_type is None or start >= best_type.start_point[0] + 1)
        ):
            best_type = node

    chosen = best_function or best_type
    if chosen is None:
        # A doc comment sits just above the symbol it documents, outside its
        # node span. Go/Python convention attaches it to the definition below,
        # so a changed doc line belongs to that symbol -- not, as the regex
        # would have it, to the previous function. Attach a contiguous comment
        # run to the definition immediately beneath it.
        attached = _attach_leading_comment(source, target, def_starts, language)
        if attached is not None:
            name, kind, _receiver = _qualified_name(attached, language, source_bytes)
            if name:
                return SymbolAnchor(
                    path=path,
                    symbol=name,
                    kind=kind,
                    start_line=attached.start_point[0] + 1,
                    confidence="parsed",
                    method="tree_sitter_doc",
                )
    if chosen is None:
        return SymbolAnchor(
            path=path,
            symbol="<file>",
            kind="file",
            start_line=1,
            confidence="parsed",
            method="tree_sitter",
        )
    name, kind, _receiver = _qualified_name(chosen, language, source_bytes)
    return SymbolAnchor(
        path=path,
        symbol=name or "<file>",
        kind=kind,
        start_line=chosen.start_point[0] + 1,
        confidence="parsed",
        method="tree_sitter",
    )


def _significant_tokens(source: str, language: str) -> list[str] | None:
    """The ordered non-comment leaf tokens of ``source``.

    Two revisions with the same token stream differ only in comments and
    whitespace. This is what makes the cosmetic-change test exact where the
    line-based regex is heuristic: a block comment, a comment that contains
    code, or reflowed whitespace all collapse to the same stream.
    """
    parser = _parser(language)
    if parser is None:
        return None
    tree = parser.parse(source.encode("utf-8"))
    tokens: list[str] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.child_count == 0:
            if node.type == "comment" or node.is_extra:
                continue
            text = node.text.decode("utf-8", "replace").strip()
            if text:
                tokens.append(text)
            continue
        stack.extend(reversed(node.children))
    return tokens


def is_cosmetic_change(before: str, after: str, *, path: str) -> bool | None:
    """Whether ``before`` -> ``after`` changes only comments/whitespace.

    Returns ``None`` for an unsupported language or unavailable parser. Unlike
    the diff-line heuristic this compares the two *token streams*, so it is not
    fooled by a reordered block comment or by code that happens to sit on the
    same line as a changed comment.
    """
    language = language_for_path(path)
    if language is None:
        return None
    before_tokens = _significant_tokens(before, language)
    after_tokens = _significant_tokens(after, language)
    if before_tokens is None or after_tokens is None:
        return None
    return before_tokens == after_tokens
