"""
Code-generated compiled pipeline for BuildingBlock DAGs.

After training, compiles the DAG into a single flat Python function via exec().
Eliminates all get_result() / _calculate() dispatch overhead in the hot path.

Usage:
    pipeline_fn = compile_pipeline(final_bb)
    for syscall in recording.syscalls():
        result = pipeline_fn(syscall)
"""
from collections import deque

from algorithms.building_block import BuildingBlock


# ── Type imports for isinstance checks in code generator ──────────────
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.int_embedding import IntEmbedding
from algorithms.features.impl.ngram import Ngram
from algorithms.decision_engines.stide import Stide
from algorithms.features.impl.stream_sum import StreamSum
from algorithms.features.impl.stream_average import StreamAverage
from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
from algorithms.features.impl.and_decider import AndDecider
from algorithms.features.impl.or_decider import OrDecider


def _topo_sort(final_bb):
    """DFS post-order topological sort over depends_on(). Shared nodes deduplicated via id()."""
    visited = set()
    order = []

    def _dfs(node):
        nid = id(node)
        if nid in visited:
            return
        visited.add(nid)
        for dep in node.depends_on():
            _dfs(dep)
        order.append(node)

    _dfs(final_bb)
    return order


# ── Inlined code generators per node type ─────────────────────────────

def _gen_syscall_name(i, node, node_to_idx):
    """SyscallName: v{i} = syscall._name"""
    return [f'v{i} = syscall._name']


def _gen_int_embedding(i, node, node_to_idx):
    """IntEmbedding: dict lookup on upstream value."""
    dep_idx = node_to_idx[id(node._dependency_list[0])]
    return [f'v{i} = _ie{i}_dict.get(v{dep_idx}, 0)']


def _gen_ngram(i, node, node_to_idx):
    """Ngram: deque buffer + concat, using compiled concat_mask."""
    lines = []
    dep_indices = [node_to_idx[id(d)] for d in node.depends_on()]

    # Safety: concat_mask must be set after training
    if node._concat_mask is None or node._deque_length is None:
        # Fallback to generic
        return None

    deque_length = node._deque_length
    thread_aware = node._thread_aware

    # None check on all deps
    none_checks = ' or '.join(f'v{d} is None' for d in dep_indices)
    lines.append(f'if {none_checks}:')
    lines.append(f'    v{i} = None')
    lines.append(f'else:')

    # Build flat deps using pre-compiled concat_mask
    has_any_iterable = any(node._concat_mask)
    if not has_any_iterable:
        # No iterables — deps list is just the raw values
        if len(dep_indices) == 1:
            flat_expr = f'(v{dep_indices[0]},)'
        else:
            flat_expr = '(' + ', '.join(f'v{d}' for d in dep_indices) + ',)'
        lines.append(f'    _ng{i}_flat = {flat_expr}')
    else:
        # Mixed: some iterable, some scalar
        lines.append(f'    _ng{i}_flat = []')
        for is_iter, dep_idx in zip(node._concat_mask, dep_indices):
            if is_iter:
                lines.append(f'    _ng{i}_flat.extend(v{dep_idx})')
            else:
                lines.append(f'    _ng{i}_flat.append(v{dep_idx})')

    # Thread ID
    if thread_aware:
        lines.append(f'    _ng{i}_tid = syscall._thread_id')
    else:
        lines.append(f'    _ng{i}_tid = 0')

    # Buffer access
    lines.append(f'    _ng{i}_buf = _ng{i}_bufdict.get(_ng{i}_tid)')
    lines.append(f'    if _ng{i}_buf is None:')
    lines.append(f'        _ng{i}_buf = deque(maxlen={deque_length})')
    lines.append(f'        _ng{i}_bufdict[_ng{i}_tid] = _ng{i}_buf')

    # Extend buffer
    if not has_any_iterable:
        lines.append(f'    _ng{i}_buf.extend(_ng{i}_flat)')
    else:
        lines.append(f'    _ng{i}_buf.extend(_ng{i}_flat)')

    # Return tuple if full, else None
    lines.append(f'    if len(_ng{i}_buf) == {deque_length}:')
    lines.append(f'        v{i} = tuple(_ng{i}_buf)')
    lines.append(f'    else:')
    lines.append(f'        v{i} = None')

    return lines


def _gen_stide(i, node, node_to_idx):
    """Stide: set membership check."""
    dep_idx = node_to_idx[id(node._dependency_list[0])]
    return [
        f'if v{dep_idx} is not None:',
        f'    v{i} = 0 if v{dep_idx} in _st{i}_db else 1',
        f'else:',
        f'    v{i} = None',
    ]


def _gen_stream_sum(i, node, node_to_idx):
    """StreamSum: sliding window with running sum."""
    dep_idx = node_to_idx[id(node._dependency_list[0])]
    thread_aware = node._thread_aware
    window_length = node._window_length
    wait_full = node._wait_until_window_full

    lines = []
    lines.append(f'_ss{i}_val = v{dep_idx}')
    lines.append(f'if _ss{i}_val is not None:')

    # Thread ID
    if thread_aware:
        lines.append(f'    _ss{i}_tid = syscall._thread_id')
    else:
        lines.append(f'    _ss{i}_tid = 0')

    # Buffer access
    lines.append(f'    _ss{i}_buf = _ss{i}_wbuf.get(_ss{i}_tid)')
    lines.append(f'    if _ss{i}_buf is None:')
    lines.append(f'        _ss{i}_buf = deque(maxlen={window_length})')
    lines.append(f'        _ss{i}_wbuf[_ss{i}_tid] = _ss{i}_buf')
    lines.append(f'        _ss{i}_sums[_ss{i}_tid] = 0')

    # Dropout + append
    lines.append(f'    _ss{i}_drop = _ss{i}_buf[0] if len(_ss{i}_buf) == {window_length} else 0')
    lines.append(f'    _ss{i}_buf.append(_ss{i}_val)')
    lines.append(f'    _ss{i}_sums[_ss{i}_tid] += _ss{i}_val - _ss{i}_drop')

    if wait_full:
        lines.append(f'    if len(_ss{i}_buf) == {window_length}:')
        lines.append(f'        v{i} = _ss{i}_sums[_ss{i}_tid]')
        lines.append(f'    else:')
        lines.append(f'        v{i} = None')
    else:
        lines.append(f'    v{i} = _ss{i}_sums[_ss{i}_tid]')

    lines.append(f'else:')
    lines.append(f'    v{i} = None')

    return lines


def _gen_stream_average(i, node, node_to_idx):
    """StreamAverage: divide StreamSum result by window_length."""
    # StreamAverage depends on its internal StreamSum
    dep_idx = node_to_idx[id(node._sum)]
    wl = node._window_length
    return [
        f'if v{dep_idx} is not None:',
        f'    v{i} = v{dep_idx} / {wl}',
        f'else:',
        f'    v{i} = None',
    ]


def _gen_max_score_threshold(i, node, node_to_idx):
    """MaxScoreThreshold: compare against threshold."""
    dep_idx = node_to_idx[id(node._dependency_list[0])]
    return [
        f'if isinstance(v{dep_idx}, (int, float)):',
        f'    v{i} = v{dep_idx} > _mst{i}_thr',
        f'else:',
        f'    v{i} = False',
    ]


def _gen_and_decider(i, node, node_to_idx):
    """AndDecider: evaluate ALL deps (for side effects), AND result."""
    dep_indices = [node_to_idx[id(d)] for d in node.depends_on()]
    # All deps are already computed (topo order), just combine
    checks = ' and '.join(f'v{d}' for d in dep_indices)
    return [f'v{i} = {checks}']


def _gen_or_decider(i, node, node_to_idx):
    """OrDecider: evaluate ALL deps (for side effects), OR result."""
    dep_indices = [node_to_idx[id(d)] for d in node.depends_on()]
    checks = ' or '.join(f'v{d}' for d in dep_indices)
    return [f'v{i} = {checks}']


# ── Registry ─────────────────────────────────────────────────────────

_INLINE_GENERATORS = {
    SyscallName: _gen_syscall_name,
    IntEmbedding: _gen_int_embedding,
    Ngram: _gen_ngram,
    Stide: _gen_stide,
    StreamSum: _gen_stream_sum,
    StreamAverage: _gen_stream_average,
    MaxScoreThreshold: _gen_max_score_threshold,
    AndDecider: _gen_and_decider,
    OrDecider: _gen_or_decider,
}


# ── Fallback code generation ─────────────────────────────────────────

def _find_fallback_dep_indices(node, node_to_idx):
    """Find indices of direct dependencies that need cache pre-setting for fallback."""
    dep_indices = []
    for dep in node.depends_on():
        dep_id = id(dep)
        if dep_id in node_to_idx:
            dep_indices.append(node_to_idx[dep_id])
    return dep_indices


def _gen_fallback(i, node, node_to_idx):
    """Fallback: pre-set cache on deps, then call get_result()."""
    lines = []
    dep_indices = _find_fallback_dep_indices(node, node_to_idx)

    # Pre-set cache on dependencies so get_result() finds them
    for dep_idx in dep_indices:
        lines.append(f'_nodes[{dep_idx}]._last_result = v{dep_idx}')
        lines.append(f'_nodes[{dep_idx}]._last_syscall = syscall')

    # Call get_result() which updates the node's own cache too
    lines.append(f'v{i} = _nodes[{i}].get_result(syscall)')

    return lines


# ── Main compiler ─────────────────────────────────────────────────────

def _generate_code(nodes, node_to_idx):
    """Generate code lines for the pipeline function body."""
    code_lines = []
    last_idx = len(nodes) - 1

    # Local aliases for hot state (generated at function start)
    alias_lines = []

    for i, node in enumerate(nodes):
        node_type = type(node)
        generator = _INLINE_GENERATORS.get(node_type)

        lines = None
        if generator is not None:
            lines = generator(i, node, node_to_idx)
            # lines=None means generator chose fallback (e.g. Ngram without concat_mask)

        if lines is None:
            lines = _gen_fallback(i, node, node_to_idx)

        # Collect alias lines for inlined nodes with mutable state
        if generator is not None and lines is not None:
            if node_type is IntEmbedding:
                alias_lines.append(f'_ie{i}_dict = _nodes[{i}]._syscall_dict')
            elif node_type is Ngram:
                alias_lines.append(f'_ng{i}_bufdict = _nodes[{i}]._ngram_buffer')
            elif node_type is Stide:
                alias_lines.append(f'_st{i}_db = _nodes[{i}]._normal_database')
            elif node_type is StreamSum:
                alias_lines.append(f'_ss{i}_wbuf = _nodes[{i}]._window_buffer')
                alias_lines.append(f'_ss{i}_sums = _nodes[{i}]._sum_values')
            elif node_type is MaxScoreThreshold:
                alias_lines.append(f'_mst{i}_thr = _nodes[{i}]._threshold')

        code_lines.extend(lines)

    # Return final result
    code_lines.append(f'return v{last_idx}')

    return alias_lines, code_lines


def compile_pipeline(final_bb, debug=False):
    """
    Compile a BuildingBlock DAG into a single flat Python function.

    After training/fitting, call this to get a callable that processes
    one syscall at a time with minimal overhead.

    Args:
        final_bb: the root BuildingBlock (must be a decider)
        debug: if True, print the generated source code

    Returns:
        A callable(syscall) -> result, with ._source and ._nodes attributes.
    """
    nodes = _topo_sort(final_bb)
    node_to_idx = {id(n): i for i, n in enumerate(nodes)}

    alias_lines, body_lines = _generate_code(nodes, node_to_idx)

    # Build function source
    parts = ['def _pipeline(syscall):']

    # Alias lines go first (local variable bindings)
    for line in alias_lines:
        parts.append(f'    {line}')

    # Body lines (indented, preserving internal indentation)
    for line in body_lines:
        parts.append(f'    {line}')

    code_str = '\n'.join(parts)

    if debug:
        print("── Compiled Pipeline Source ──")
        print(code_str)
        print("── End ──")

    # Compile and execute
    ns = {'_nodes': nodes, 'deque': deque}
    exec(compile(code_str, '<compiled_pipeline>', 'exec'), ns)
    fn = ns['_pipeline']
    fn._source = code_str
    fn._nodes = nodes
    return fn
