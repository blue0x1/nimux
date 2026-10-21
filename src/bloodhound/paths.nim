## Native directed shortest-path queries over the FULL imported graph.
import std/[algorithm, sets, tables]
import ./graph

type
  PathReport* = object
    paths*: seq[seq[int]]
    reachablePairs*, nodes*, edges*: int
    truncated*: bool
  TargetPlan = object
    target: string
    distance: Table[string, int]

proc privilegedMembers*(g: Graph): HashSet[string] =
  var incoming = initTable[string, seq[string]]()
  for e in g.edges:
    if e.kind == "MemberOf": incoming.mgetOrPut(e.target, @[]).add e.source
  var queue: seq[string]
  for id, n in g.nodes:
    if n.highValue: result.incl id; queue.add id
  var cursor = 0
  while cursor < queue.len:
    let id = queue[cursor]
    inc cursor
    for member in incoming.getOrDefault(id):
      if member notin result: result.incl member; queue.add member

proc shortestPaths*(g: Graph; sources, targets: seq[string]; limit = 50;
                    maxDepth = 0): PathReport =
  if targets.len > 1000:
    raise newException(ValueError, "Too many path targets; narrow with --to")
  result.nodes = g.nodes.len
  result.edges = g.edges.len
  var forward, reverse: Table[string, seq[int]]
  for i, e in g.edges:
    # Legacy's high-value query excludes these component rights. Neither alone
    # is a DCSync edge. Combined rights are materialized before querying.
    if e.kind in ["GetChanges", "GetChangesAll", "GetChangesInFilteredSet"]: continue
    forward.mgetOrPut(e.source, @[]).add i
    reverse.mgetOrPut(e.target, @[]).add i
  for id, indexes in forward.mpairs:
    indexes.sort(proc(a, b: int): int = cmp(edgeKey(g.edges[a]), edgeKey(g.edges[b])))
  var plans: seq[TargetPlan]
  var pairs: seq[tuple[depth: int, source: string, plan: int]]
  var work = 0
  for target in targets:
    var plan = TargetPlan(target: target)
    plan.distance[target] = 0
    var queue = @[target]
    var cursor = 0
    while cursor < queue.len:
      let current = queue[cursor]
      inc cursor
      let depth = plan.distance[current]
      if maxDepth > 0 and depth >= maxDepth: continue
      for i in reverse.getOrDefault(current):
        inc work
        if work > 20000000:
          raise newException(ValueError, "Path query exceeds work limit; narrow with --from/--to or --depth")
        let source = g.edges[i].source
        if source notin plan.distance:
          plan.distance[source] = depth+1
          queue.add source
    for source in sources:
      if source != target and source in plan.distance:
        if pairs.len >= 2000000:
          raise newException(ValueError, "Too many reachable pairs; narrow with --from/--to")
        pairs.add (plan.distance[source], source, plans.len)
    plans.add plan
  pairs.sort()
  result.reachablePairs = pairs.len
  let cap = if limit == 0: 100000 else: limit
  for pair in pairs:
    let plan = plans[pair.plan]
    # Iterative DFS of the shortest-path DAG retains equal-length alternatives.
    var nodes = @[pair.source]
    var cursors = @[0]
    var path: seq[int]
    while nodes.len > 0:
      let current = nodes[^1]
      if current == plan.target:
        if result.paths.len >= cap:
          result.truncated = true
          return
        result.paths.add path
        discard nodes.pop(); discard cursors.pop()
        if path.len > 0: discard path.pop()
        continue
      let adjacent = forward.getOrDefault(current)
      var found = false
      while cursors[^1] < adjacent.len:
        let i = adjacent[cursors[^1]]
        inc cursors[^1]
        let next = g.edges[i].target
        if plan.distance.getOrDefault(next, -1) == plan.distance[current]-1:
          path.add i
          nodes.add next
          cursors.add 0
          found = true
          break
      if not found:
        discard nodes.pop(); discard cursors.pop()
        if path.len > 0: discard path.pop()
