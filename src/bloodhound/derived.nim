## Offline Legacy 4.3.1 replication-right conjunctions. No network activity.
import std/[algorithm, sets, tables]
import ./graph

proc deriveReplicationRights*(g: var Graph) =
  let originalEdges = g.edges
  var incoming: Table[string, seq[int]]
  var existing = initHashSet[string]()
  for i, e in g.edges:
    existing.incl e.source & "\x00" & e.kind & "\x00" & e.target
    if not e.derived and e.kind in ["MemberOf", "GetChanges", "GetChangesAll", "GetChangesInFilteredSet"]:
      incoming.mgetOrPut(e.target, @[]).add i
  var domains: seq[string]
  var laps: Table[string, seq[string]]
  for id, n in g.nodes:
    if n.kind == "domains": domains.add id
    if n.kind == "computers" and n.hasLaps and n.domainSid.len > 0:
      laps.mgetOrPut(n.domainSid, @[]).add id
  domains.sort()
  for ids in laps.mvalues: ids.sort()
  var work, added: int
  # Read only the original graph while collecting witnesses. Derived edges are
  # appended later, so support indexes remain stable and cannot justify themselves.
  var additions: seq[GraphEdge]
  proc witnesses(domain, right: string): Table[string, seq[int]] =
    var next = initTable[string, int]()
    var queue = @[domain]
    var visited = initHashSet[string]()
    visited.incl domain
    var cursor = 0
    while cursor < queue.len:
      let target = queue[cursor]
      inc cursor
      for i in incoming.getOrDefault(target):
        inc work
        if work > 20000000: raise newException(ValueError, "Derived-right processing exceeds 20M edge visits")
        let e = originalEdges[i]
        if e.kind notin ["MemberOf", right] or e.source in visited: continue
        visited.incl e.source
        next[e.source] = i
        queue.add e.source
    for source in queue:
      if source == domain: continue
      var current = source
      var proof: seq[int]
      var hasRight = false
      while current != domain:
        let i = next[current]
        proof.add i
        hasRight = hasRight or originalEdges[i].kind == right
        current = originalEdges[i].target
        inc work
        if work > 20000000: raise newException(ValueError, "Derived-right evidence exceeds 20M steps")
      if hasRight: result[source] = proof
  proc add(source, target, kind, basis: string; a, b: seq[int]) =
    let signature = source & "\x00" & kind & "\x00" & target
    if signature in existing: return
    existing.incl signature
    inc added
    if added > 1000000: raise newException(ValueError, "Derived-right processing exceeds 1M added edges")
    additions.add GraphEdge(source: source, target: target, kind: kind,
      evidence: "Derived (BloodHound Legacy rule): " & basis, derived: true,
      support: @[a, b])
  for domain in domains:
    let changes = witnesses(domain, "GetChanges")
    let all = witnesses(domain, "GetChangesAll")
    let filtered = witnesses(domain, "GetChangesInFilteredSet")
    var principals: seq[string]
    for id in changes.keys: principals.add id
    principals.sort()
    for id in principals:
      if id in all:
        add(id, domain, "DCSync", "GetChanges + GetChangesAll on " & domain,
          changes[id], all[id])
      if id in filtered:
        for computer in laps.getOrDefault(domain):
          add(id, computer, "SyncLAPSPassword",
            "GetChanges + GetChangesInFilteredSet on " & domain & "; target domainsid matches; haslaps=true",
            changes[id], filtered[id])
  g.edges.add additions
