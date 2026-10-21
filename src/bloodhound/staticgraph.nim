## Noninteractive findings: named horizontal paths with plain-language evidence.
import std/[algorithm, json, sets, strutils, tables]
import ./graph

const controlEdgeKinds* = toHashSet([
  "AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "DCSync", "SyncLAPSPassword",
  "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "AllExtendedRights",
  "AddKeyCredentialLink", "ForceChangePassword", "WriteAccountRestrictions",
  "AllowedToDelegate", "AllowedToAct", "HasSession", "DumpSMSAPassword", "HasSIDHistory"
])

type GraphSelection* = object
  seeds*: seq[string]
  edges*: seq[int]
  totalEdges*: int

proc selectGraph*(g: Graph; seeds: seq[string]; limit = 24; controlOnly = false): GraphSelection =
  result.seeds = seeds
  var wanted = initHashSet[string]()
  for id in seeds: wanted.incl id
  var buckets = initTable[string, seq[int]]()
  var candidates: seq[int]
  for i, e in g.edges:
    let incident = e.source in wanted or e.target in wanted
    if not incident: continue
    if controlOnly and not (e.source in wanted and e.kind in controlEdgeKinds): continue
    candidates.add i
  candidates.sort(proc(a, b: int): int =
    # Put explicit memberships first; ties are stable by identity, not ZIP order.
    let ea = g.edges[a]
    let eb = g.edges[b]
    result = cmp(ord(ea.kind != "MemberOf"), ord(eb.kind != "MemberOf"))
    if result == 0: result = cmp(edgeKey(ea), edgeKey(eb)))
  result.totalEdges = candidates.len
  for i in candidates:
    let e = g.edges[i]
    if e.source in wanted: buckets.mgetOrPut(e.source, @[]).add i
    if e.target in wanted and e.source != e.target: buckets.mgetOrPut(e.target, @[]).add i
  var seen = initHashSet[int]()
  var depth = 0
  let cap = if limit == 0: high(int) else: limit
  while result.edges.len < cap:
    var more = false
    for id in seeds:
      let bucket = buckets.getOrDefault(id)
      if depth < bucket.len:
        more = true
        let i = bucket[depth]
        if i notin seen:
          seen.incl i
          result.edges.add i
          if result.edges.len >= cap: break
    if not more: break
    inc depth


proc chainAnnotation*(g: Graph; e: GraphEdge): string =
  let src = safe(g.nodes.getOrDefault(e.source).name)
  let tgt = safe(g.nodes.getOrDefault(e.target).name)
  case e.kind
  of "AdminTo":     "nimux scm " & tgt & " -u <user> -p <pass> --cmd whoami"
  of "CanRDP":      "nimux rdp " & tgt & " -u <user> -p <pass>"
  of "CanPSRemote": "nimux winrm " & tgt & " -u <user> -p <pass> --cmd whoami"
  of "ExecuteDCOM": "nimux cim " & tgt & " -u <user> -p <pass> --cmd whoami"
  of "DCSync":      "nimux dcsync <dc> -u <user> -p <pass> -d <domain>"
  of "SyncLAPSPassword": "nimux ldap <dc> -u <user> -p <pass> --filter \"(ms-Mcs-AdmPwd=*)\"  # LAPS on " & tgt
  of "GenericAll", "AllExtendedRights":
    "nimux ldap <dc> -u <user> -p <pass> -d <domain> --set-password --user " & tgt & " --new-pass 'NewPass123!' --ldaps\n" &
    "  # or shadow creds: nimux ldap <dc> -u <user> -p <pass> -d <domain> --shadow-creds --user " & tgt & " --shadow-out " & tgt & "\n" &
    "  # or grant DCSync: nimux ldap <dc> -u <user> -p <pass> -d <domain> --acl --add --dn <domainDN> --principal <user> --rights DCSync"
  of "GenericWrite":
    "nimux ldap <dc> -u <user> -p <pass> -d <domain> --shadow-creds --user " & tgt & " --shadow-out " & tgt & "\n" &
    "  # or targeted kerberoast: nimux ldap <dc> -u <user> -p <pass> -d <domain> --make-kerberoast --user " & tgt & " --spn fake/spn\n" &
    "  # or RBCD: nimux ldap <dc> -u <user> -p <pass> -d <domain> --set-rbcd --from <controlled$> --to " & tgt
  of "WriteDacl":
    "nimux ldap <dc> -u <user> -p <pass> -d <domain> --acl --add --user " & tgt & " --principal <user> --rights GenericAll\n" &
    "  # then escalate with GenericAll rights above"
  of "WriteOwner":
    "nimux ldap <dc> -u <user> -p <pass> -d <domain> --set-owner --user " & tgt & " --owner <user>\n" &
    "  # then: nimux ldap <dc> -u <user> -p <pass> -d <domain> --acl --add --user " & tgt & " --principal <user> --rights GenericAll"
  of "ForceChangePassword":
    "nimux ldap <dc> -u " & src & " -p <pass> -d <domain> --set-password --user " & tgt & " --new-pass 'NewPass123!' --ldaps\n" &
    "  # Linux alt: rpcclient -U '<domain>/" & src & "%<pass>' <dc> -c \"setuserinfo2 " & tgt & " 23 'NewPass123!'\"\n" &
    "  # Windows:   net user " & tgt & " 'NewPass123!' /domain"
  of "WriteAccountRestrictions":
    "nimux ldap <dc> -u <user> -p <pass> -d <domain> --set-rbcd --from <controlled$> --to " & tgt & "\n" &
    "  # then S4U2Self/S4U2Proxy to impersonate Administrator on " & tgt
  of "AddKeyCredentialLink":
    "nimux ldap <dc> -u <user> -p <pass> -d <domain> --shadow-creds --user " & tgt & " --shadow-out " & tgt & "\n" &
    "  # then use the cert to get a TGT and retrieve NT hash via PKINIT"
  of "AllowedToDelegate":
    "# Constrained delegation from " & src & " to " & tgt & ": request forwardable TGT for " & src & " then S4U2Proxy"
  of "AllowedToAct":
    "nimux ldap <dc> -u <user> -p <pass> -d <domain> --set-rbcd --from " & src & " --to " & tgt & "\n" &
    "  # then S4U2Self/S4U2Proxy to impersonate Administrator on " & tgt
  of "HasSession":
    "# " & src & " had a session for " & tgt & ": hunt credentials/tokens on " & src
  else: ""

proc renderGraph*(g: Graph; seeds: seq[string]; color = false; limit = 50;
                  queryPaths: seq[seq[int]] = @[]; pathMode = false;
                  reachablePairs = 0; pathTruncated = false; chain = false;
                  controlOnly = false): string =
  let selection = if pathMode: GraphSelection(seeds: seeds)
                  else: selectGraph(g, seeds, limit, controlOnly)
  proc paint(s, code: string): string =
    if color: "\e[" & code & "m" & s & "\e[0m" else: s
  var names = initCountTable[string]()
  var derivedCount = 0
  for e in g.edges:
    if e.derived: inc derivedCount
  for n in g.nodes.values: names.inc safe(n.name)
  proc label(id: string): string =
    let n = g.nodes[id]
    result = safe(n.name)
    if names[result] > 1: result.add " (" & safe(id) & ")"
    if n.unresolved: result.add " [incomplete record]"
  proc explain(e: GraphEdge): string =
    let a = label(e.source)
    let b = label(e.target)
    case e.kind
    of "MemberOf": a & " belongs to " & b & "."
    of "AdminTo": a & " has recorded local administrator rights on " & b & "."
    of "Contains": a & " contains " & b & "."
    of "HasSession": a & " had a recorded session for " & b & "."
    of "GenericAll": a & " has a recorded full-control permission on " & b & "."
    of "GenericWrite": a & " has a recorded write permission on " & b & "."
    of "WriteDacl": a & " has recorded permission to change the access-control list of " & b & "."
    of "WriteOwner": a & " has recorded permission to change the owner of " & b & "."
    of "Owns": a & " is recorded as the owner of " & b & "."
    of "CanRDP": a & " has recorded remote-desktop rights on " & b & "."
    of "CanPSRemote": a & " has recorded PowerShell remoting rights on " & b & "."
    of "ExecuteDCOM": a & " has recorded DCOM execution rights on " & b & "."
    of "GPLink": a & " is linked as group policy to " & b & "."
    of "DCSync": a & " satisfies the Legacy combined replication-rights rule for " & b & "."
    of "SyncLAPSPassword": a & " satisfies the Legacy replication-based LAPS rule for " & b & "."
    of "ForceChangePassword": a & " can change the password of " & b & " without knowing the current password."
    of "AddKeyCredentialLink": a & " can write msDS-KeyCredentialLink on " & b & " (shadow credentials / PKINIT)."
    of "WriteAccountRestrictions": a & " can write msDS-AllowedToActOnBehalfOfOtherIdentity on " & b & " (RBCD)."
    of "AllowedToAct": a & " is recorded in the RBCD attribute of " & b & "; it can impersonate any user to " & b & "."
    of "AllowedToDelegate": a & " has constrained delegation rights targeting " & b & "."
    of "AllExtendedRights": a & " has all extended rights on " & b & " (includes ForceChangePassword, targeted Kerberoast)."
    else: "The collection records " & safe(e.kind) & " from " & a & " to " & b & "."
  result = paint("┌─ BLOODHOUND · relationship findings", "1;36") & "\n"
  if pathMode:
    result.add "│ Full graph queried: " & $g.nodes.len & " nodes / " & $g.edges.len & " evidence edges.\n"
    result.add "│ " & $reachablePairs & " reachable source/target pairs; " & $queryPaths.len & " shortest paths shown.\n"
  else:
    result.add "│ " & $selection.edges.len & "/" & $selection.totalEdges &
      (if derivedCount > 0: " graph relationships shown (recorded + derived)." else: " recorded relationships shown.") &
      " Read each path left to right.\n"
  result.add "│ Findings describe collection evidence, not confirmed exploitable access.\n"
  if derivedCount > 0:
    result.add "│ " & $derivedCount & " derived-right edges included in the graph.\n"
  if seeds.len == 0:
    result.add "└─ No matching objects.\n"
    return
  var paths = queryPaths
  if not pathMode:
    for i in selection.edges: paths.add @[i]
  var altRoutes = initTable[int, seq[string]]()
  if pathMode and paths.len > 0:
    var nodeSeqToIdx = initTable[string, int]()
    var deduped: seq[seq[int]]
    for path in paths:
      var key = safe(g.edges[path[0]].source)
      for idx in path: key.add "\x00" & safe(g.edges[idx].target)
      if key in nodeSeqToIdx:
        let orig = nodeSeqToIdx[key]
        var combo = ""
        for idx in path: combo.add safe(g.edges[idx].kind) & "+"
        altRoutes.mgetOrPut(orig, @[]).add combo.strip(chars={'+' })
      else:
        nodeSeqToIdx[key] = deduped.len
        deduped.add path
    paths = deduped
  for i, path in paths:
    var title = "Recorded " & safe(g.edges[path[0]].kind) & " relationship"
    if g.edges[path[0]].derived: title = "Derived " & safe(g.edges[path[0]].kind) & " relationship"
    if pathMode: title = "Shortest directed path (" & $path.len & " relationships)"
    if g.nodes[g.edges[path[^1]].target].highValue:
      title.add " to a high-value object"
    result.add "\n" & paint("  Finding " & $(i+1) & " · " & title, "1;36") & "\n\n"
    var diagram = label(g.edges[path[0]].source)
    for edge in path:
      let e = g.edges[edge]
      diagram.add " ──" & safe(e.kind) & "──▶ " & label(e.target)
    result.add "  " & diagram & "\n\n"
    for edge in path:
      result.add "  " & explain(g.edges[edge]) & "\n"
    var evidence: seq[string]
    for edge in path:
      let origin = safe(g.edges[edge].evidence)
      if origin notin evidence: evidence.add origin
    result.add "  Evidence: " & $path.len & " graph relationship" &
      (if path.len == 1: "" else: "s") & " · " & evidence.join("; ") & ".\n"
    if pathMode and altRoutes.hasKey(i) and altRoutes[i].len > 0:
      result.add "  Alternate routes: " & altRoutes[i].join(", ") & "\n"
    for edge in path:
      let derived = g.edges[edge]
      if not derived.derived: continue
      result.add "  Derived " & safe(derived.kind) & " — supporting recorded paths:\n"
      for proof in derived.support:
        if proof.len == 0: continue
        var line = label(g.edges[proof[0]].source)
        var origins: seq[string]
        for step in proof:
          let e = g.edges[step]
          line.add " ──" & safe(e.kind) & "──▶ " & label(e.target)
          let origin = safe(e.evidence)
          if origin notin origins: origins.add origin
        result.add "    " & line & "\n"
        result.add "    Collection evidence: " & origins.join("; ") & "\n"
    if chain:
      for edge in path:
        let anno = chainAnnotation(g, g.edges[edge])
        if anno.len > 0:
          for line in anno.splitLines():
            if line.startsWith("  #"):
              result.add paint("  " & line.strip(leading=false), "2") & "\n"
            elif line.startsWith("#"):
              result.add paint("  " & line, "2") & "\n"
            else:
              result.add paint("  Chain: ", "33") & paint(line.strip(leading=false), "1;32") & "\n"
  if pathMode and paths.len == 0:
    result.add "\n  No directed paths matched the chosen sources, targets and traversal rules.\n"
  elif not pathMode and selection.totalEdges == 0:
    result.add "\n  No resolved incident edges recorded; absence does not establish no access.\n"
    for i in 0..<min(seeds.len, 24): result.add "  " & label(seeds[i]) & "\n"
    if seeds.len > 24: result.add "  Additional selected objects omitted.\n"
  if pathMode and pathTruncated:
    result.add "\n  MORE PATHS EXIST: output limit reached, not an analysis depth limit. Use --limit 0 or narrow --from/--to.\n"
  if not pathMode and selection.totalEdges > selection.edges.len:
    result.add "\n  OMITTED: " & $(selection.totalEdges-selection.edges.len) &
      " relationships. Use --limit 0 or narrow with --inspect <name-or-id> --graph.\n"
  for warning in g.warnings: result.add "  NOTE: " & safe(warning) & "\n"
  result.add "└─ Snapshot evidence only; connected edges do not prove end-to-end access.\n"

proc renderGraphJson*(g: Graph; queryPaths: seq[seq[int]]; reachablePairs: int; truncated: bool): JsonNode =
  result = %*{"nodes": g.nodes.len, "edges": g.edges.len,
              "reachable_pairs": reachablePairs, "truncated": truncated, "paths": []}
  for path in queryPaths:
    var hops = newJArray()
    for idx in path:
      let e = g.edges[idx]
      let src = g.nodes.getOrDefault(e.source)
      let tgt = g.nodes.getOrDefault(e.target)
      hops.add %*{"source": {"id": e.source, "name": src.name, "kind": src.kind},
                  "target": {"id": e.target, "name": tgt.name, "kind": tgt.kind},
                  "relationship": e.kind, "evidence": e.evidence, "derived": e.derived}
    result["paths"].add hops
