## Offline inventory and membership inspection; no network or execution imports.
import std/[algorithm, json, os, sets, strutils, tables, terminal, times, unicode]
import ./archive
import ./graph
import ./staticgraph
import ./paths
import ./derived

type
  BhObject* = object
    id*, name*, kind*, domain*, dn*: string
    enabled*: JsonNode
    facts*: JsonNode
  Dataset* = object
    objects*: OrderedTable[string, BhObject]
    memberships*: Table[string, seq[string]]
    files*: JsonNode
    warnings*: seq[string]
    coverage*: JsonNode
    snapshotTime*: int64
    edges*: seq[GraphEdge]
    references*: Table[string, GraphNode]

const coverageFields = ["Sessions", "LocalAdmins", "RemoteDesktopUsers",
  "DcomUsers", "PSRemoteUsers"]

proc key(s: string): string = s.toUpperAscii()

proc checkNesting(s: string) =
  var depth = 0
  var quoted, escaped: bool
  for c in s:
    if quoted:
      if escaped: escaped = false
      elif c == '\\': escaped = true
      elif c == '"': quoted = false
    elif c == '"': quoted = true
    elif c in {'{', '['}:
      inc depth
      if depth > 64: raise newException(ValueError, "JSON nesting exceeds 64")
    elif c in {'}', ']'}: dec depth

proc refId(item: JsonNode): string =
  if item.kind == JString: item.getStr()
  else: item{"ObjectIdentifier"}.getStr()

proc evidenceValue(value: JsonNode): string =
  if value == nil: "unknown" else: $value

proc loadDataset*(path: string): Dataset =
  result.files = newJArray()
  result.coverage = newJObject()
  for field in coverageFields:
    result.coverage[field] = %*{"collected": 0, "not_collected": 0, "unknown": 0}
  var pending: seq[tuple[member, group: string]]
  var rawEdges: seq[GraphEdge]
  var aliases = initTable[string, string]()
  var records = 0
  var duplicates = 0
  for entry in jsonEntries(path):
    let base = extractFilename(entry.name)
    if base.len >= 15 and base[14] == '_':
      try:
        let stamp = parse(base[0..13], "yyyyMMddHHmmss", utc()).toTime.toUnix
        result.snapshotTime = max(result.snapshotTime, stamp)
      except TimeParseError: discard
    checkNesting(entry.contents)
    let doc = parseJson(entry.contents)
    if doc.kind != JObject or doc{"data"}.isNil or doc["data"].kind != JArray or
        doc{"meta"}.isNil or doc["meta"].kind != JObject:
      result.warnings.add entry.name & ": skipped (no BloodHound data/meta envelope)"
      continue
    let kind = doc{"meta", "type"}.getStr().toLowerAscii()
    if kind notin ["users", "groups", "computers", "domains", "gpos", "ous", "containers", "trusts"]:
      result.warnings.add entry.name & ": unsupported object type"
      continue
    let version = doc{"meta", "version"}.getInt()
    if version notin [5, 6]:
      result.warnings.add entry.name & ": unsupported schema version " & $version
      continue
    if doc{"meta", "count"}.isNil or doc["meta"]["count"].kind != JInt or
        doc["meta"]["count"].getInt() != doc["data"].len:
      raise newException(ValueError, entry.name & ": meta.count does not match data")
    result.files.add %*{"file": entry.name, "type": kind,
      "version": version, "count": doc["data"].len}
    for item in doc["data"]:
      inc records
      if records > 200000: raise newException(ValueError, "Dataset exceeds 200000 objects")
      let id = key(item{"ObjectIdentifier"}.getStr())
      let props = item{"Properties"}
      if id.len == 0 or props.isNil or props.kind != JObject:
        raise newException(ValueError, entry.name & ": object lacks identifier/properties")
      var obj = BhObject(id: id, name: props{"name"}.getStr(id), kind: kind,
        domain: props{"domain"}.getStr(), dn: props{"distinguishedname"}.getStr(),
        enabled: props{"enabled"})
      obj.facts = newJObject()
      for field in ["highvalue", "passwordnotreqd", "pwdneverexpires", "haslaps"]:
        let value = props{field}
        if value != nil and value.kind == JBool: obj.facts[field] = value
      let logon = props{"lastlogontimestamp"}
      if props{"domainsid"} != nil and props["domainsid"].kind == JString:
        obj.facts["domainsid"] = %key(props["domainsid"].getStr())
      if logon != nil and logon.kind == JInt: obj.facts["lastlogontimestamp"] = logon
      if id in result.objects:
        let previous = result.objects[id]
        if previous.kind != obj.kind or key(previous.name) != key(obj.name):
          raise newException(ValueError, entry.name & ": conflicting object identifier")
        inc duplicates
      else:
        result.objects[id] = obj
      aliases[id] = id
      if obj.dn.len > 0: aliases[key(obj.dn)] = id
      if kind == "groups" and item{"Members"} != nil and item["Members"].kind == JArray:
        for member in item["Members"]:
          let memberId = refId(member)
          if memberId.len > 0: pending.add (key(memberId), id)
      let primary = item{"PrimaryGroupSID"}.getStr()
      if primary.len > 0: pending.add (id, key(primary))
      template edge(src, dst, relation, origin: string) =
        if src.len > 0 and dst.len > 0:
          rawEdges.add GraphEdge(source: key(src), target: key(dst), kind: relation, evidence: origin)
          if rawEdges.len > 1000000: raise newException(ValueError, "Too many recorded graph edges")
      if item{"Aces"} != nil and item["Aces"].kind == JArray:
        for ace in item["Aces"]:
          let right = ace{"RightName"}.getStr()
          if right.len > 0 and key(ace{"PrincipalSID"}.getStr()) != id:
            edge(ace{"PrincipalSID"}.getStr(), id, right,
              "Aces; inherited=" & $ace{"IsInherited"}.getBool())
      for field in ["LocalAdmins", "RemoteDesktopUsers", "DcomUsers", "PSRemoteUsers"]:
        let section = item{field}
        if section != nil and section{"Collected"}.getBool() and section{"Results"} != nil and section["Results"].kind == JArray:
          let relation = case field
            of "LocalAdmins": "AdminTo"
            of "RemoteDesktopUsers": "CanRDP"
            of "DcomUsers": "ExecuteDCOM"
            else: "CanPSRemote"
          for principal in section["Results"]: edge(refId(principal), id, relation, field)
      for field in ["Sessions", "PrivilegedSessions", "RegistrySessions"]:
        let section = item{field}
        if section != nil and section{"Collected"}.getBool() and section{"Results"} != nil and section["Results"].kind == JArray:
          for session in section["Results"]:
            edge(session{"ComputerSID"}.getStr(), session{"UserSID"}.getStr(), "HasSession", field)
      for field in ["ChildObjects", "AllowedToDelegate", "AllowedToAct", "HasSIDHistory", "DumpSMSAPassword"]:
        if item{field} != nil and item[field].kind == JArray:
          for other in item[field]:
            let target = refId(other)
            if field == "AllowedToAct": edge(target, id, field, field)
            else: edge(id, target, (if field == "ChildObjects": "Contains" else: field), field)
      if item{"Links"} != nil and item["Links"].kind == JArray:
        for link in item["Links"]:
          edge(link{"GUID"}.getStr(), id, "GPLink", "Links; enforced=" & $link{"IsEnforced"}.getBool())
      let changes = item{"GPOChanges"}
      if kind in ["ous", "domains"] and changes != nil and changes{"AffectedComputers"} != nil and changes["AffectedComputers"].kind == JArray:
        for field in ["LocalAdmins", "RemoteDesktopUsers", "DcomUsers", "PSRemoteUsers"]:
          if changes{field} != nil and changes[field].kind == JArray:
            let relation = case field
              of "LocalAdmins": "AdminTo"
              of "RemoteDesktopUsers": "CanRDP"
              of "DcomUsers": "ExecuteDCOM"
              else: "CanPSRemote"
            for computer in changes["AffectedComputers"]:
              for principal in changes[field]:
                edge(refId(principal), refId(computer), relation, "GPOChanges." & field & "; from=" & id)
      if kind == "domains" and item{"Trusts"} != nil and item["Trusts"].kind == JArray:
        for trust in item["Trusts"]:
          let target = key(trust{"TargetDomainSid"}.getStr())
          if target.len == 0: continue
          result.references[target] = GraphNode(id: target,
            name: trust{"TargetDomainName"}.getStr(target), kind: "domains")
          let direction = trust{"TrustDirection"}
          let code = if direction != nil and direction.kind == JInt: direction.getInt()
                     elif direction.getStr() == "Inbound": 1
                     elif direction.getStr() == "Outbound": 2
                     elif direction.getStr() == "Bidirectional": 3 else: 0
          let evidence = "Trusts; type=" & evidenceValue(trust{"TrustType"}) & "; transitive=" &
            evidenceValue(trust{"IsTransitive"}) & "; sidfiltering=" & evidenceValue(trust{"SidFilteringEnabled"})
          if code in [1,3]: edge(id, target, "TrustedBy", evidence)
          if code in [2,3]: edge(target, id, "TrustedBy", evidence)
      if pending.len > 1000000: raise newException(ValueError, "Too many memberships")
      if kind == "computers":
        for field in coverageFields:
          let value = item{field, "Collected"}
          let state = if value.isNil or value.kind != JBool: "unknown"
                      elif value.getBool(): "collected" else: "not_collected"
          result.coverage[field][state] = %(result.coverage[field][state].getInt() + 1)
  if result.files.len == 0: raise newException(ValueError, "No supported BloodHound v5/v6 JSON files found")
  if duplicates > 0: result.warnings.add $duplicates & " repeated objects merged by identifier (first properties retained)"
  var unresolved = 0
  var seen = initHashSet[string]()
  for pair in pending:
    let member = aliases.getOrDefault(pair.member, pair.member)
    let group = aliases.getOrDefault(pair.group, pair.group)
    if member notin result.objects or group notin result.objects:
      inc unresolved
      rawEdges.add GraphEdge(source: member, target: group, kind: "MemberOf", evidence: "Members/PrimaryGroupSID; unresolved endpoint")
      continue
    let signature = member & "\x00" & group
    if signature notin seen:
      seen.incl signature
      result.memberships.mgetOrPut(member, @[]).add group
  if unresolved > 0: result.warnings.add $unresolved & " membership references were unresolved"
  for member, groups in result.memberships:
    for group in groups:
      rawEdges.add GraphEdge(source: member, target: group, kind: "MemberOf", evidence: "Members/PrimaryGroupSID")
  seen.clear()
  unresolved = 0
  for raw in rawEdges:
    var e = raw
    e.source = aliases.getOrDefault(e.source, e.source)
    e.target = aliases.getOrDefault(e.target, e.target)
    if e.source notin result.objects or e.target notin result.objects:
      inc unresolved
    let signature = edgeKey(e)
    if signature notin seen:
      seen.incl signature
      result.edges.add e
  if unresolved > 0: result.warnings.add $unresolved & " evidence edges have incomplete endpoint records; retained as reference nodes"

proc objectJson*(obj: BhObject): JsonNode =
  result = %*{"id": obj.id, "name": obj.name, "type": obj.kind, "domain": obj.domain}
  if obj.enabled != nil and obj.enabled.kind == JBool: result["enabled"] = obj.enabled

proc summary*(dataset: Dataset): JsonNode =
  var counts = newJObject()
  var edges = 0
  for obj in dataset.objects.values:
    counts[obj.kind] = %(counts{obj.kind}.getInt() + 1)
  for groups in dataset.memberships.values: edges += groups.len
  %*{"operation": "summary", "objects": dataset.objects.len, "counts": counts,
    "membership_edges": edges, "recorded_graph_edges": dataset.edges.len, "files": dataset.files, "coverage": dataset.coverage,
    "warnings": dataset.warnings, "notice": "Snapshot only; missing relationships do not prove absence of access."}

proc search*(dataset: Dataset; query: string; limit = 100): JsonNode =
  result = %*{"operation": "search", "matches": [], "total": 0}
  var ids: seq[string]
  for id, obj in dataset.objects:
    if key(query) in key(obj.name) or key(query) in id: ids.add id
  ids.sort()
  result["total"] = %ids.len
  for i in 0 ..< min(limit, ids.len): result["matches"].add objectJson(dataset.objects[ids[i]])
  result["truncated"] = %(ids.len > limit)

proc list*(dataset: Dataset; kind: string; filter = ""; limit = 1000): JsonNode =
  result = %*{"operation": "list", "kind": kind, "matches": [], "total": 0, "filter": filter}
  var ids: seq[string]
  for id, obj in dataset.objects:
    if obj.kind != kind: continue
    if filter.len > 0 and key(filter) notin key(obj.name): continue
    ids.add id
  ids.sort()
  result["total"] = %ids.len
  for i in 0 ..< min(limit, ids.len):
    let obj = dataset.objects[ids[i]]
    let item = objectJson(obj)
    if obj.facts{"highvalue"}.getBool(): item["high_value"] = %true
    if obj.enabled != nil and obj.enabled.kind == JBool: item["enabled"] = obj.enabled
    result["matches"].add item
  result["truncated"] = %(ids.len > limit)

proc inspect*(dataset: Dataset; query: string): JsonNode =
  var matches: seq[string]
  for id, obj in dataset.objects:
    if key(query) == id or key(query) == key(obj.name): matches.add id
  if matches.len == 0: raise newException(ValueError, "Object not found; use --search first")
  if matches.len != 1: raise newException(ValueError, "Ambiguous name; use an object identifier")
  let id = matches[0]
  result = %*{"operation": "inspect", "object": objectJson(dataset.objects[id]),
    "memberships": [], "truncated": false}
  var seen = initHashSet[string]()
  seen.incl id
  var queue: seq[tuple[id: string, depth: int]] = @[(id, 0)]
  var cursor = 0
  while cursor < queue.len:
    let current = queue[cursor]
    inc cursor
    var groups = dataset.memberships.getOrDefault(current.id)
    groups.sort()
    for group in groups:
      if group in seen: continue
      if current.depth >= 32 or seen.len >= 1001:
        result["truncated"] = %true
        continue
      seen.incl group
      queue.add (group, current.depth + 1)
      result["memberships"].add %*{"group": objectJson(dataset.objects[group]),
        "depth": current.depth + 1, "via": current.id, "relationship": "MemberOf"}

proc highValueReasons*(obj: BhObject): JsonNode =
  result = newJArray()
  if obj.facts{"highvalue"}.getBool():
    result.add %*{"basis": "recorded", "reason": "Collection marks highvalue=true"}
  if obj.kind == "domains":
    result.add %*{"basis": "inferred", "reason": "Domain infrastructure"}
  if obj.kind != "groups": return
  let parts = obj.id.split('-')
  var validDomainSid = parts.len == 8 and obj.id.startsWith("S-1-5-21-")
  if validDomainSid:
    for i in 4..7:
      if parts[i].len == 0: validDomainSid = false
      for c in parts[i]:
        if c notin {'0'..'9'}: validDomainSid = false
  var reason = ""
  if validDomainSid:
    case parts[^1]
    of "512": reason = "Domain Admins SID"
    of "518": reason = "Schema Admins SID"
    of "519": reason = "Enterprise Admins SID"
    else: discard
  if obj.id == "S-1-5-32-544" or
      (obj.domain.len > 0 and obj.id == key(obj.domain) & "-S-1-5-32-544"):
    reason = "Builtin Administrators SID"
  if reason.len > 0: result.add %*{"basis": "inferred", "reason": reason}

proc highValue*(dataset: Dataset): JsonNode =
  result = %*{"operation": "high-value", "objects": [], "total": 0, "truncated": false}
  var members: Table[string, seq[string]]
  for member, groups in dataset.memberships:
    for group in groups: members.mgetOrPut(group, @[]).add member
  for children in members.mvalues: children.sort()
  proc membershipTree(root: string): JsonNode =
    var expanded = initHashSet[string]()
    var remaining = 60
    proc visit(id, parent: string; depth: int): JsonNode =
      dec remaining
      result = %*{"object": objectJson(dataset.objects[id]), "children": [],
        "repeated": id in expanded, "omitted_children": 0}
      if parent.len > 0:
        result["relationship"] = %*{"source": id, "target": parent, "type": "MemberOf"}
      if id in expanded: return
      expanded.incl id
      if dataset.objects[id].kind != "groups": return
      let children = members.getOrDefault(id)
      for i, child in children:
        if depth >= 6 or remaining <= 0:
          result["omitted_children"] = %(children.len - i)
          break
        result["children"].add visit(child, id, depth + 1)
    result = visit(root, "", 0)
  var ids: seq[string]
  for id in dataset.objects.keys: ids.add id
  ids.sort()
  for id in ids:
    let reasons = highValueReasons(dataset.objects[id])
    if reasons.len == 0: continue
    result["total"] = %(result["total"].getInt() + 1)
    if result["objects"].len < 100:
      let item = objectJson(dataset.objects[id])
      item["evidence"] = reasons
      item["membership_tree"] = membershipTree(id)
      result["objects"].add item
    else: result["truncated"] = %true
  result["warnings"] = %dataset.warnings

proc interesting*(dataset: Dataset): JsonNode =
  result = %*{"operation": "interesting", "high_value": dataset.highValue(),
    "findings": [], "finding_count": 0, "truncated": false,
    "coverage": dataset.coverage, "warnings": dataset.warnings,
    "privileged_accounts": 0, "privileged_members": [], "activity_unknown": 0,
    "snapshot_time": dataset.snapshotTime,
    "time_basis": "Latest timestamp inferred from collection filenames (UTC assumed)",
    "notice": "Review snapshot evidence; missing data does not establish absence of access."}
  # Follow only recorded group membership, never ACL/control relationships.
  var members: Table[string, seq[string]]
  for member, groups in dataset.memberships:
    for group in groups: members.mgetOrPut(group, @[]).add member
  var privileged = initHashSet[string]()
  var queue: seq[string]
  for id, obj in dataset.objects:
    if highValueReasons(obj).len > 0:
      privileged.incl id
      if obj.kind == "groups": queue.add id
  var cursor = 0
  while cursor < queue.len:
    let group = queue[cursor]
    inc cursor
    for member in members.getOrDefault(group):
      if member notin privileged:
        privileged.incl member
        if dataset.objects[member].kind == "groups": queue.add member
  var ids: seq[string]
  for id in dataset.objects.keys: ids.add id
  ids.sort()
  for id in ids:
    let obj = dataset.objects[id]
    if obj.kind notin ["users", "computers"]: continue
    if id in privileged:
      result["privileged_accounts"] = %(result["privileged_accounts"].getInt() + 1)
      if result["privileged_members"].len < 100:
        let item = objectJson(obj)
        item["basis"] = %"Critical-object classification or recorded direct/nested membership in a classified group"
        result["privileged_members"].add item
    let logon = obj.facts{"lastlogontimestamp"}.getBiggestInt()
    if dataset.snapshotTime == 0 or logon <= 0 or logon > dataset.snapshotTime:
      result["activity_unknown"] = %(result["activity_unknown"].getInt() + 1)
    var reasons = newJArray()
    if id in privileged and obj.enabled != nil and obj.enabled.kind == JBool and not obj.enabled.getBool():
      reasons.add %*{"basis": "recorded", "reason": "Disabled account retains critical classification or group membership",
        "review": "Verify ownership and remove obsolete privileged membership through change control."}
    if obj.facts{"passwordnotreqd"}.getBool():
      reasons.add %*{"basis": "recorded", "reason": "Password-not-required flag is set (not proof of an empty password)",
        "review": "Confirm the account's password policy and remove unnecessary exceptions."}
    if obj.facts{"pwdneverexpires"}.getBool():
      reasons.add %*{"basis": "recorded", "reason": "Password-expiry exception is recorded",
        "review": "Verify an approved exception and managed credential rotation."}
    if dataset.snapshotTime > 0 and logon > 0 and logon <= dataset.snapshotTime and
        dataset.snapshotTime - logon > 90'i64 * 86400:
      reasons.add %*{"basis": "inferred", "reason": "Recorded logon timestamp predates the inferred collection date by over 90 days",
        "review": "Confirm activity in authoritative logs before changing the account."}
    if reasons.len > 0:
      result["finding_count"] = %(result["finding_count"].getInt() + reasons.len)
      if result["findings"].len < 100:
        result["findings"].add %*{"object": objectJson(obj), "privileged": id in privileged, "evidence": reasons}
      else: result["truncated"] = %true

proc toGraph*(dataset: Dataset): Graph =
  var interestingIds = initHashSet[string]()
  var members = initTable[string, seq[string]]()
  for member, groups in dataset.memberships:
    for group in groups: members.mgetOrPut(group, @[]).add member
  var queue: seq[string]
  for id, obj in dataset.objects:
    if highValueReasons(obj).len > 0:
      interestingIds.incl id
      queue.add id
  var cursor = 0
  while cursor < queue.len:
    let id = queue[cursor]
    inc cursor
    for member in members.getOrDefault(id):
      if member notin interestingIds:
        interestingIds.incl member
        queue.add member
  for id, obj in dataset.objects:
    let logon = obj.facts{"lastlogontimestamp"}.getBiggestInt()
    let stale = dataset.snapshotTime > 0 and logon > 0 and logon <= dataset.snapshotTime and
      dataset.snapshotTime-logon > 90'i64*86400
    result.nodes[id] = GraphNode(id: id, name: obj.name, kind: obj.kind,
      domainSid: obj.facts{"domainsid"}.getStr(), hasLaps: obj.facts{"haslaps"}.getBool(),
      highValue: highValueReasons(obj).len > 0,
      interesting: id in interestingIds or (obj.kind in ["users", "computers"] and
        (stale or obj.facts{"passwordnotreqd"}.getBool() or obj.facts{"pwdneverexpires"}.getBool())))
  result.edges = dataset.edges
  for e in result.edges:
    for id in [e.source, e.target]:
      if id notin result.nodes:
        result.nodes[id] = dataset.references.getOrDefault(id,
          GraphNode(id: id, name: id, kind: "unknown"))
        result.nodes[id].unresolved = true
  result.warnings = dataset.warnings
  result.deriveReplicationRights()

proc terminalSafe(s: string): string =
  for c in s:
    if c == '\n' or (ord(c) >= 32 and ord(c) != 127): result.add c

proc renderText*(report: JsonNode; color = false; membershipTrees = true): string =
  proc clean(s: string): string =
    for r in s.toRunes:
      let n = int(r)
      if n >= 32 and n notin 127..159 and n notin 0x202a..0x202e and n notin 0x2066..0x2069:
        result.add $r
  proc paint(s, code: string): string =
    if color: "\e[" & code & "m" & s & "\e[0m" else: s
  var lines: seq[string]
  proc border(label: string; top = false) =
    let safe = clean(label)
    let lead = if top: "┌─ " else: "├─ "
    lines.add paint(lead, "90") & paint(safe, "1;36") & paint(" " & repeat("─", max(3, 74 - safe.runeLen)), "90")
  proc row(label, value: string; code = "37") =
    # Wrap untrusted values by Unicode characters before adding ANSI styling.
    let chars = clean(value).toRunes
    var offset = 0
    while offset < max(1, chars.len):
      var finish = min(chars.len, offset + 53)
      if finish < chars.len:
        for j in countdown(finish - 1, offset + 20):
          if chars[j] == Rune(32):
            finish = j + 1
            break
      var chunk = ""
      for i in offset..<finish: chunk.add $chars[i]
      lines.add paint("│  ", "90") & paint(strutils.alignLeft(if offset == 0: clean(label) else: "", 20), "2") & paint(chunk, code)
      offset = max(offset + 1, finish)
  proc showHigh(value: JsonNode) =
    border((if membershipTrees: "High-value membership graphs  " else: "High-value objects  ") & $value["total"].getInt())
    if membershipTrees:
      row("read the graph", "Each indented node is a member of the group above it.")
      row("relationship", "MemberOf: account/group -> parent group.", "2")
    proc treeLine(prefix, continuation, label: string; code = "1;36") =
      let chars = clean(label).toRunes
      let width = max(12, 73 - prefix.runeLen)
      var offset = 0
      while offset < max(1, chars.len):
        let finish = min(chars.len, offset + width)
        var chunk = ""
        for i in offset..<finish: chunk.add $chars[i]
        lines.add paint("│  " & (if offset == 0: prefix else: continuation), "90") & paint(chunk, code)
        offset = max(offset + 1, finish)
    proc drawChildren(tree: JsonNode; indent: string) =
      let omitted = tree["omitted_children"].getInt()
      for i in 0..<tree["children"].len:
        let child = tree["children"][i]
        let last = i == tree["children"].len - 1 and omitted == 0
        let branch = if last: "└─ " else: "├─ "
        let nextIndent = indent & (if last: "   " else: "│  ")
        let obj = child["object"]
        let suffix = if child["repeated"].getBool(): " [already shown]" else: ""
        treeLine(indent & branch, nextIndent, "[MemberOf] " & obj["name"].getStr() &
          " [" & obj["type"].getStr() & "]" & suffix)
        drawChildren(child, nextIndent)
      if omitted > 0:
        treeLine(indent & "└─ ", indent & "   ", $omitted &
          " direct members omitted (graph limit: 6 levels / 60 nodes)", "33")
    for obj in value["objects"]:
      lines.add paint("│", "90")
      treeLine("", "", "[HIGH VALUE] " & obj["name"].getStr() & " [" & obj["type"].getStr() & "]")
      for evidence in obj["evidence"]:
        row(evidence["basis"].getStr(), evidence["reason"].getStr())
      if membershipTrees:
        let tree = obj["membership_tree"]
        drawChildren(tree, "")
        if obj["type"].getStr() != "groups":
          treeLine("└─ ", "   ", "Classified object; group membership tree not applicable.", "2")
        elif tree["children"].len == 0:
          treeLine("└─ ", "   ", "No resolved members recorded in this dataset.", "2")
    if value["total"].getInt() == 0: row("result", "No high-value classifications in this dataset.")
    if value["truncated"].getBool(): row("limit", "Showing first 100 objects.", "33")
  proc showCoverage() =
    border("Collection coverage")
    for field, coverage in report["coverage"]:
      row(field, $coverage["collected"].getInt() & " collected / " &
        $coverage["not_collected"].getInt() & " not collected / " & $coverage["unknown"].getInt() & " unknown",
        if coverage["not_collected"].getInt() + coverage["unknown"].getInt() > 0: "33" else: "32")
  border("BLOODHOUND  offline", true)
  row("operation", report["operation"].getStr(), "1;36")
  if report{"archive"} != nil: row("archive", report["archive"].getStr())
  case report["operation"].getStr()
  of "summary":
    border("Inventory")
    row("objects", $report["objects"].getInt(), "1;36")
    for kind, count in report["counts"]:
      row(kind, $count.getInt())
    row("memberships", $report["membership_edges"].getInt())
    row("graph evidence", $report["recorded_graph_edges"].getInt())
    showCoverage()
  of "high-value": showHigh(report)
  of "interesting":
    row("privileged accts", $report["privileged_accounts"].getInt())
    row("activity unknown", $report["activity_unknown"].getInt(), "33")
    showHigh(report["high_value"])
    border("Privileged account review")
    for obj in report["privileged_members"]:
      row(obj["type"].getStr(), obj["name"].getStr(), "1;36")
      row("enabled", if obj{"enabled"} == nil: "unknown" else: $obj["enabled"].getBool())
      row("basis", obj["basis"].getStr(), "2")
    if report["privileged_accounts"].getInt() == 0: row("result", "No classified accounts or group members recorded.")
    if report["privileged_accounts"].getInt() > 100: row("limit", "Showing first 100 accounts.", "33")
    border("Account hygiene  " & $report["finding_count"].getInt() & " observations")
    for finding in report["findings"]:
      row("account", finding["object"]["name"].getStr(), "1;36")
      for evidence in finding["evidence"]:
        row(evidence["basis"].getStr(), evidence["reason"].getStr(), "33")
        row("review", evidence["review"].getStr())
    if report["findings"].len == 0: row("result", "No supported hygiene findings in this dataset.")
    if report["truncated"].getBool(): row("limit", "Showing first 100 accounts.", "33")
    if report["snapshot_time"].getBiggestInt() > 0:
      row("date basis", report["time_basis"].getStr(), "2")
    else: row("date basis", "Unknown; stale-activity classification skipped.", "33")
    showCoverage()
  of "search":
    border("Search  " & $report["total"].getInt() & " matches")
    for obj in report["matches"]:
      row(obj["type"].getStr(), obj["name"].getStr(), "1;36")
      row("id", obj["id"].getStr(), "2")
    if report["truncated"].getBool(): row("limit", "First 100 matches; refine your search.", "33")
  of "list":
    let filterNote = if report["filter"].getStr().len > 0: " (filter: " & report["filter"].getStr() & ")" else: ""
    border(report["kind"].getStr() & "  " & $report["total"].getInt() & filterNote)
    for obj in report["matches"]:
      let hv = if obj{"high_value"}.getBool(): " [HIGH VALUE]" else: ""
      let enabled = if obj{"enabled"} != nil and not obj["enabled"].getBool(): " [DISABLED]" else: ""
      row(obj["id"].getStr(), obj["name"].getStr() & hv & enabled, "1;36")
    if report["truncated"].getBool(): row("limit", "First 1000 results; use --filter to narrow.", "33")
  of "inspect":
    let obj = report["object"]
    row(obj["type"].getStr(), obj["name"].getStr(), "1;36")
    row("id", obj["id"].getStr(), "2")
    border("Group memberships")
    for item in report["memberships"]:
      row("depth " & $item["depth"].getInt(), item["group"]["name"].getStr(), "1;36")
      row("via", item["via"].getStr(), "2")
    if report["memberships"].len == 0: row("result", "None found in this dataset.")
    if report["truncated"].getBool(): row("limit", "Results truncated at depth/object limit.", "33")
  of "diff":
    row("baseline", report["archives"][0].getStr())
    row("comparison", report["archives"][1].getStr())
    row("added edges", $report["added_count"].getInt(),
        if report["added_count"].getInt() > 0: "33" else: "32")
    row("removed edges", $report["removed_count"].getInt(),
        if report["removed_count"].getInt() > 0: "33" else: "32")
    border("New relationships")
    for e in report["added_edges"]:
      row(e["kind"].getStr(), e["source"].getStr() & " -> " & e["target"].getStr(), "33")
    if report["added_edges"].len == 0: row("result", "No new relationships.")
    border("Removed relationships")
    for e in report["removed_edges"]:
      row(e["kind"].getStr(), e["source"].getStr() & " -> " & e["target"].getStr(), "2")
    if report["removed_edges"].len == 0: row("result", "No removed relationships.")
    if report["added_objects"].len > 0:
      border("New objects")
      for o in report["added_objects"]:
        row(o["kind"].getStr(), o["name"].getStr(), "33")
    if report["removed_objects"].len > 0:
      border("Removed objects")
      for o in report["removed_objects"]:
        row(o["kind"].getStr(), o["name"].getStr(), "2")
  if report{"warnings"} != nil and report["warnings"].len > 0:
    border("Data quality")
    for warning in report["warnings"]: row("note", warning.getStr(), "33")
  if report{"notice"} != nil: row("snapshot", report["notice"].getStr(), "2")
  lines.add paint("└" & repeat("─", 77), "90")
  result = lines.join("\n") & "\n"

proc diffDatasets*(a, b: Dataset; archiveA, archiveB: string): JsonNode =
  result = %*{"operation": "diff", "archives": [archiveA, archiveB],
              "added_edges": [], "removed_edges": [],
              "added_objects": [], "removed_objects": [],
              "added_count": 0, "removed_count": 0, "warnings": []}
  var aKeys = initHashSet[string]()
  var bKeys = initHashSet[string]()
  for e in a.edges: aKeys.incl edgeKey(e)
  for e in b.edges: bKeys.incl edgeKey(e)
  for e in b.edges:
    if edgeKey(e) notin aKeys:
      result["added_edges"].add %*{"source": e.source, "target": e.target,
                                   "kind": e.kind, "evidence": e.evidence}
      result["added_count"] = %(result["added_count"].getInt() + 1)
  for e in a.edges:
    if edgeKey(e) notin bKeys:
      result["removed_edges"].add %*{"source": e.source, "target": e.target,
                                     "kind": e.kind, "evidence": e.evidence}
      result["removed_count"] = %(result["removed_count"].getInt() + 1)
  for id, obj in b.objects:
    if id notin a.objects:
      result["added_objects"].add %*{"id": id, "name": obj.name, "kind": obj.kind}
  for id, obj in a.objects:
    if id notin b.objects:
      result["removed_objects"].add %*{"id": id, "name": obj.name, "kind": obj.kind}
  for w in a.warnings: result["warnings"].add %w
  for w in b.warnings: result["warnings"].add %w

const bhHelp* = """Offline BloodHound inventory (ZIP, JSON schema v5/v6)
Usage: nimux bh <archive.zip> [--summary | --interesting | --high-value |
       --search <text> | --inspect <name-or-id>] [--graph] [--json] [--no-color]
  --interesting  Review inventory + paths from non-privileged principals to high-value targets
  --high-value   High-value inventory + shortest paths from other principals
  --users        List all user accounts (add --filter <text> to narrow by name)
  --computers    List all computer accounts
  --groups       List all groups
  --gpos         List all GPOs
  --ous          List all OUs
  --containers   List all containers
  --filter <s>   Name filter for --users/--computers/--groups/--gpos/--ous/--containers
  --graph        Print graph only; combine with a preset/search/inspection
  --user <name>  Scope findings to one user (short/full name or identifier)
  --computer <name>  Scope findings to one computer (short name/FQDN or identifier)
  --group <name> Scope findings to one group (short/full name or identifier)
                 Use one selector; combine with --interesting, --high-value or --to.
                 Alone: incident relationships. Selectors imply --graph (text only).
  --from <spec>  Source: exact name/id, comma-separated list, or @file (one per line)
  --owned <spec> Like --from but labels sources as owned/compromised; mutually exclusive with --from
  --to <id>      Exact target name or identifier; may be combined with --from/--owned
  --chain        Annotate each graph edge with the nimux command to exploit it (implies --graph)
  --diff <zip>   Compare two archives: show added/removed relationships and objects
  --limit <n>    Output paths/relationships (default 50; 0 = all, subject to safety limits)
  --depth <n>    Path search depth (default 0 = unbounded, cycle-safe)
Text --interesting/--high-value include a static graph automatically.
--graph --json exports paths as structured JSON (compatible with --from/--owned/--to).
No interaction, terminal screen switching, or external viewer. Output can be piped.
Each finding shows a named left-to-right path and a plain-language explanation.
Path queries search the full imported graph BEFORE limiting output; equal shortest paths retained.
Plain --graph / --inspect --graph lists recorded edges without inventing chains.
No effective-access guarantee. DCSync/SyncLAPSPassword are derived using Legacy rules,
with supporting permission paths shown. Individual replication rights are not standalone path hops.
Full BloodHound query compatibility is not implemented.
Safety: at most 1000 targets, 2M reachable pairs, 20M reverse edge visits, 100000 output paths.
Default: --summary. Inspection includes direct and nested group memberships.
No network connections. JSON output omits raw object properties and secrets.
Limits: 32 MiB archive/JSON entry, 128 MiB total JSON, 1024 entries;
deflated entries: at most 128 KiB compressed. ZIP64/encrypted ZIP unsupported.
"""

proc runBh*(args: seq[string]) =
  if args.len == 0 or args == @["--help"] or args == @["-h"]:
    echo bhHelp
    return
  let path = args[0]
  var action = "summary"
  var query = ""
  var fromQueries, ownedQueries: seq[string]
  var toQuery: string
  var selectorKind, selectorValue: string
  var graphLimit = 50
  var graphDepth = 0
  var jsonOutput, selected, noColor, graphView, chainMode: bool
  var diffPath, listKind, listFilter: string

  proc parseSpec(v: string): seq[string] =
    if v.startsWith("@"):
      for line in readFile(v[1..^1]).splitLines():
        let t = line.strip()
        if t.len > 0: result.add t
    elif ',' in v:
      for part in v.split(','):
        let t = part.strip()
        if t.len > 0: result.add t
    else:
      result.add v

  var i = 1
  while i < args.len:
    case args[i]
    of "--json": jsonOutput = true
    of "--no-color": noColor = true
    of "--graph": graphView = true
    of "--chain": chainMode = true; graphView = true
    of "--user", "--computer", "--group":
      if selectorKind.len > 0: raise newException(ValueError, "Choose only one --user, --computer or --group selector")
      selectorKind = args[i][2..^1] & "s"
      inc i
      if i >= args.len or args[i].startsWith("--"):
        raise newException(ValueError, "Missing object name for typed selector")
      selectorValue = args[i]
      graphView = true
    of "--from", "--to", "--limit", "--depth", "--owned", "--diff":
      let option = args[i]
      inc i
      if i >= args.len: raise newException(ValueError, "Missing value for " & option)
      case option
      of "--from":
        if ownedQueries.len > 0: raise newException(ValueError, "--from and --owned are mutually exclusive")
        for q in parseSpec(args[i]): fromQueries.add q
        graphView = true
      of "--owned":
        if fromQueries.len > 0: raise newException(ValueError, "--from and --owned are mutually exclusive")
        for q in parseSpec(args[i]): ownedQueries.add q
        graphView = true
      of "--to": toQuery = args[i]; graphView = true
      of "--diff": diffPath = args[i]
      of "--limit":
        graphLimit = parseInt(args[i])
        if graphLimit < 0 or graphLimit > 100000: raise newException(ValueError, "--limit must be 0..100000")
      else:
        graphDepth = parseInt(args[i])
        if graphDepth < 0 or graphDepth > 200000: raise newException(ValueError, "--depth must be 0..200000")
    of "--users", "--computers", "--groups", "--containers", "--gpos", "--ous":
      if selected: raise newException(ValueError, "Choose one bh operation")
      selected = true
      action = "list"
      listKind = args[i][2..^1]
    of "--filter":
      inc i
      if i >= args.len: raise newException(ValueError, "Missing value for --filter")
      listFilter = args[i]
    of "--summary", "--search", "--inspect", "--interesting", "--high-value":
      if selected: raise newException(ValueError, "Choose one bh operation")
      selected = true
      action = args[i][2 .. ^1]
      if action in ["search", "inspect"]:
        inc i
        if i >= args.len: raise newException(ValueError, "Missing query")
        query = args[i]
    of "--help", "-h":
      echo bhHelp
      return
    else: raise newException(ValueError, "Unknown bh option: " & args[i])
    inc i

  if selectorKind.len > 0:
    if fromQueries.len > 0 or ownedQueries.len > 0:
      raise newException(ValueError, "Typed selectors cannot be combined with --from/--owned; use --to for a destination")
    if selected and action notin ["interesting", "high-value"]:
      raise newException(ValueError, "Typed selectors support --interesting, --high-value, --to, or no operation (incident relationships)")
  if graphDepth > 0 and action notin ["interesting", "high-value"] and
      fromQueries.len == 0 and ownedQueries.len == 0 and toQuery.len == 0:
    raise newException(ValueError, "--depth requires --interesting, --high-value, --from, --owned or --to")

  let dataset = loadDataset(path)
  let useColor = not noColor and not existsEnv("NO_COLOR") and isatty(stdout)

  if diffPath.len > 0:
    let dataset2 = loadDataset(diffPath)
    let report = diffDatasets(dataset, dataset2, extractFilename(path), extractFilename(diffPath))
    if jsonOutput: echo $report
    else: stdout.write renderText(report, useColor)
    return

  proc buildSources(g: Graph; resolve: proc(v: string): string): seq[string] =
    let privileged = g.privilegedMembers()
    for id, n in g.nodes:
      if not n.unresolved and n.kind in ["users", "groups", "computers"] and not n.highValue:
        if action != "interesting" or id notin privileged: result.add id
    if fromQueries.len > 0:
      result = @[]
      for q in fromQueries: result.add resolve(q)
    elif ownedQueries.len > 0:
      result = @[]
      for q in ownedQueries: result.add resolve(q)

  proc sourceLabel(): string =
    if fromQueries.len > 0:
      "specified principal" & (if fromQueries.len > 1: "s (" & $fromQueries.len & ")" else: "")
    elif ownedQueries.len > 0:
      "owned principal" & (if ownedQueries.len > 1: "s (" & $ownedQueries.len & ")" else: "")
    else: "selected principals"

  proc graphOutput(): string =
    let g = dataset.toGraph()
    let selectorId = if selectorKind.len > 0: g.resolveTyped(selectorValue, selectorKind) else: ""
    let selectorNote = if selectorId.len > 0:
      "Selected " & selectorKind & ": " & safe(g.nodes[selectorId].name) & "\n" else: ""
    proc resolve(value: string): string =
      for id, n in g.nodes:
        if key(value) == id: return id
      for id, n in g.nodes:
        if key(value) == key(n.name):
          if result.len > 0: raise newException(ValueError, "Ambiguous graph name; use the object identifier")
          result = id
      if result.len == 0: raise newException(ValueError, "Graph object not found: " & value)
    let isPathQuery = action in ["interesting", "high-value"] or
        fromQueries.len > 0 or ownedQueries.len > 0 or toQuery.len > 0
    if isPathQuery:
      var sources = buildSources(g, resolve)
      var targets: seq[string]
      for id, n in g.nodes:
        if n.highValue: targets.add id
      if selectorId.len > 0: sources = @[selectorId]
      if toQuery.len > 0: targets = @[resolve(toQuery)]
      sources.sort(); targets.sort()
      let report = shortestPaths(g, sources, targets, graphLimit, graphDepth)
      let lbl = if selectorId.len > 0: "specified principal" else: sourceLabel()
      result = selectorNote & "Path query: " & lbl &
        " to " & (if toQuery.len > 0: "specified target" else: "high-value objects") & ".\n"
      result.add "Depth: " & (if graphDepth == 0: "unbounded (cycle-safe)" else: $graphDepth) &
        "; Legacy replication-right derivation enabled (DCSync / SyncLAPSPassword).\n"
      result.add renderGraph(g, sources, useColor, graphLimit, report.paths, true,
        report.reachablePairs, report.truncated, chainMode)
      if toQuery.len == 0 and (ownedQueries.len > 0 or action in ["interesting", "high-value"]):
        result.add "\nDirect rights on non-high-value objects:\n"
        result.add renderGraph(g, sources, useColor, graphLimit,
          chain = chainMode, controlOnly = true)
      return
    var seeds: seq[string]
    if selectorId.len > 0:
      seeds = @[selectorId]
    elif action == "inspect":
      seeds = @[dataset.inspect(query)["object"]["id"].getStr()]
    else:
      seeds = g.matching(query, (if action in ["interesting", "high-value"]: action else: "all"))
    seeds.sort()
    selectorNote & renderGraph(g, seeds, useColor, graphLimit, chain = chainMode)

  proc graphOutputJson(): string =
    let g = dataset.toGraph()
    proc resolve(value: string): string =
      for id, n in g.nodes:
        if key(value) == id: return id
      for id, n in g.nodes:
        if key(value) == key(n.name):
          if result.len > 0: raise newException(ValueError, "Ambiguous graph name; use the object identifier")
          result = id
      if result.len == 0: raise newException(ValueError, "Graph object not found: " & value)
    var sources = buildSources(g, resolve)
    var targets: seq[string]
    for id, n in g.nodes:
      if n.highValue: targets.add id
    if toQuery.len > 0: targets = @[resolve(toQuery)]
    sources.sort(); targets.sort()
    let report = shortestPaths(g, sources, targets, graphLimit, graphDepth)
    $renderGraphJson(g, report.paths, report.reachablePairs, report.truncated)

  if graphView and jsonOutput:
    echo graphOutputJson()
    return
  if graphView:
    stdout.write graphOutput()
    return
  let report = case action
    of "interesting": dataset.interesting()
    of "high-value": dataset.highValue()
    of "search": dataset.search(query)
    of "inspect": dataset.inspect(query)
    of "list": dataset.list(listKind, listFilter)
    else: dataset.summary()
  report["archive"] = %extractFilename(path)
  if jsonOutput: echo $report
  else:
    stdout.write renderText(report, useColor, membershipTrees=false)
    if action in ["high-value", "interesting"]: stdout.write graphOutput()

when isMainModule:
  try: runBh(commandLineParams())
  except CatchableError as error:
    stderr.writeLine "error: " & terminalSafe(error.msg)
    quit 1
