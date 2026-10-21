## Recorded relationships only. No derived permissions or live queries.
import std/[strutils, tables]

type
  GraphNode* = object
    id*, name*, kind*: string
    highValue*, interesting*: bool
    unresolved*: bool
    domainSid*: string
    hasLaps*: bool
  GraphEdge* = object
    source*, target*, kind*, evidence*: string
    derived*: bool
    support*: seq[seq[int]]
  Graph* = object
    nodes*: OrderedTable[string, GraphNode]
    edges*: seq[GraphEdge]
    warnings*: seq[string]

proc safe*(s: string): string =
  ## ASCII display prevents terminal controls, bidi controls and width ambiguity.
  for c in s:
    if c >= ' ' and c <= '~': result.add c
    elif ord(c) >= 128: result.add '?'

proc edgeKey*(e: GraphEdge): string =
  e.source & "\x00" & e.target & "\x00" & e.kind & "\x00" & e.evidence

proc matching*(g: Graph; query, preset: string): seq[string] =
  for id, n in g.nodes:
    if preset == "high-value" and not n.highValue: continue
    if preset == "interesting" and not n.interesting: continue
    if query.toUpperAscii() in (n.name & " " & id).toUpperAscii(): result.add id

proc incident*(g: Graph; id, filter: string): seq[int] =
  for i, e in g.edges:
    if (e.source == id or e.target == id) and
        (filter.len == 0 or e.kind == filter): result.add i

proc resolveTyped*(g: Graph; value, kind: string): string =
  ## Exact identity or exact short name, never a substring or first-match guess.
  let query = value.toUpperAscii()
  if query.len == 0: raise newException(ValueError, "Object selector cannot be empty")
  if query in g.nodes and g.nodes[query].kind == kind: return query
  var matches: seq[string]
  for id, n in g.nodes:
    if n.kind != kind: continue
    let full = n.name.toUpperAscii()
    var short = full.split('@')[0]
    var shortQuery = query
    if kind == "computers":
      short = short.split('.')[0].strip(chars={'$'})
      shortQuery = shortQuery.strip(chars={'$'})
    if query == full or shortQuery == short:
      matches.add id
  if matches.len == 0:
    raise newException(ValueError, "No " & kind & " object matches: " & value)
  if matches.len > 1:
    raise newException(ValueError, "Ambiguous " & kind & " name: " & value & "; use a full name or object identifier")
  matches[0]
