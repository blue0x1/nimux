import std/[asyncdispatch, asyncnet, base64, net, os, sequtils, strutils]
import ../../core/proxy as netproxy

type
  WebDavResult* = object
    host*:          string
    port*:          int
    ssl*:           bool
    reachable*:     bool
    davSupported*:  bool
    davClasses*:    seq[string]
    server*:        string
    authenticated*: bool
    authMessage*:   string
    listing*:       seq[string]

  WebDavEntry* = object
    href*: string
    name*: string
    isDirectory*: bool

proc recvHttpResponse(sock: AsyncSocket; timeoutMs: int): Future[tuple[status: int; headers, body: string]] {.async.} =
  var raw = ""
  while true:
    let f = sock.recv(4096)
    if not await withTimeout(f, timeoutMs): break
    let chunk = await f
    if chunk.len == 0: break
    raw.add chunk
    if "\r\n\r\n" in raw: break
  let split = raw.find("\r\n\r\n")
  let hdrs = if split >= 0: raw[0 ..< split] else: raw
  var body = if split >= 0: raw[split + 4 .. ^1] else: ""
  var status = 0
  let firstLine = hdrs.splitLines()[0]
  let parts = firstLine.splitWhitespace()
  if parts.len >= 2:
    try: status = parseInt(parts[1]) except: discard
  var contentLength = -1
  for line in hdrs.splitLines():
    if line.toLowerAscii().startsWith("content-length:"):
      try: contentLength = parseInt(line[16..^1].strip()) except: discard
  if contentLength > 0:
    while body.len < contentLength:
      let f = sock.recv(contentLength - body.len)
      if not await withTimeout(f, timeoutMs): break
      let chunk = await f
      if chunk.len == 0: break
      body.add chunk
  result = (status, hdrs, body)

proc headerVal(hdrs, name: string): string =
  let lower = name.toLowerAscii() & ":"
  for line in hdrs.splitLines():
    if line.toLowerAscii().startsWith(lower):
      return line[name.len + 1 .. ^1].strip()

proc webDavNormalizePath*(path: string; wantCollection = false): string =
  var p = if path.len == 0: "/" else: path
  if not p.startsWith("/"):
    p = "/" & p
  if wantCollection and not p.endsWith("/"):
    p.add '/'
  if not wantCollection and p.len > 1 and p.endsWith("/"):
    p.setLen(p.len - 1)
  p

proc webDavResolveRedirect(location, currentPath: string): string =
  if location.len == 0:
    return currentPath
  let lower = location.toLowerAscii()
  if lower.startsWith("http://") or lower.startsWith("https://"):
    let schemeSplit = location.find("://")
    let pathStart = location.find('/', schemeSplit + 3)
    if pathStart >= 0:
      return location[pathStart .. ^1]
    return "/"
  if location.startsWith("/"):
    return location
  let base =
    if currentPath.endsWith("/"): currentPath
    else:
      let slash = currentPath.rfind('/')
      if slash >= 0: currentPath[0 .. slash] else: "/"
  base & location

proc parsePropfindListing(body: string): seq[string] =
  var pos = 0
  while true:
    let s = body.find("<d:href>", pos)
    let s2 = body.find("<D:href>", pos)
    let start = if s >= 0 and (s2 < 0 or s < s2): s else: s2
    if start < 0: break
    let tagEnd = body.find(">", start) + 1
    let closeS = body.find("</", tagEnd)
    if closeS < 0: break
    let href = body[tagEnd ..< closeS].strip()
    if href.len > 0: result.add href
    pos = closeS + 1

proc parsePropfindEntries(body: string): seq[WebDavEntry] =
  var pos = 0
  while true:
    let lowerStart = body.find("<d:response", pos)
    let upperStart = body.find("<D:response", pos)
    let start =
      if lowerStart >= 0 and (upperStart < 0 or lowerStart < upperStart): lowerStart
      else: upperStart
    if start < 0:
      break
    let lowerFinish = body.find("</d:response>", start)
    let upperFinish = body.find("</D:response>", start)
    let finish =
      if lowerFinish >= 0 and (upperFinish < 0 or lowerFinish < upperFinish): lowerFinish
      else: upperFinish
    if finish < 0:
      break
    let chunk = body[start ..< finish]
    var href = ""
    let hs = max(chunk.find("<d:href>"), chunk.find("<D:href>"))
    if hs >= 0:
      let tagEnd = chunk.find(">", hs) + 1
      let closeS = chunk.find("</", tagEnd)
      if closeS > tagEnd:
        href = chunk[tagEnd ..< closeS].strip()
    var isDir = chunk.contains("<d:collection/>") or chunk.contains("<D:collection/>")
    if href.len > 0:
      let trimmed = href.strip(chars={'/'})
      let name =
        if trimmed.len == 0: "/"
        elif "/" in trimmed: trimmed.split('/')[^1]
        else: trimmed
      result.add WebDavEntry(href: href, name: name, isDirectory: isDir)
    pos = finish + 1

proc webDavRequest(host: string; port, timeoutMs: int; ssl: bool;
                   username, password, httpMethod, path: string;
                   extraHeaders = ""; body = ""): Future[tuple[status: int; headers, body: string]] {.async.} =
  var currentPath = path
  for _ in 0 .. 4:
    let sock = newAsyncSocket(buffered = false)
    try:
      let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
      if not ok:
        return (0, "", "")
      if ssl:
        let ctx = newContext(verifyMode = CVerifyNone)
        ctx.wrapSocket(sock)
      let hostHdr = if (ssl and port == 443) or (not ssl and port == 80):
                      host else: host & ":" & $port
      let authHdr = if username.len > 0:
        "Authorization: Basic " & base64.encode(username & ":" & password) & "\r\n"
      else:
        ""
      let req =
        httpMethod & " " & currentPath & " HTTP/1.1\r\nHost: " & hostHdr & "\r\n" &
        authHdr & extraHeaders &
        "Content-Length: " & $body.len & "\r\nConnection: close\r\n\r\n" & body
      await sock.send(req)
      let resp = await recvHttpResponse(sock, timeoutMs)
      if resp.status in [301, 302, 307, 308]:
        let location = headerVal(resp.headers, "Location")
        let nextPath = webDavResolveRedirect(location, currentPath)
        if nextPath == currentPath:
          return resp
        currentPath = nextPath
        continue
      return resp
    finally:
      try: sock.close() except: discard
  result = (0, "", "")

proc webDavList*(host: string; port, timeoutMs: int; ssl: bool;
                 username, password, path: string): Future[tuple[ok: bool; entries: seq[WebDavEntry]; message: string]] {.async.} =
  let normalizedPath = webDavNormalizePath(path, wantCollection = true)
  let body = """<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:resourcetype/></d:prop></d:propfind>"""
  let (status, _, respBody) = await webDavRequest(host, port, timeoutMs, ssl, username, password,
    "PROPFIND", normalizedPath, "Depth: 1\r\nContent-Type: application/xml\r\n", body)
  if status != 207:
    return (false, @[], "PROPFIND returned " & $status)
  let entries = parsePropfindEntries(respBody).filterIt(it.href != normalizedPath and it.name != "")
  result = (true, entries, "")

proc webDavMkdir*(host: string; port, timeoutMs: int; ssl: bool;
                  username, password, path: string): Future[tuple[ok: bool; message: string]] {.async.} =
  let (status, _, _) = await webDavRequest(host, port, timeoutMs, ssl, username, password, "MKCOL",
    webDavNormalizePath(path, wantCollection = true))
  result = (status in [200, 201, 204, 405], if status in [200, 201, 204, 405]: "" else: "MKCOL returned " & $status)

proc webDavDelete*(host: string; port, timeoutMs: int; ssl: bool;
                   username, password, path: string): Future[tuple[ok: bool; message: string]] {.async.} =
  let (status, _, _) = await webDavRequest(host, port, timeoutMs, ssl, username, password, "DELETE", path)
  result = (status in [200, 202, 204], if status in [200, 202, 204]: "" else: "DELETE returned " & $status)

proc webDavGet*(host: string; port, timeoutMs: int; ssl: bool;
                username, password, path, localPath: string): Future[tuple[ok: bool; bytesRead: int; message: string]] {.async.} =
  let (status, _, body) = await webDavRequest(host, port, timeoutMs, ssl, username, password, "GET", path)
  if status != 200:
    return (false, 0, "GET returned " & $status)
  writeFile(localPath, body)
  result = (true, body.len, "")

proc webDavPut*(host: string; port, timeoutMs: int; ssl: bool;
                username, password, localPath, remotePath: string): Future[tuple[ok: bool; bytesWritten: int; message: string]] {.async.} =
  if not fileExists(localPath):
    return (false, 0, "local file not found")
  let body = readFile(localPath)
  let (status, _, _) = await webDavRequest(host, port, timeoutMs, ssl, username, password,
    "PUT", remotePath, "Content-Type: application/octet-stream\r\n", body)
  result = (status in [200, 201, 204], body.len, if status in [200, 201, 204]: "" else: "PUT returned " & $status)

proc probeWebDav*(host: string; port, timeoutMs: int; ssl: bool;
                  username, password: string): Future[WebDavResult] {.async.} =
  result.host = host
  result.port = port
  result.ssl = ssl
  let sock = newAsyncSocket(buffered = false)
  try:
    let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
    if not ok: sock.close(); return
  except: sock.close(); return
  result.reachable = true
  try:
    if ssl:
      let ctx = newContext(verifyMode = CVerifyNone)
      ctx.wrapSocket(sock)

    let hostHdr = if (ssl and port == 443) or (not ssl and port == 80):
                    host else: host & ":" & $port
    let authHdr = if username.len > 0:
                    "Authorization: Basic " & base64.encode(username & ":" & password) & "\r\n"
                  else: ""

    await sock.send(
      "OPTIONS / HTTP/1.1\r\nHost: " & hostHdr & "\r\n" &
      authHdr & "Connection: keep-alive\r\n\r\n")
    let (_, optHdrs, _) = await recvHttpResponse(sock, timeoutMs)

    result.server = headerVal(optHdrs, "Server")
    let dav = headerVal(optHdrs, "DAV")
    if dav.len > 0:
      result.davSupported = true
      for cls in dav.split(','):
        let c = cls.strip()
        if c.len > 0: result.davClasses.add c

    if not result.davSupported:
      result.authMessage = "DAV header not present"
      sock.close(); return

    let propfindBody = """<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:resourcetype/></d:prop></d:propfind>"""
    await sock.send(
      "PROPFIND / HTTP/1.1\r\nHost: " & hostHdr & "\r\n" &
      authHdr &
      "Depth: 1\r\nContent-Type: application/xml\r\n" &
      "Content-Length: " & $propfindBody.len & "\r\n" &
      "Connection: close\r\n\r\n" & propfindBody)
    let (pfStatus, pfHdrs, pfBody) = await recvHttpResponse(sock, timeoutMs)

    if pfStatus == 207:
      result.authenticated = true
      for href in parsePropfindListing(pfBody):
        let h = href.strip(chars={'/',' '})
        if h.len > 0 and href != "/" and not href.endsWith(":/") and
           not (h == host or h == host & ":" & $port):
          result.listing.add href
    elif pfStatus == 401:
      result.authMessage = "authentication failed (401)"
    elif pfStatus == 403:
      result.authenticated = username.len == 0
      result.authMessage = if username.len > 0: "access denied (403)" else: "anonymous access denied"
    else:
      result.authMessage = "PROPFIND returned " & $pfStatus
    discard pfHdrs

  except Exception as e:
    result.authMessage = e.msg.splitLines()[0]
  finally:
    sock.close()
