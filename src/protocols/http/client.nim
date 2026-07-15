import std/[asyncdispatch, asyncnet, base64, net, strutils]
import ../../core/proxy as netproxy

type
  HttpResult* = object
    host*: string
    port*: int
    ssl*: bool
    reachable*: bool
    statusCode*: int
    reason*: string
    server*: string
    location*: string
    contentType*: string
    wwwAuthenticate*: string
    title*: string
    bodySnippet*: string
    authenticated*: bool
    authMessage*: string

proc recvHttpResponse(sock: AsyncSocket; timeoutMs: int): Future[tuple[status: int; reason, headers, body: string]] {.async.} =
  var raw = ""
  while true:
    let f = sock.recv(4096)
    if not await withTimeout(f, timeoutMs):
      break
    let chunk = await f
    if chunk.len == 0:
      break
    raw.add chunk
    if "\r\n\r\n" in raw:
      break
  let split = raw.find("\r\n\r\n")
  let hdrs = if split >= 0: raw[0 ..< split] else: raw
  var body = if split >= 0: raw[split + 4 .. ^1] else: ""
  var status = 0
  var reason = ""
  let lines = hdrs.splitLines()
  if lines.len > 0:
    let parts = lines[0].splitWhitespace()
    if parts.len >= 2:
      try: status = parseInt(parts[1]) except: discard
    if parts.len >= 3:
      reason = parts[2 .. ^1].join(" ")
  var contentLength = -1
  for line in lines:
    if line.toLowerAscii().startsWith("content-length:"):
      try: contentLength = parseInt(line[16 .. ^1].strip()) except: discard
  if contentLength > 0:
    while body.len < contentLength:
      let f = sock.recv(contentLength - body.len)
      if not await withTimeout(f, timeoutMs):
        break
      let chunk = await f
      if chunk.len == 0:
        break
      body.add chunk
  result = (status, reason, hdrs, body)

proc headerVal(hdrs, name: string): string =
  let lower = name.toLowerAscii() & ":"
  for line in hdrs.splitLines():
    if line.toLowerAscii().startsWith(lower):
      return line[name.len + 1 .. ^1].strip()

proc htmlTitle(body: string): string =
  let lower = body.toLowerAscii()
  let start = lower.find("<title")
  if start < 0:
    return ""
  let gt = lower.find('>', start)
  if gt < 0:
    return ""
  let stop = lower.find("</title>", gt + 1)
  if stop < 0:
    return ""
  result = body[gt + 1 ..< stop].strip().replace("\r", " ").replace("\n", " ")

proc probeHttp*(host: string; port, timeoutMs: int; ssl: bool;
                username, password, path: string): Future[HttpResult] {.async.} =
  result.host = host
  result.port = port
  result.ssl = ssl
  var currentPath = if path.len > 0: path else: "/"
  if not currentPath.startsWith("/"):
    currentPath = "/" & currentPath
  for _ in 0 .. 4:
    let sock = newAsyncSocket(buffered = false)
    try:
      let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
      if not ok:
        return
      result.reachable = true
      if ssl:
        let ctx = newContext(verifyMode = CVerifyNone)
        ctx.wrapSocket(sock)
      let hostHdr = if (ssl and port == 443) or (not ssl and port == 80): host else: host & ":" & $port
      let authHdr =
        if username.len > 0: "Authorization: Basic " & base64.encode(username & ":" & password) & "\r\n"
        else: ""
      let req = "GET " & currentPath & " HTTP/1.1\r\nHost: " & hostHdr &
        "\r\nUser-Agent: nimux/0.1\r\nAccept: */*\r\n" & authHdr &
        "Connection: close\r\n\r\n"
      await sock.send(req)
      let (status, reason, hdrs, body) = await recvHttpResponse(sock, timeoutMs)
      result.statusCode = status
      result.reason = reason
      result.server = headerVal(hdrs, "Server")
      result.location = headerVal(hdrs, "Location")
      result.contentType = headerVal(hdrs, "Content-Type")
      result.wwwAuthenticate = headerVal(hdrs, "WWW-Authenticate")
      result.title = htmlTitle(body)
      result.bodySnippet = body.replace("\r", " ").replace("\n", " ")
      if result.bodySnippet.len > 160:
        result.bodySnippet.setLen(160)
      if status == 401:
        result.authenticated = false
        result.authMessage = "authentication required"
      elif username.len > 0 and status in [200, 201, 202, 204, 206, 301, 302, 307, 308, 403]:
        result.authenticated = true
      elif username.len == 0:
        result.authenticated = status notin [401]
      if status in [301, 302, 307, 308] and result.location.len > 0:
        if result.location.startsWith("/"):
          currentPath = result.location
          continue
      return
    finally:
      try: sock.close() except: discard
