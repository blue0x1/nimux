import std/[asyncdispatch, asyncnet, net, strutils]

type
  ProxyConfig* = object
    enabled*: bool
    kind*: string
    host*: string
    port*: int

var globalProxy*: ProxyConfig

proc configureProxy*(spec: string) =
  let clean = spec.strip()
  if clean.len == 0:
    globalProxy = ProxyConfig()
    return
  var rest = clean
  var kind = "socks5"
  let sep = clean.find("://")
  if sep >= 0:
    kind = clean[0 ..< sep].toLowerAscii()
    rest = clean[sep + 3 .. ^1]
  let colon = rest.rfind(":")
  if colon < 0:
    raise newException(ValueError, "--proxy expects socks5://host:port")
  let port = parseInt(rest[colon + 1 .. ^1])
  let host = rest[0 ..< colon]
  if kind notin ["socks5", "socks"]:
    raise newException(ValueError, "only socks5 proxy is supported")
  globalProxy = ProxyConfig(enabled: true, kind: "socks5", host: host, port: port)

proc recvExact(socket: AsyncSocket; n: int; timeoutMs: int): Future[string] {.async.} =
  while result.len < n:
    let recvFuture = socket.recv(n - result.len)
    if not await withTimeout(recvFuture, timeoutMs):
      break
    let chunk = recvFuture.read()
    if chunk.len == 0:
      break
    result.add chunk

proc u16be(port: int): string =
  result.add char((port shr 8) and 0xff)
  result.add char(port and 0xff)

proc proxySocketHost*(targetHost: string): string =
  if globalProxy.enabled: globalProxy.host else: targetHost

proc socks5Connect(socket: AsyncSocket; host: string; port, timeoutMs: int): Future[bool] {.async.} =
  let connected = await withTimeout(socket.connect(globalProxy.host, Port(globalProxy.port)), timeoutMs)
  if not connected:
    return false
  await socket.send("\x05\x01\x00")
  let hello = await recvExact(socket, 2, timeoutMs)
  if hello.len != 2 or hello[0] != '\x05' or hello[1] == '\xff':
    raise newException(IOError, "SOCKS5 proxy rejected no-auth negotiation")
  if host.len > 255:
    raise newException(ValueError, "SOCKS5 domain name too long")
  var req = "\x05\x01\x00\x03" & char(host.len) & host & u16be(port)
  await socket.send(req)
  let head = await recvExact(socket, 4, timeoutMs)
  if head.len != 4:
    return false
  if head[1] != '\x00':
    raise newException(IOError, "SOCKS5 connect failed with code " & $ord(head[1]))
  let extraLen =
    case ord(head[3])
    of 1: 4
    of 3:
      let ln = await recvExact(socket, 1, timeoutMs)
      if ln.len != 1: return false
      ord(ln[0])
    of 4: 16
    else: 0
  if extraLen > 0:
    discard await recvExact(socket, extraLen, timeoutMs)
  discard await recvExact(socket, 2, timeoutMs)
  return true

proc connectTcp*(socket: AsyncSocket; host: string; port, timeoutMs: int): Future[bool] {.async.} =
  if globalProxy.enabled:
    return await socks5Connect(socket, host, port, timeoutMs)
  return await withTimeout(socket.connect(host, Port(port)), timeoutMs)

proc connectTcpResolved*(socket: AsyncSocket; host: string; port, timeoutMs: int): Future[bool] {.async.} =
  if globalProxy.enabled:
    return await socks5Connect(socket, host, port, timeoutMs)
  return await withTimeout(socket.connect(host, Port(port)), timeoutMs)

proc recvExactSync(socket: Socket; n: int): string =
  while result.len < n:
    var chunk = newString(n - result.len)
    let got = socket.recv(chunk, chunk.len)
    if got <= 0:
      break
    chunk.setLen(got)
    result.add chunk

proc socks5ConnectSync(socket: Socket; host: string; port, timeoutMs: int) =
  socket.connect(globalProxy.host, Port(globalProxy.port), timeout = timeoutMs)
  socket.send("\x05\x01\x00")
  let hello = recvExactSync(socket, 2)
  if hello.len != 2 or hello[0] != '\x05' or hello[1] == '\xff':
    raise newException(IOError, "SOCKS5 proxy rejected no-auth negotiation")
  if host.len > 255:
    raise newException(ValueError, "SOCKS5 domain name too long")
  socket.send("\x05\x01\x00\x03" & char(host.len) & host & u16be(port))
  let head = recvExactSync(socket, 4)
  if head.len != 4:
    raise newException(IOError, "SOCKS5 connect failed: short response")
  if head[1] != '\x00':
    raise newException(IOError, "SOCKS5 connect failed with code " & $ord(head[1]))
  let extraLen =
    case ord(head[3])
    of 1: 4
    of 3:
      let ln = recvExactSync(socket, 1)
      if ln.len != 1:
        raise newException(IOError, "SOCKS5 connect failed: short domain response")
      ord(ln[0])
    of 4: 16
    else: 0
  if extraLen > 0:
    discard recvExactSync(socket, extraLen)
  discard recvExactSync(socket, 2)

proc connectTcpSync*(socket: Socket; host: string; port, timeoutMs: int) =
  if globalProxy.enabled:
    socks5ConnectSync(socket, host, port, timeoutMs)
  else:
    socket.connect(host, Port(port), timeout = timeoutMs)
