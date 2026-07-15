import std/[nativesockets, net, os, locks, times, strutils]
import posix

const BufSize = 65536
const PingMs  = 5_000
const PongTmo = 15.0

type
  SocksServerArgs* = object
    bindAddr*: string
    socksPort*: int
    ctrlPort*: int

var gCtrlFd:    SocketHandle = SocketHandle(-1)
var gCtrlLock:  Lock
var gCtrlAlive: bool = false
var gNextId:    uint32 = 1

const MaxPend = 512
type PendChan = Channel[SocketHandle]
var gPendLock:  Lock
var gPendIds:   array[MaxPend, uint32]
var gPendChans: array[MaxPend, ptr PendChan]
var gPendCount: int

initLock(gCtrlLock)
initLock(gPendLock)

proc buildFrame(id: uint32; ft: uint8; data: string): string =
  let dlen = data.len
  result = newString(8 + dlen)
  result[0] = char((id shr 24) and 0xFF'u32); result[1] = char((id shr 16) and 0xFF'u32)
  result[2] = char((id shr 8) and 0xFF'u32);  result[3] = char(id and 0xFF'u32)
  result[4] = char(ft)
  result[5] = char((dlen shr 16) and 0xFF); result[6] = char((dlen shr 8) and 0xFF)
  result[7] = char(dlen and 0xFF)
  for i in 0 ..< dlen: result[8 + i] = data[i]

proc sendAllFd(fd: SocketHandle; data: string) =
  var sent = 0
  while sent < data.len:
    let r = nativesockets.send(fd, unsafeAddr data[sent], cint(data.len - sent), 0)
    if r <= 0: raise newException(IOError, "send failed")
    sent += r

proc recvAllFd(fd: SocketHandle; n: int): string =
  result = newString(n)
  var got = 0
  while got < n:
    let r = nativesockets.recv(fd, addr result[got], cint(n - got), 0)
    if r <= 0: raise newException(IOError, "eof")
    got += r

proc setNoDelay(fd: SocketHandle) =
  try: setSockOptInt(fd, cint(6), cint(1), 1)
  except: discard

proc sendCtrl(ft: uint8; id: uint32; data: string): bool =
  let frame = buildFrame(id, ft, data)
  acquire(gCtrlLock)
  if gCtrlAlive:
    try:
      sendAllFd(gCtrlFd, frame)
      result = true
    except:
      gCtrlAlive = false
  release(gCtrlLock)

proc pendAdd(id: uint32; ch: ptr PendChan) =
  acquire(gPendLock)
  if gPendCount < MaxPend:
    gPendIds[gPendCount] = id
    gPendChans[gPendCount] = ch
    inc gPendCount
  release(gPendLock)

proc pendPop(id: uint32): ptr PendChan =
  result = nil
  acquire(gPendLock)
  for i in 0 ..< gPendCount:
    if gPendIds[i] == id:
      result = gPendChans[i]
      dec gPendCount
      gPendIds[i] = gPendIds[gPendCount]
      gPendChans[i] = gPendChans[gPendCount]
      gPendChans[gPendCount] = nil
      break
  release(gPendLock)

proc pendRemove(id: uint32) = discard pendPop(id)

proc socks5Handshake(fd: SocketHandle): tuple[host: string; port: int] =
  let h = recvAllFd(fd, 2)
  if h[0] != '\x05': raise newException(IOError, "not socks5")
  discard recvAllFd(fd, ord(h[1]))
  sendAllFd(fd, "\x05\x00")
  let req = recvAllFd(fd, 4)
  if req[0] != '\x05' or req[1] != '\x01': raise newException(IOError, "bad cmd")
  var host: string
  case req[3]
  of '\x01':
    let b = recvAllFd(fd, 4)
    host = $ord(b[0]) & "." & $ord(b[1]) & "." & $ord(b[2]) & "." & $ord(b[3])
  of '\x03':
    let lb = recvAllFd(fd, 1)
    host = recvAllFd(fd, ord(lb[0]))
  of '\x04':
    let b = recvAllFd(fd, 16)
    var parts: seq[string]
    for i in countup(0, 14, 2):
      parts.add toHex((ord(b[i]) shl 8) or ord(b[i + 1]), 4).toLowerAscii
    host = parts.join(":")
  else: raise newException(IOError, "bad atyp")
  let pb = recvAllFd(fd, 2)
  result = (host, (ord(pb[0]) shl 8) or ord(pb[1]))

proc bidirCopy(fd1, fd2: SocketHandle) =
  var buf = newString(BufSize)
  var fds: array[2, TPollfd]
  fds[0].fd = cast[cint](fd1); fds[0].events = POLLIN
  fds[1].fd = cast[cint](fd2); fds[1].events = POLLIN
  while true:
    if posix.poll(addr fds[0], Tnfds(2), -1) <= 0: break
    if (fds[0].revents and POLLIN) != 0:
      let n = nativesockets.recv(fd1, addr buf[0], cint(BufSize), 0)
      if n <= 0: break
      var s = 0
      while s < n:
        let r = nativesockets.send(fd2, unsafeAddr buf[s], cint(n - s), 0)
        if r <= 0: return
        s += r
    if (fds[1].revents and POLLIN) != 0:
      let n = nativesockets.recv(fd2, addr buf[0], cint(BufSize), 0)
      if n <= 0: break
      var s = 0
      while s < n:
        let r = nativesockets.send(fd1, unsafeAddr buf[s], cint(n - s), 0)
        if r <= 0: return
        s += r

type SocksHandlerArgs = object
  fd: SocketHandle

const MaxHandlers = 512
var gHandlerThreads: array[MaxHandlers, Thread[SocksHandlerArgs]]
var gHandlerIdx: int
var gHandlerLock: Lock
initLock(gHandlerLock)

proc runSocksHandler(args: SocksHandlerArgs) {.thread.} =
  {.cast(gcsafe).}:
    let clientFd = args.fd
    var dataFd = SocketHandle(-1)
    var id: uint32 = 0
    try:
      let (host, port) = socks5Handshake(clientFd)

      acquire(gCtrlLock)
      let alive = gCtrlAlive
      id = gNextId; gNextId += 2
      release(gCtrlLock)

      if not alive:
        sendAllFd(clientFd, "\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        nativesockets.close(clientFd)
        return

      var connData = newString(1 + host.len + 2)
      connData[0] = char(host.len)
      for i, c in host: connData[1 + i] = c
      connData[1 + host.len] = char(port shr 8)
      connData[2 + host.len] = char(port and 0xff)

      let ch = create(PendChan)
      ch[].open(1)
      pendAdd(id, ch)
      discard sendCtrl(0x01, id, connData)

      let deadline = epochTime() + 10.0
      while epochTime() < deadline:
        let (ok, val) = ch[].tryRecv()
        if ok: dataFd = val; break
        sleep(5)

      ch[].close()
      dealloc(cast[pointer](ch))
      pendRemove(id)

      if cast[int](dataFd) < 0:
        sendAllFd(clientFd, "\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
        nativesockets.close(clientFd)
        return

      sendAllFd(clientFd, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
      bidirCopy(clientFd, dataFd)
    except: discard
    nativesockets.close(clientFd)
    if cast[int](dataFd) >= 0: nativesockets.close(dataFd)

proc spawnHandler(fd: SocketHandle) =
  acquire(gHandlerLock)
  let i = gHandlerIdx mod MaxHandlers
  gHandlerIdx = (gHandlerIdx + 1) mod MaxHandlers
  release(gHandlerLock)
  createThread(gHandlerThreads[i], runSocksHandler, SocksHandlerArgs(fd: fd))

type CtrlRecvArgs = object
  fd: SocketHandle

var gCtrlRecvThread: Thread[CtrlRecvArgs]

proc runCtrlRecv(args: CtrlRecvArgs) {.thread.} =
  {.cast(gcsafe).}:
    var lastPong = epochTime()
    while true:
      try:
        let hdr = recvAllFd(args.fd, 8)
        let ft = uint8(ord(hdr[4]))
        if ft == 0xFE: lastPong = epochTime()
        if epochTime() - lastPong > PongTmo: break
      except: break
    acquire(gCtrlLock)
    if gCtrlFd == args.fd: gCtrlAlive = false
    release(gCtrlLock)
    echo "[!] agent disconnected"

var gPingThread: Thread[pointer]

proc runPing(p: pointer) {.thread.} =
  {.cast(gcsafe).}:
    while true:
      sleep(PingMs)
      if not sendCtrl(0xFF, 0, ""): break

proc listenFd(port: int; bindAddr: string): SocketHandle =
  let fd = nativesockets.createNativeSocket(Domain.AF_INET, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP)
  setSockOptInt(fd, cint(posix.SOL_SOCKET), cint(posix.SO_REUSEADDR), 1)
  var sa: Sockaddr_in
  sa.sin_family = TSa_Family(posix.AF_INET)
  sa.sin_port = nativesockets.htons(uint16(port))
  sa.sin_addr.s_addr = if bindAddr == "" or bindAddr == "0.0.0.0": 0'u32
                       else: inet_addr(bindAddr.cstring)
  if nativesockets.bindAddr(fd, cast[ptr SockAddr](addr sa), SockLen(sizeof(sa))) != 0:
    raise newException(IOError, "bind failed port=" & $port)
  discard nativesockets.listen(fd, cint(128))
  result = fd

type AcceptCtrlArgs = object
  port: int
  bindStr: string

var gAcceptCtrlThread: Thread[AcceptCtrlArgs]

proc runAcceptCtrl(args: AcceptCtrlArgs) {.thread.} =
  {.cast(gcsafe).}:
    let srv = listenFd(args.port, args.bindStr)
    while true:
      var sa: SockAddr
      var saLen = SockLen(sizeof(sa))
      let sock = nativesockets.accept(srv, addr sa, addr saLen)
      if cast[int](sock) < 0: continue
      setNoDelay(sock)
      try:
        let hdr = recvAllFd(sock, 5)
        let connType = uint8(ord(hdr[0]))
        let id = (uint32(ord(hdr[1])) shl 24) or (uint32(ord(hdr[2])) shl 16) or
                 (uint32(ord(hdr[3])) shl 8) or uint32(ord(hdr[4]))
        if connType == 0x01:
          acquire(gCtrlLock)
          if gCtrlAlive: discard posix.shutdown(gCtrlFd, cint(SHUT_RDWR))
          gCtrlFd = sock
          gCtrlAlive = true
          release(gCtrlLock)
          var peer = "?"
          try:
            var sin = cast[ptr Sockaddr_in](addr sa)
            peer = $inet_ntoa(sin.sin_addr)
          except: discard
          echo "[*] agent connected from " & peer & " (total: 1)"
          createThread(gCtrlRecvThread, runCtrlRecv, CtrlRecvArgs(fd: sock))
          createThread(gPingThread, runPing, nil)
        elif connType == 0x02:
          let ch = pendPop(id)
          if ch != nil: ch[].send(sock)
          else: nativesockets.close(sock)
        else:
          nativesockets.close(sock)
      except:
        nativesockets.close(sock)

type AcceptSocksArgs = object
  port: int

var gAcceptSocksThread: Thread[AcceptSocksArgs]

proc runAcceptSocks(args: AcceptSocksArgs) {.thread.} =
  {.cast(gcsafe).}:
    let srv = listenFd(args.port, "127.0.0.1")
    while true:
      var sa: SockAddr
      var saLen = SockLen(sizeof(sa))
      let sock = nativesockets.accept(srv, addr sa, addr saLen)
      if cast[int](sock) < 0: continue
      setNoDelay(sock)
      spawnHandler(sock)

proc runSocksServer*(args: SocksServerArgs) =
  echo "[*] reverse TCP listening on " & args.bindAddr & ":" & $args.ctrlPort
  echo "[*] SOCKS5 on 127.0.0.1:" & $args.socksPort
  echo "[*] waiting for agent callback..."
  createThread(gAcceptCtrlThread, runAcceptCtrl,
    AcceptCtrlArgs(port: args.ctrlPort, bindStr: args.bindAddr))
  createThread(gAcceptSocksThread, runAcceptSocks,
    AcceptSocksArgs(port: args.socksPort))
  joinThread(gAcceptCtrlThread)
