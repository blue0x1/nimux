import std/[nativesockets, os, strutils, locks]

const BufSize = 65536
const MaxHost = 256

proc setNoDelay(fd: SocketHandle) =
  try: setSockOptInt(fd, cint(6), cint(1), 1)
  except: discard

proc connectTo(host: string; port: int): SocketHandle =
  result = SocketHandle(-1)
  var res: ptr AddrInfo
  try: res = getAddrInfo(host, Port(port), AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP)
  except: return
  if res == nil: return
  var ai = res
  while ai != nil:
    let fd = createNativeSocket(Domain(ai.ai_family), SockType(ai.ai_socktype), Protocol(ai.ai_protocol))
    if cast[int](fd) >= 0:
      if nativesockets.connect(fd, ai.ai_addr, ai.ai_addrlen.SockLen) == 0:
        setNoDelay(fd)
        freeaddrinfo(res)
        return fd
      nativesockets.close(fd)
    ai = ai.ai_next
  freeaddrinfo(res)

proc sendAll(fd: SocketHandle; data: string) =
  var sent = 0
  while sent < data.len:
    let r = nativesockets.send(fd, unsafeAddr data[sent], cint(data.len - sent), 0)
    if r <= 0: raise newException(IOError, "send failed")
    sent += r

proc recvAll(fd: SocketHandle; n: int): string =
  result = newString(n)
  var got = 0
  while got < n:
    let r = nativesockets.recv(fd, addr result[got], cint(n - got), 0)
    if r <= 0: raise newException(IOError, "eof")
    got += r

when defined(windows):
  proc winShutdown(fd: SocketHandle; how: cint): cint
    {.stdcall, dynlib: "ws2_32.dll", importc: "shutdown".}
  proc shutdownFd(fd: SocketHandle) = discard winShutdown(fd, cint(2))
else:
  proc posixShutdown(fd: cint; how: cint): cint
    {.cdecl, importc: "shutdown", header: "<sys/socket.h>".}
  proc shutdownFd(fd: SocketHandle) = discard posixShutdown(cast[cint](fd), cint(2))

type CopyArgs = object
  src: SocketHandle
  dst: SocketHandle

var copyThreads: array[2048, Thread[CopyArgs]]
var nextCopy: int
var copyLock: Lock
initLock(copyLock)

proc runCopy(args: CopyArgs) {.thread.} =
  {.cast(gcsafe).}:
    var buf = newString(BufSize)
    while true:
      let n = nativesockets.recv(args.src, addr buf[0], cint(BufSize), 0)
      if n <= 0: break
      var sent = 0
      while sent < n:
        let r = nativesockets.send(args.dst, unsafeAddr buf[sent], cint(n - sent), 0)
        if r <= 0: return
        sent += r
    shutdownFd(args.dst)

proc spawnCopy(src, dst: SocketHandle) =
  acquire(copyLock)
  let i = nextCopy mod 2048
  nextCopy = (nextCopy + 1) mod 2048
  release(copyLock)
  createThread(copyThreads[i], runCopy, CopyArgs(src: src, dst: dst))

type StreamArgs = object
  id: uint32
  ctrlPort: int
  ctrlHostLen: int
  ctrlHost: array[MaxHost, char]
  targetPort: int
  targetHostLen: int
  targetHost: array[MaxHost, char]

var streamThreads: array[512, Thread[StreamArgs]]
var nextStream: int
var streamLock: Lock
initLock(streamLock)

proc runStream(args: StreamArgs) {.thread.} =
  {.cast(gcsafe).}:
    var th = newString(args.targetHostLen)
    for i in 0 ..< args.targetHostLen: th[i] = args.targetHost[i]
    var ch = newString(args.ctrlHostLen)
    for i in 0 ..< args.ctrlHostLen: ch[i] = args.ctrlHost[i]

    let targetFd = connectTo(th, args.targetPort)
    if cast[int](targetFd) < 0: return

    let dataFd = connectTo(ch, args.ctrlPort)
    if cast[int](dataFd) < 0:
      nativesockets.close(targetFd)
      return

    var hs = newString(5)
    hs[0] = '\x02'
    hs[1] = char((args.id shr 24) and 0xff)
    hs[2] = char((args.id shr 16) and 0xff)
    hs[3] = char((args.id shr 8) and 0xff)
    hs[4] = char(args.id and 0xff)
    try: sendAll(dataFd, hs)
    except:
      nativesockets.close(dataFd)
      nativesockets.close(targetFd)
      return

    spawnCopy(dataFd, targetFd)
    spawnCopy(targetFd, dataFd)

proc spawnStream(id: uint32; ctrlHost: string; ctrlPort: int; targetHost: string; targetPort: int) =
  acquire(streamLock)
  let i = nextStream mod 512
  nextStream = (nextStream + 1) mod 512
  release(streamLock)
  var args: StreamArgs
  args.id = id
  args.ctrlPort = ctrlPort
  args.ctrlHostLen = min(ctrlHost.len, MaxHost - 1)
  for i in 0 ..< args.ctrlHostLen: args.ctrlHost[i] = ctrlHost[i]
  args.targetPort = targetPort
  args.targetHostLen = min(targetHost.len, MaxHost - 1)
  for i in 0 ..< args.targetHostLen: args.targetHost[i] = targetHost[i]
  createThread(streamThreads[i], runStream, args)

proc sendFrame(fd: SocketHandle; id: uint32; ft: uint8; data: string) =
  let dlen = data.len
  var frame = newString(8 + dlen)
  frame[0] = char((id shr 24) and 0xFF'u32)
  frame[1] = char((id shr 16) and 0xFF'u32)
  frame[2] = char((id shr 8) and 0xFF'u32)
  frame[3] = char(id and 0xFF'u32)
  frame[4] = char(ft)
  frame[5] = char((dlen shr 16) and 0xFF)
  frame[6] = char((dlen shr 8) and 0xFF)
  frame[7] = char(dlen and 0xFF)
  if dlen > 0: copyMem(addr frame[8], unsafeAddr data[0], dlen)
  sendAll(fd, frame)

proc ctrlLoop(ctrlHost: string; ctrlPort: int; fd: SocketHandle) =
  while true:
    let hdr  = recvAll(fd, 8)
    let id   = (uint32(ord(hdr[0])) shl 24) or (uint32(ord(hdr[1])) shl 16) or
               (uint32(ord(hdr[2])) shl  8) or  uint32(ord(hdr[3]))
    let ft   = uint8(ord(hdr[4]))
    let dlen = (int(ord(hdr[5])) shl 16) or (int(ord(hdr[6])) shl 8) or int(ord(hdr[7]))
    let data = if dlen > 0: recvAll(fd, dlen) else: ""
    case ft
    of 0x01:
      if data.len >= 3:
        let hlen = int(ord(data[0]))
        if data.len >= 1 + hlen + 2:
          let h = data[1 ..< 1 + hlen]
          let p = (int(ord(data[1 + hlen])) shl 8) or int(ord(data[2 + hlen]))
          spawnStream(id, ctrlHost, ctrlPort, h, p)
    of 0xFF:
      sendFrame(fd, 0, 0xFE, "")
    else: discard

proc reverseLoop(host: string; port: int) =
  while true:
    let fd = connectTo(host, port)
    if cast[int](fd) < 0:
      sleep(3000)
      continue

    var hs = newString(5)
    hs[0] = '\x01'
    hs[1] = '\x00'; hs[2] = '\x00'; hs[3] = '\x00'; hs[4] = '\x00'
    try: sendAll(fd, hs)
    except:
      nativesockets.close(fd)
      sleep(3000)
      continue

    try: ctrlLoop(host, port, fd)
    except CatchableError: discard
    nativesockets.close(fd)
    sleep(3000)

proc main() =
  var reverseHost = ""
  var reversePort = 0
  var i = 1
  while i <= paramCount():
    case paramStr(i)
    of "--reverse":
      if i < paramCount(): inc i; reverseHost = paramStr(i)
    of "--reverse-port":
      if i < paramCount():
        inc i
        try: reversePort = parseInt(paramStr(i)) except: discard
    else: discard
    inc i
  if reverseHost.len > 0 and reversePort > 0:
    reverseLoop(reverseHost, reversePort)

main()
