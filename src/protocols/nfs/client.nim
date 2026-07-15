import std/[asyncdispatch, asyncnet, net, posix, random, sequtils, strutils]
import ../../core/proxy as netproxy

type
  RpcService* = object
    prog*:  uint32
    vers*:  uint32
    proto*: uint32
    port*:  uint32

  NfsExport* = object
    path*:   string
    groups*: seq[string]

  NfsResult* = object
    host*:        string
    port*:        int
    reachable*:   bool
    rpcServices*: seq[RpcService]
    exports*:     seq[NfsExport]
    mountPort*:   int
    nfsVersions*: seq[int]

  Fattr3* = object
    ftype*:  uint32
    mode*:   uint32
    nlink*:  uint32
    uid*:    uint32
    gid*:    uint32
    size*:   uint64
    fileid*: uint64

  DirEntry* = object
    name*:    string
    fileid*:  uint64
    isDir*:   bool
    size*:    uint64
    mode*:    uint32

  NfsSession* = ref object
    host*:        string
    mountPort*:   int
    nfsPort*:     int
    timeoutMs*:   int
    exportPath*:  string
    rootFh*:      string
    cwd*:         string
    sock*:        AsyncSocket

proc addU32(s: var string; v: uint32) =
  s.add char((v shr 24) and 0xff)
  s.add char((v shr 16) and 0xff)
  s.add char((v shr 8)  and 0xff)
  s.add char(v and 0xff)

proc addU64(s: var string; v: uint64) =
  s.addU32 uint32(v shr 32)
  s.addU32 uint32(v and 0xffffffff'u64)

proc readU32(s: string; pos: int): uint32 =
  if pos + 3 >= s.len: return 0
  (uint32(ord(s[pos])) shl 24) or (uint32(ord(s[pos+1])) shl 16) or
  (uint32(ord(s[pos+2])) shl 8) or uint32(ord(s[pos+3]))

proc readU64(s: string; pos: int): uint64 =
  uint64(readU32(s, pos)) shl 32 or uint64(readU32(s, pos + 4))

proc rpcCallMsg(prog, vers, procedure: uint32; uid = 0'u32; gid = 0'u32): string =
  result.addU32 uint32(rand(0x7fffffff))
  result.addU32 0
  result.addU32 2
  result.addU32 prog
  result.addU32 vers
  result.addU32 procedure
  const machine = "localhost"
  var cred = ""
  cred.addU32 uint32(rand(0x7fffffff))
  cred.addU32 uint32(machine.len)
  cred.add machine
  let machinePad = (4 - (machine.len and 3)) and 3
  for _ in 0 ..< machinePad: cred.add '\x00'
  cred.addU32 uid
  cred.addU32 gid
  cred.addU32 1'u32
  cred.addU32 gid
  result.addU32 1
  result.addU32 uint32(cred.len)
  result.add cred
  result.addU32 0; result.addU32 0

proc tcpRecord(payload: string): string =
  result.addU32 0x80000000'u32 or uint32(payload.len)
  result.add payload

proc recvExact(sock: AsyncSocket; n: int; timeoutMs: int): Future[string] {.async.} =
  var buf = ""
  while buf.len < n:
    let f = sock.recv(n - buf.len)
    if not await withTimeout(f, timeoutMs):
      raise newException(IOError, "NFS: timeout")
    let chunk = await f
    if chunk.len == 0:
      raise newException(IOError, "NFS: connection closed")
    buf.add chunk
  result = buf

proc recvRpcReply(sock: AsyncSocket; timeoutMs: int): Future[string] {.async.} =
  var payload = ""
  while true:
    let hdr = await recvExact(sock, 4, timeoutMs)
    let mark = readU32(hdr, 0)
    let size = int(mark and 0x7fffffff'u32)
    if size > 0:
      payload.add await recvExact(sock, size, timeoutMs)
    if (mark and 0x80000000'u32) != 0: break
  result = payload

proc connectTcpPrivileged(host: string; port, timeoutMs: int): Future[AsyncSocket] {.async.} =
  for srcPort in countDown(1023, 512):
    let sock = newAsyncSocket(buffered = false)
    var optval: cint = 1
    discard posix.setsockopt(sock.getFd(), posix.SOL_SOCKET, posix.SO_REUSEADDR,
      addr optval, SockLen(sizeof(optval)))
    var sa: Sockaddr_in
    sa.sin_family = uint16(posix.AF_INET)
    sa.sin_port = posix.htons(uint16(srcPort))
    sa.sin_addr.s_addr = 0
    if posix.bindSocket(sock.getFd(), cast[ptr SockAddr](addr sa), SockLen(sizeof(sa))) != 0:
      sock.close()
      continue
    try:
      let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
      if ok: return sock
    except: discard
    sock.close()
  return nil

proc connectTcpPriv*(host: string; port, timeoutMs: int): Future[AsyncSocket] {.async.} =
  result = await connectTcpPrivileged(host, port, timeoutMs)

proc connectTcp(host: string; port, timeoutMs: int): Future[AsyncSocket] {.async.} =
  let sock = newAsyncSocket(buffered = false)
  try:
    let ok = await netproxy.connectTcp(sock, host, port, timeoutMs)
    if ok: return sock
    sock.close()
  except: sock.close()
  return nil

proc xdrReadString(s: string; pos: var int): string =
  if pos + 4 > s.len: return ""
  let n = int(readU32(s, pos)); pos += 4
  if n <= 0: return ""
  let aligned = (n + 3) and (not 3)
  if pos + n > s.len: return ""
  result = s[pos ..< pos + n]
  pos += aligned

proc xdrAddString(s: var string; v: string) =
  s.addU32 uint32(v.len)
  s.add v
  let pad = (4 - (v.len and 3)) and 3
  for _ in 0 ..< pad: s.add '\x00'

proc xdrAddFh(s: var string; fh: string) =
  s.addU32 uint32(fh.len)
  s.add fh
  let pad = (4 - (fh.len and 3)) and 3
  for _ in 0 ..< pad: s.add '\x00'

proc xdrReadFh(s: string; pos: var int): string =
  if pos + 4 > s.len: return ""
  let n = int(readU32(s, pos)); pos += 4
  if n <= 0 or n > 64: pos += ((n + 3) and (not 3)); return ""
  if pos + n > s.len: return ""
  result = s[pos ..< pos + n]
  let aligned = (n + 3) and (not 3)
  pos += aligned

proc xdrReadFattr3(s: string; pos: var int): Fattr3 =
  if pos + 84 > s.len: pos += 84; return
  result.ftype  = readU32(s, pos);      pos += 4
  result.mode   = readU32(s, pos);      pos += 4
  result.nlink  = readU32(s, pos);      pos += 4
  result.uid    = readU32(s, pos);      pos += 4
  result.gid    = readU32(s, pos);      pos += 4
  result.size   = readU64(s, pos);      pos += 8
  pos += 8
  pos += 8
  pos += 8
  result.fileid = readU64(s, pos);      pos += 8
  pos += 24

proc xdrSkipPostOpAttr(s: string; pos: var int) =
  if pos + 4 > s.len: return
  let present = readU32(s, pos); pos += 4
  if present != 0:
    pos += 84

proc rpcReplyData(reply: string): tuple[ok: bool; pos: int] =
  if reply.len < 24: return (false, 0)
  let msgType = readU32(reply, 4)
  if msgType != 1: return (false, 0)
  let replyStat = readU32(reply, 8)
  if replyStat != 0: return (false, 0)
  let verfLen = int(readU32(reply, 16))
  let acceptStat = readU32(reply, 20 + verfLen)
  if acceptStat != 0: return (false, 0)
  return (true, 24 + verfLen)

proc portmapperDump(host: string; timeoutMs: int): Future[seq[RpcService]] {.async.} =
  let sock = await connectTcp(host, 111, timeoutMs)
  if sock.isNil: return
  defer: sock.close()
  try:
    var req = rpcCallMsg(100000, 2, 4)
    await sock.send(tcpRecord(req))
    let reply = await recvRpcReply(sock, timeoutMs)
    let (ok, pos0) = rpcReplyData(reply)
    if not ok: return
    var pos = pos0
    while pos + 4 <= reply.len:
      let vf = readU32(reply, pos); pos += 4
      if vf == 0: break
      if pos + 16 > reply.len: break
      let prog = readU32(reply, pos); pos += 4
      let vers = readU32(reply, pos); pos += 4
      let prot = readU32(reply, pos); pos += 4
      let port = readU32(reply, pos); pos += 4
      result.add RpcService(prog: prog, vers: vers, proto: prot, port: port)
  except: discard

proc mountExport(host: string; port, timeoutMs: int): Future[seq[NfsExport]] {.async.} =
  let sock = await connectTcp(host, port, timeoutMs)
  if sock.isNil: return
  defer: sock.close()
  try:
    var req = rpcCallMsg(100005, 3, 5)
    await sock.send(tcpRecord(req))
    let reply = await recvRpcReply(sock, timeoutMs)
    let (ok, pos0) = rpcReplyData(reply)
    if not ok: return
    var pos = pos0
    while pos + 4 <= reply.len:
      let vf = readU32(reply, pos); pos += 4
      if vf == 0: break
      let path = xdrReadString(reply, pos)
      var groups: seq[string]
      while pos + 4 <= reply.len:
        let gvf = readU32(reply, pos); pos += 4
        if gvf == 0: break
        let grp = xdrReadString(reply, pos)
        if grp.len > 0: groups.add grp
      if path.len > 0:
        result.add NfsExport(path: path, groups: groups)
  except: discard

proc nfsMnt*(host: string; mountPort, timeoutMs: int; exportPath: string): Future[string] {.async.} =
  let sock = await connectTcpPrivileged(host, mountPort, timeoutMs)
  if sock.isNil: return ""
  defer: sock.close()
  try:
    var req = rpcCallMsg(100005, 3, 1)
    req.xdrAddString exportPath
    await sock.send(tcpRecord(req))
    let reply = await recvRpcReply(sock, timeoutMs)
    let (ok, pos0) = rpcReplyData(reply)
    if not ok: return ""
    var pos = pos0
    if pos + 4 > reply.len: return ""
    let mntStat = readU32(reply, pos); pos += 4
    if mntStat != 0: return ""
    result = xdrReadFh(reply, pos)
  except: discard

proc nfsLookupSock*(sock: AsyncSocket; timeoutMs: int; dirFh, name: string): Future[tuple[fh: string; attr: Fattr3; ok: bool]] {.async.} =
  try:
    var req = rpcCallMsg(100003, 3, 3)
    req.xdrAddFh dirFh
    req.xdrAddString name
    await sock.send(tcpRecord(req))
    let reply = await recvRpcReply(sock, timeoutMs)
    let (ok, pos0) = rpcReplyData(reply)
    if not ok: return ("", Fattr3(), false)
    var pos = pos0
    if pos + 4 > reply.len: return ("", Fattr3(), false)
    let nfsStat = readU32(reply, pos); pos += 4
    if nfsStat != 0: return ("", Fattr3(), false)
    let fh = xdrReadFh(reply, pos)
    var attr: Fattr3
    if pos + 4 <= reply.len:
      let present = readU32(reply, pos); pos += 4
      if present != 0:
        attr = xdrReadFattr3(reply, pos)
    xdrSkipPostOpAttr(reply, pos)
    return (fh, attr, true)
  except: discard
  return ("", Fattr3(), false)

proc nfsLookupPathSock*(sock: AsyncSocket; timeoutMs: int; rootFh, path: string): Future[tuple[fh: string; attr: Fattr3; ok: bool]] {.async.} =
  var fh = rootFh
  var attr: Fattr3
  for part in path.split('/').filterIt(it.len > 0):
    let r = await nfsLookupSock(sock, timeoutMs, fh, part)
    if not r.ok: return ("", Fattr3(), false)
    fh = r.fh
    attr = r.attr
  return (fh, attr, true)

proc nfsReaddirplusSock*(sock: AsyncSocket; timeoutMs: int; dirFh: string): Future[seq[DirEntry]] {.async.} =
  try:
    var req = rpcCallMsg(100003, 3, 17)
    req.xdrAddFh dirFh
    req.addU64 0'u64
    req.addU64 0'u64
    req.addU32 4096'u32
    req.addU32 32768'u32
    await sock.send(tcpRecord(req))
    let reply = await recvRpcReply(sock, timeoutMs)
    let (ok, pos0) = rpcReplyData(reply)
    if not ok: return
    var pos = pos0
    if pos + 4 > reply.len: return
    let nfsStat = readU32(reply, pos); pos += 4
    if nfsStat != 0: return
    xdrSkipPostOpAttr(reply, pos)
    if pos + 8 > reply.len: return
    pos += 8
    while pos + 4 <= reply.len:
      let vf = readU32(reply, pos); pos += 4
      if vf == 0: break
      let fileid = readU64(reply, pos); pos += 8
      let name = xdrReadString(reply, pos)
      pos += 8
      var isDir = false
      var size = 0'u64
      var mode = 0'u32
      if pos + 4 <= reply.len:
        let attrFollow = readU32(reply, pos); pos += 4
        if attrFollow != 0:
          let attr = xdrReadFattr3(reply, pos)
          isDir = attr.ftype == 2
          size = attr.size
          mode = attr.mode
      if pos + 4 <= reply.len:
        let fhFollow = readU32(reply, pos); pos += 4
        if fhFollow != 0:
          discard xdrReadFh(reply, pos)
      if name.len > 0 and name != "." and name != "..":
        result.add DirEntry(name: name, fileid: fileid, isDir: isDir, size: size, mode: mode)
  except: discard

proc nfsReadSock*(sock: AsyncSocket; timeoutMs: int; fh: string; offset: uint64; count: uint32): Future[tuple[data: string; eof: bool]] {.async.} =
  try:
    var req = rpcCallMsg(100003, 3, 6)
    req.xdrAddFh fh
    req.addU64 offset
    req.addU32 count
    await sock.send(tcpRecord(req))
    let reply = await recvRpcReply(sock, timeoutMs)
    let (ok, pos0) = rpcReplyData(reply)
    if not ok: return ("", true)
    var pos = pos0
    if pos + 4 > reply.len: return ("", true)
    let nfsStat = readU32(reply, pos); pos += 4
    if nfsStat != 0: return ("", true)
    xdrSkipPostOpAttr(reply, pos)
    if pos + 8 > reply.len: return ("", true)
    discard readU32(reply, pos); pos += 4
    let eof = readU32(reply, pos) != 0; pos += 4
    if pos + 4 > reply.len: return ("", eof)
    let dataLen = int(readU32(reply, pos)); pos += 4
    if pos + dataLen > reply.len: return (reply[pos ..< reply.len], eof)
    return (reply[pos ..< pos + dataLen], eof)
  except: discard
  return ("", true)

proc nfsReadFileSock*(sock: AsyncSocket; timeoutMs: int; fh: string; size: uint64): Future[string] {.async.} =
  var offset = 0'u64
  let chunkSize = 32768'u32
  while true:
    let (chunk, eof) = await nfsReadSock(sock, timeoutMs, fh, offset, chunkSize)
    result.add chunk
    offset += uint64(chunk.len)
    if eof or chunk.len == 0 or (size > 0 and offset >= size): break

proc nfsGetattrSock*(sock: AsyncSocket; timeoutMs: int; fh: string): Future[tuple[attr: Fattr3; ok: bool]] {.async.} =
  try:
    var req = rpcCallMsg(100003, 3, 1)
    req.xdrAddFh fh
    await sock.send(tcpRecord(req))
    let reply = await recvRpcReply(sock, timeoutMs)
    let (ok, pos0) = rpcReplyData(reply)
    if not ok: return (Fattr3(), false)
    var pos = pos0
    if pos + 4 > reply.len: return (Fattr3(), false)
    let nfsStat = readU32(reply, pos); pos += 4
    if nfsStat != 0: return (Fattr3(), false)
    let attr = xdrReadFattr3(reply, pos)
    return (attr, true)
  except: discard
  return (Fattr3(), false)

proc nfsCreateSock*(sock: AsyncSocket; timeoutMs: int; dirFh, name: string): Future[tuple[fh: string; ok: bool; errCode: uint32]] {.async.} =
  try:
    var req = rpcCallMsg(100003, 3, 8)
    req.xdrAddFh dirFh
    req.xdrAddString name
    req.addU32 0'u32
    req.addU32 1'u32; req.addU32 0o644'u32
    req.addU32 0'u32
    req.addU32 0'u32
    req.addU32 0'u32
    req.addU32 0'u32
    req.addU32 0'u32
    await sock.send(tcpRecord(req))
    let reply = await recvRpcReply(sock, timeoutMs)
    let (ok, pos0) = rpcReplyData(reply)
    if not ok: return ("", false, 0xffffffff'u32)
    var pos = pos0
    if pos + 4 > reply.len: return ("", false, 0xffffffff'u32)
    let nfsStat = readU32(reply, pos); pos += 4
    if nfsStat != 0: return ("", false, nfsStat)
    if pos + 4 > reply.len: return ("", false, 0xffffffff'u32)
    let fhFollow = readU32(reply, pos); pos += 4
    if fhFollow == 0: return ("", false, 0xffffffff'u32)
    let fh = xdrReadFh(reply, pos)
    return (fh, true, 0'u32)
  except: discard
  return ("", false, 0xffffffff'u32)

proc nfsWriteSock*(sock: AsyncSocket; timeoutMs: int; fh: string; offset: uint64; data: string): Future[tuple[written: int; ok: bool]] {.async.} =
  try:
    var req = rpcCallMsg(100003, 3, 7)
    req.xdrAddFh fh
    req.addU64 offset
    req.addU32 uint32(data.len)
    req.addU32 2'u32
    req.addU32 uint32(data.len)
    req.add data
    let pad = (4 - (data.len and 3)) and 3
    for _ in 0 ..< pad: req.add '\x00'
    await sock.send(tcpRecord(req))
    let reply = await recvRpcReply(sock, timeoutMs)
    let (ok, pos0) = rpcReplyData(reply)
    if not ok: return (0, false)
    var pos = pos0
    if pos + 4 > reply.len: return (0, false)
    let nfsStat = readU32(reply, pos); pos += 4
    if nfsStat != 0: return (0, false)
    if pos + 4 <= reply.len:
      let preFollow = readU32(reply, pos); pos += 4
      if preFollow != 0: pos += 20
    xdrSkipPostOpAttr(reply, pos)
    if pos + 4 > reply.len: return (0, false)
    let written = int(readU32(reply, pos))
    return (written, true)
  except: discard
  return (0, false)

proc nfsWriteFileSock*(sock: AsyncSocket; timeoutMs: int; fh: string; data: string): Future[tuple[written: int; ok: bool]] {.async.} =
  let chunkSize = 32768
  var offset = 0'u64
  while offset < uint64(data.len):
    let remaining = data.len - int(offset)
    let count = min(remaining, chunkSize)
    let chunk = data[int(offset) ..< int(offset) + count]
    let (written, ok) = await nfsWriteSock(sock, timeoutMs, fh, offset, chunk)
    if not ok or written == 0: return (int(offset), false)
    offset += uint64(written)
  return (int(offset), true)

proc nfsSetattrSock*(sock: AsyncSocket; timeoutMs: int; fh: string; mode: uint32; setMode: bool; uid, gid: uint32; setUid, setGid: bool): Future[tuple[ok: bool; errCode: uint32]] {.async.} =
  try:
    var req = rpcCallMsg(100003, 3, 2)
    req.xdrAddFh fh
    if setMode: req.addU32 1'u32; req.addU32 mode
    else: req.addU32 0'u32
    if setUid: req.addU32 1'u32; req.addU32 uid
    else: req.addU32 0'u32
    if setGid: req.addU32 1'u32; req.addU32 gid
    else: req.addU32 0'u32
    req.addU32 0'u32
    req.addU32 0'u32
    req.addU32 0'u32
    req.addU32 0'u32
    await sock.send(tcpRecord(req))
    let reply = await recvRpcReply(sock, timeoutMs)
    let (ok, pos0) = rpcReplyData(reply)
    if not ok: return (false, 0xffffffff'u32)
    var pos = pos0
    if pos + 4 > reply.len: return (false, 0xffffffff'u32)
    let nfsStat = readU32(reply, pos)
    return (nfsStat == 0, nfsStat)
  except: discard
  return (false, 0xffffffff'u32)

proc probeNfs*(host: string; port, timeoutMs: int): Future[NfsResult] {.async.} =
  result.host = host
  result.port = port

  let testSock = await connectTcp(host, 111, timeoutMs)
  if testSock.isNil: return
  testSock.close()
  result.reachable = true

  result.rpcServices = await portmapperDump(host, timeoutMs)

  var mountPort = 0
  var mountVers = 0'u32
  for svc in result.rpcServices:
    if svc.prog == 100003 and svc.proto == 6:
      let v = int(svc.vers)
      if v notin result.nfsVersions:
        result.nfsVersions.add v
    if svc.prog == 100005 and svc.proto == 6:
      if svc.vers > mountVers:
        mountVers = svc.vers
        mountPort = int(svc.port)

  result.mountPort = mountPort
  if mountPort > 0:
    result.exports = await mountExport(host, mountPort, timeoutMs)

proc nfsOpenSession*(host: string; mountPort, nfsPort, timeoutMs: int; exportPath: string): Future[NfsSession] {.async.} =
  let rootFh = await nfsMnt(host, mountPort, timeoutMs, exportPath)
  if rootFh.len == 0:
    raise newException(IOError, "MOUNT failed for " & exportPath)
  let nfsSock = await connectTcpPrivileged(host, nfsPort, timeoutMs)
  if nfsSock.isNil:
    raise newException(IOError, "NFS connect failed to " & host & ":" & $nfsPort)
  result = NfsSession(
    host: host,
    mountPort: mountPort,
    nfsPort: nfsPort,
    timeoutMs: timeoutMs,
    exportPath: exportPath,
    rootFh: rootFh,
    cwd: "/",
    sock: nfsSock,
  )

proc nfsCloseSession*(sess: NfsSession) =
  if not sess.sock.isNil:
    try: sess.sock.close() except: discard
