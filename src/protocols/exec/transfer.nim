## SMB file upload (`put`) and download (`get`) on top of the shared
## establishSmbSession + exec/output helpers. Supports arbitrary shares —
## you can read from C$ or write to a non-admin share by passing
## `--share <name>`.
##
## UNC paths accepted on the CLI side:
##   \\host\share\path\to\file
##   //host/share/path/to/file
##   share:path  (when --target supplies the host separately)
##
## The chunked write path here loops 60 KiB at a time so transfers aren't
## capped at the 60 KiB single-write limit of `execio.writeSmbFile`.

import std/[asyncdispatch, asyncnet, os, strutils]

import ../smb/client as smb

const
  TransferChunkFloor = 4 * 1024
  TransferChunkCeil = 60_000
type
  SmbTransferProgress* = proc(bytesDone, totalBytes: int; label: string; done: bool) {.closure, gcsafe.}

  SmbTransferResult* = object
    host*: string
    share*: string
    remotePath*: string
    localPath*: string
    bytes*: int
    files*: int
    success*: bool
    authenticated*: bool
    message*: string
    error*: string

proc putFileOnTree*(session: smb.SmbSession; treeId: uint32; share, remotePath,
                    localPath: string; progress: SmbTransferProgress = nil):
                    Future[SmbTransferResult] {.async.}
proc getFileOnTree*(session: smb.SmbSession; treeId: uint32; share, remotePath,
                    localPath: string; progress: SmbTransferProgress = nil):
                    Future[SmbTransferResult] {.async.}
proc deleteFileOnTree*(session: smb.SmbSession; treeId: uint32; share, remotePath: string):
                       Future[SmbTransferResult] {.async.}

proc ensureRemoteDirOnTree*(session: smb.SmbSession; treeId: uint32;
                            remoteDir: string): Future[bool] {.async.}

proc ensureRemoteDir*(host: string; port, timeoutMs: int;
                      username, password, ntlmHash, domain: string;
                      share, remoteDir: string;
                      authMethod: smb.SmbAuthMethod = smb.samNtlm; ccache = "";
                      krb5Config = ""): Future[SmbTransferResult] {.async.} =
  result.host = host
  result.share = share
  result.remotePath = remoteDir
  let credential = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain, ccache: ccache, krb5Config: krb5Config)
  let session = await smb.establishSmbSession(host, port, timeoutMs, credential, authMethod)
  if session == nil or not session.authenticated:
    result.message = if session == nil: "no session" else: session.message
    return
  result.authenticated = true
  let treeId = await smb.connectShareTree(session, share)
  if treeId == 0:
    result.message = "could not mount share \\\\" & host & "\\" & share
    return
  result.success = await ensureRemoteDirOnTree(session, treeId, remoteDir)
  result.message = if result.success: "directory ensured" else: "mkdir failed"

proc readU64Le(data: string; offset: int): uint64 =
  if offset + 7 >= data.len:
    return 0
  for shift in countup(0, 56, 8):
    result = result or (uint64(ord(data[offset + (shift div 8)])) shl shift)

proc readU32Le(data: string; offset: int): uint32 =
  if offset + 3 >= data.len:
    return 0
  uint32(ord(data[offset])) or
    (uint32(ord(data[offset + 1])) shl 8) or
    (uint32(ord(data[offset + 2])) shl 16) or
    (uint32(ord(data[offset + 3])) shl 24)

proc effectiveChunkSize(limit: uint32): int =
  let raw = if limit == 0: TransferChunkFloor else: int(limit)
  result = max(TransferChunkFloor, min(raw, TransferChunkCeil))

proc parseSmbWriteCount(response: string): int =
  let body = 4 + 64
  if response.len < body + 16:
    return -1
  let status = readU32Le(response, 12)
  if status != 0:
    return -1
  int(readU32Le(response, body + 4))

proc smbStatusDetail(status: uint32): string =
  case status
  of 0xC000007F'u32: "STATUS_DISK_FULL"
  of 0xC0000022'u32: "STATUS_ACCESS_DENIED"
  of 0xC0000034'u32: "STATUS_OBJECT_NAME_NOT_FOUND"
  of 0xC0000035'u32: "STATUS_OBJECT_NAME_COLLISION"
  else: ""

proc splitUnc*(spec: string): tuple[host, share, path: string] =
  var s = spec.replace('/', '\\')
  if s.startsWith("\\\\"):
    s = s[2 .. ^1]
  let firstSlash = s.find('\\')
  if firstSlash < 0:
    raise newException(ValueError, "expected \\\\host\\share\\path, got " & spec)
  result.host = s[0 ..< firstSlash]
  let rest = s[firstSlash + 1 .. ^1]
  let secondSlash = rest.find('\\')
  if secondSlash < 0:
    result.share = rest
    result.path = ""
  else:
    result.share = rest[0 ..< secondSlash]
    result.path = rest[secondSlash + 1 .. ^1]

proc putFile*(host: string; port, timeoutMs: int;
              username, password, ntlmHash, domain: string;
              share, remotePath, localPath: string;
              progress: SmbTransferProgress = nil;
              authMethod: smb.SmbAuthMethod = smb.samNtlm; ccache = "";
              krb5Config = ""): Future[SmbTransferResult] {.async.} =
  let credential = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain, ccache: ccache, krb5Config: krb5Config)
  let session = await smb.establishSmbSession(host, port, timeoutMs, credential, authMethod)
  if session == nil or not session.authenticated:
    result.message = if session == nil: "no session" else: session.message
    return
  let treeId = await smb.connectShareTree(session, share)
  if treeId == 0:
    result.message = "could not mount share \\\\" & host & "\\" & share
    return
  result = await putFileOnTree(session, treeId, share, remotePath, localPath, progress)

proc putFileOnTree*(session: smb.SmbSession; treeId: uint32; share, remotePath,
                    localPath: string; progress: SmbTransferProgress = nil):
                    Future[SmbTransferResult] {.async.} =
  result.host = session.ctx.host
  result.share = share
  result.remotePath = remotePath
  result.localPath = localPath
  if not fileExists(localPath):
    result.error = "local file not found: " & localPath
    return
  let contents = readFile(localPath)
  result.authenticated = true
  const DesiredAccess: uint32 = 0x00120196
  const CreateAlways: uint32 = 0x00000005
  const NonDirectoryFile: uint32 = 0x40
  let ctx = session.ctx
  let chunkSize = effectiveChunkSize(session.negotiate.maxWriteSize)
  if progress != nil:
    progress(0, contents.len, "upload", false)
  let createPkt = ctx.signed(smb.buildSmbFileCreateRequest(remotePath,
    DesiredAccess, CreateAlways, NonDirectoryFile,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(createPkt)
  let createResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  let fid = smb.fileIdFromCreateResponse(createResp)
  if fid.len != 16:
    result.message = "remote CREATE failed"
    return
  var offset = 0
  while offset < contents.len:
    let take = min(chunkSize, contents.len - offset)
    let chunk = contents[offset ..< offset + take]
    let writePkt = ctx.signed(smb.buildSmbWriteRequest(fid, chunk,
      ctx.nextMid(), ctx.sessionId, treeId, uint64(offset)))
    await ctx.socket.send(writePkt)
    let writeResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
    let writeStatus = if writeResp.len >= 16: readU32Le(writeResp, 12) else: 0xffffffff'u32
    if writeStatus != 0:
      result.message = "remote WRITE failed 0x" & writeStatus.toHex(8)
      let detail = smbStatusDetail(writeStatus)
      if detail.len > 0:
        result.message.add " (" & detail & ")"
      return
    let written = parseSmbWriteCount(writeResp)
    if written != take:
      result.message = "remote WRITE wrote " & $max(written, 0) & " of " & $take & " bytes"
      return
    offset += take
    if progress != nil:
      progress(offset, contents.len, "upload", false)
  let closePkt = ctx.signed(smb.buildSmbCloseRequest(fid,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(closePkt)
  discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  if progress != nil:
    progress(contents.len, contents.len, "upload", true)
  result.bytes = contents.len
  result.files = 1
  result.success = true
  result.message = "uploaded " & $contents.len & " bytes"

proc getFile*(host: string; port, timeoutMs: int;
              username, password, ntlmHash, domain: string;
              share, remotePath, localPath: string;
              progress: SmbTransferProgress = nil;
              authMethod: smb.SmbAuthMethod = smb.samNtlm; ccache = "";
              krb5Config = ""): Future[SmbTransferResult] {.async.} =
  let credential = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain, ccache: ccache, krb5Config: krb5Config)
  let session = await smb.establishSmbSession(host, port, timeoutMs, credential, authMethod)
  if session == nil or not session.authenticated:
    result.message = if session == nil: "no session" else: session.message
    return
  let treeId = await smb.connectShareTree(session, share)
  if treeId == 0:
    result.message = "could not mount share \\\\" & host & "\\" & share
    return
  result = await getFileOnTree(session, treeId, share, remotePath, localPath, progress)

proc deleteFile*(host: string; port, timeoutMs: int;
                 username, password, ntlmHash, domain: string;
                 share, remotePath: string;
                 authMethod: smb.SmbAuthMethod = smb.samNtlm; ccache = "";
                 krb5Config = ""): Future[SmbTransferResult] {.async.} =
  let credential = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain, ccache: ccache, krb5Config: krb5Config)
  let session = await smb.establishSmbSession(host, port, timeoutMs, credential, authMethod)
  if session == nil or not session.authenticated:
    result.message = if session == nil: "no session" else: session.message
    return
  let treeId = await smb.connectShareTree(session, share)
  if treeId == 0:
    result.message = "could not mount share \\\\" & host & "\\" & share
    return
  result = await deleteFileOnTree(session, treeId, share, remotePath)

proc getFileOnTree*(session: smb.SmbSession; treeId: uint32; share, remotePath,
                    localPath: string; progress: SmbTransferProgress = nil):
                    Future[SmbTransferResult] {.async.} =
  result.host = session.ctx.host
  result.share = share
  result.remotePath = remotePath
  result.localPath = localPath
  result.authenticated = true
  const DesiredAccess: uint32 = 0x00120089
  const CreateExisting: uint32 = 0x00000001
  const NonDirectoryFile: uint32 = 0x40
  let ctx = session.ctx
  let chunkSize = effectiveChunkSize(session.negotiate.maxReadSize)
  let createPkt = ctx.signed(smb.buildSmbFileCreateRequest(remotePath,
    DesiredAccess, CreateExisting, NonDirectoryFile,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(createPkt)
  let createResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  let fid = smb.fileIdFromCreateResponse(createResp)
  if fid.len != 16:
    result.message = "remote file not found or unreadable"
    return
  let total64 = readU64Le(createResp, 4 + 64 + 48)
  let total = if total64 > uint64(high(int)): high(int) else: int(total64)
  if progress != nil:
    progress(0, total, "download", false)
  var outFile: File
  try:
    outFile = open(localPath, fmWrite)
  except CatchableError as error:
    result.error = "local write failed: " & error.msg.splitLines()[0]
    return
  var offset: uint64 = 0
  var bytesWritten = 0
  try:
    while true:
      let readReq = ctx.signed(smb.buildSmbReadRequest(fid, chunkSize.uint32,
        ctx.nextMid(), ctx.sessionId, treeId, offset))
      await ctx.socket.send(readReq)
      let readResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
      let chunk = smb.parseSmbReadData(readResp)
      if chunk.len == 0:
        break
      outFile.write(chunk)
      bytesWritten += chunk.len
      offset += chunk.len.uint64
      if progress != nil:
        progress(bytesWritten, total, "download", false)
      if chunk.len < chunkSize:
        break
    let closePkt = ctx.signed(smb.buildSmbCloseRequest(fid,
      ctx.nextMid(), ctx.sessionId, treeId))
    await ctx.socket.send(closePkt)
    discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  finally:
    try: outFile.close()
    except CatchableError: discard
  if progress != nil:
    progress(bytesWritten, total, "download", true)
  result.bytes = bytesWritten
  result.files = 1
  result.success = true
  result.message = "downloaded " & $bytesWritten & " bytes"

proc readFileIntoMemory*(session: smb.SmbSession; treeId: uint32; remotePath: string;
                         maxBytes = 4 * 1024 * 1024): Future[string] {.async.} =
  const DesiredAccess: uint32 = 0x00120089
  const CreateExisting: uint32 = 0x00000001
  const NonDirectoryFile: uint32 = 0x40
  let ctx = session.ctx
  let chunkSize = effectiveChunkSize(session.negotiate.maxReadSize)
  let createPkt = ctx.signed(smb.buildSmbFileCreateRequest(remotePath,
    DesiredAccess, CreateExisting, NonDirectoryFile,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(createPkt)
  let createResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  let fid = smb.fileIdFromCreateResponse(createResp)
  if fid.len != 16: return ""
  var offset: uint64 = 0
  try:
    while result.len < maxBytes:
      let readReq = ctx.signed(smb.buildSmbReadRequest(fid, chunkSize.uint32,
        ctx.nextMid(), ctx.sessionId, treeId, offset))
      await ctx.socket.send(readReq)
      let readResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
      let chunk = smb.parseSmbReadData(readResp)
      if chunk.len == 0: break
      result.add chunk
      offset += chunk.len.uint64
      if chunk.len < chunkSize: break
  except CatchableError:
    discard
  let closePkt = ctx.signed(smb.buildSmbCloseRequest(fid,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(closePkt)
  discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)

proc deleteFileOnTree*(session: smb.SmbSession; treeId: uint32; share, remotePath: string):
                       Future[SmbTransferResult] {.async.} =
  result.host = session.ctx.host
  result.share = share
  result.remotePath = remotePath
  result.authenticated = true
  const DesiredAccess: uint32 = 0x00010000
  const CreateExisting: uint32 = 0x00000001
  const NonDirectoryFile: uint32 = 0x40
  let ctx = session.ctx
  let createPkt = ctx.signed(smb.buildSmbFileCreateRequest(remotePath,
    DesiredAccess, CreateExisting, NonDirectoryFile,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(createPkt)
  let createResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  let fid = smb.fileIdFromCreateResponse(createResp)
  if fid.len != 16:
    result.message = "remote file not found or not deletable"
    return
  let delPkt = ctx.signed(smb.buildSmbSetInfoDispositionDelete(fid,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(delPkt)
  let delResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  let delStatus = if delResp.len >= 16: readU32Le(delResp, 12) else: 0xffffffff'u32
  let closePkt = ctx.signed(smb.buildSmbCloseRequest(fid,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(closePkt)
  discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  if delStatus != 0:
    result.message = "remote DELETE failed 0x" & delStatus.toHex(8)
    return
  result.success = true
  result.message = "deleted"

proc ensureRemoteDirOnTree*(session: smb.SmbSession; treeId: uint32;
                            remoteDir: string): Future[bool] {.async.} =
  if remoteDir.len == 0:
    return true
  const DesiredAccess: uint32 = 0x00100081
  const OpenIf: uint32 = 0x00000003
  const DirectoryFile: uint32 = 0x00000001
  let ctx = session.ctx
  var current = ""
  for part in remoteDir.replace('/', '\\').split('\\'):
    if part.len == 0:
      continue
    if current.len > 0:
      current.add "\\"
    current.add part
    let createPkt = ctx.signed(smb.buildSmbFileCreateRequest(current,
      DesiredAccess, OpenIf, DirectoryFile,
      ctx.nextMid(), ctx.sessionId, treeId))
    await ctx.socket.send(createPkt)
    let createResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
    let fid = smb.fileIdFromCreateResponse(createResp)
    if fid.len != 16:
      return false
    let closePkt = ctx.signed(smb.buildSmbCloseRequest(fid,
      ctx.nextMid(), ctx.sessionId, treeId))
    await ctx.socket.send(closePkt)
    discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  return true
