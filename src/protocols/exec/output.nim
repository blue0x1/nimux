## Shared SMB file-transfer helpers used by every execution module
## (smbexec, plus the future psexec/atexec/wmiexec). All three need:
##   * write a small helper file (batch script, service binary) to ADMIN$
##   * read the captured-stdout file the executed command wrote
##   * delete-on-close cleanup for whatever we dropped
##
## Living in `protocols/exec/output.nim` so individual exec modules don't
## reimplement the same five SMB packets with subtly different bugs.

import std/[asyncdispatch, asyncnet]

import ../smb/client as smb

const
  AccessRead*: uint32        = 0x00120089
  AccessReadDelete*: uint32  = 0x00130089
  AccessWriteCreate*: uint32 = 0x00120196
  DispOpenExisting*: uint32  = 0x00000001
  DispOverwriteIf*: uint32   = 0x00000005
  OptNonDirectory*: uint32   = 0x00000040
  OptDeleteOnClose*: uint32  = 0x00001040

proc readSmbFile*(ctx: smb.SmbRpcCtx; treeId: uint32;
                  filePath: string; deleteOnClose: bool): Future[tuple[exists: bool; data: string]] {.async.} =
  let access  = if deleteOnClose: AccessReadDelete else: AccessRead
  let options = if deleteOnClose: OptDeleteOnClose else: OptNonDirectory
  let createPkt = ctx.signed(smb.buildSmbFileCreateRequest(filePath,
    access, DispOpenExisting, options,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(createPkt)
  let createResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  let fid = smb.fileIdFromCreateResponse(createResp)
  if fid.len != 16:
    return (exists: false, data: "")
  result.exists = true
  var offset: uint64 = 0
  while true:
    let readReq = ctx.signed(smb.buildSmbReadRequest(fid, 65536'u32,
      ctx.nextMid(), ctx.sessionId, treeId, offset))
    await ctx.socket.send(readReq)
    let readResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
    let chunk = smb.parseSmbReadData(readResp)
    if chunk.len == 0: break
    result.data.add chunk
    offset += chunk.len.uint64
    if chunk.len < 65536: break
  let closePkt = ctx.signed(smb.buildSmbCloseRequest(fid,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(closePkt)
  discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)

proc writeSmbFile*(ctx: smb.SmbRpcCtx; treeId: uint32;
                   filePath, contents: string): Future[bool] {.async.} =
  if contents.len > 60_000:
    raise newException(ValueError, "writeSmbFile: payload exceeds 60 KiB single-write limit")
  let createPkt = ctx.signed(smb.buildSmbFileCreateRequest(filePath,
    AccessWriteCreate, DispOverwriteIf, OptNonDirectory,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(createPkt)
  let createResp = await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  let fid = smb.fileIdFromCreateResponse(createResp)
  if fid.len != 16: return false
  let writePkt = ctx.signed(smb.buildSmbWriteRequest(fid, contents,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(writePkt)
  discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  let closePkt = ctx.signed(smb.buildSmbCloseRequest(fid,
    ctx.nextMid(), ctx.sessionId, treeId))
  await ctx.socket.send(closePkt)
  discard await smb.recvOneSmb(ctx.socket, ctx.timeoutMs)
  return true

proc pollOutputFile*(ctx: smb.SmbRpcCtx; treeId: uint32;
                     filePath: string; attempts = 12;
                     initialDelayMs = 400; backoffMs = 200;
                     preDelayMs = 0): Future[tuple[stable: bool; data: string]] {.async.} =
  if preDelayMs > 0:
    await sleepAsync(preDelayMs)
  var data = ""
  var lastLen = -1
  for attempt in 0 ..< attempts:
    let r = await readSmbFile(ctx, treeId, filePath, false)
    if r.exists:
      if r.data.len == lastLen and r.data.len > 0:
        data = r.data
        result.stable = true
        break
      lastLen = r.data.len
      data = r.data
    await sleepAsync(initialDelayMs + attempt * backoffMs)
  if data.len == 0:
    await sleepAsync(5000)
    let late = await readSmbFile(ctx, treeId, filePath, false)
    if late.exists:
      data = late.data
  let final = await readSmbFile(ctx, treeId, filePath, true)
  if final.exists and final.data.len >= data.len:
    data = final.data
  result.data = data
