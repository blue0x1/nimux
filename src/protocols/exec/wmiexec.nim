import std/[asyncdispatch, strutils, random, times]

import ../smb/client as smb
import ../dcom/client as dcom
import ./output as execio

type
  WmiExecResult* = object
    host*: string
    username*: string
    domain*: string
    authenticated*: bool
    namespace*: string
    success*: bool
    output*: string
    bytesRead*: int
    message*: string
    error*: string

proc randomToken(): string =
  var rng = initRand(int(getTime().toUnix()) xor cast[int](addr result))
  for _ in 0 ..< 10:
    let c = rng.rand(35)
    if c < 10: result.add chr(ord('0') + c)
    else: result.add chr(ord('a') + (c - 10))

proc wmiExec*(host: string; port, timeoutMs: int;
              username, password, ntlmHash, domain, command: string;
              namespace = "root\\cimv2";
              authMethod: smb.SmbAuthMethod = smb.samNtlm;
              ccache = ""): Future[WmiExecResult] {.async.} =
  result.host = host
  result.username = username
  result.domain = domain
  result.namespace = namespace
  let cred = smb.SmbCredential(
    username: username, password: password,
    ntlmHash: ntlmHash, domain: domain,
    ccache: ccache)
  let outName = randomToken() & ".out"
  let wrapped = "cmd.exe /Q /c " & command &
    " 1> C:\\Windows\\Temp\\" & outName & " 2>&1"
  var session: dcom.WmiSession
  try:
    if authMethod == smb.samKerberos:
      session = await dcom.connectWbemKerb(host, port, timeoutMs, domain, "//./root/cimv2")
    else:
      session = await dcom.connectWbem(host, port, timeoutMs, cred, "//./root/cimv2")
    result.authenticated = true
    let inBlob = dcom.buildWin32ProcessCreateInputs(wrapped)
    let r = await session.execMethod("Win32_Process", "Create", inBlob)
    if not r.ok:
      result.error = "ExecMethod fault 0x" & r.faultStatus.toHex(8)
      result.message = result.error
      session.close()
      return
    result.success = true
    let outPath = "Temp\\" & outName
    let smbSession = await smb.establishSmbSession(host, 445, timeoutMs, cred, authMethod)
    if smbSession != nil and smbSession.authenticated and smbSession.adminTreeId != 0:
      let polled = await execio.pollOutputFile(smbSession.ctx,
        smbSession.adminTreeId, outPath)
      result.output = polled.data
      result.bytesRead = polled.data.len
    session.close()
    return
  except CatchableError as error:
    let msg = error.msg.splitLines()[0]
    result.error = msg
    result.message = msg
    if session != nil: session.close()
    return

proc openWmiExecSession*(host: string; port, timeoutMs: int;
                         username, password, ntlmHash, domain: string;
                         namespace = "root\\cimv2";
                         authMethod: smb.SmbAuthMethod = smb.samNtlm;
                         ccache = ""): Future[WmiExecResult] {.async.} =
  result = await wmiExec(host, port, timeoutMs, username, password, ntlmHash, domain,
                         "cd", namespace, authMethod, ccache)

proc runWmiExecShellCommand*(host: string; port, timeoutMs: int;
                             username, password, ntlmHash, domain, command: string;
                             namespace = "root\\cimv2";
                             authMethod: smb.SmbAuthMethod = smb.samNtlm;
                             ccache = ""):
    Future[tuple[output, err: string]] {.async.} =
  let r = await wmiExec(host, port, timeoutMs, username, password, ntlmHash,
                        domain, command, namespace, authMethod, ccache)
  result.output = r.output
  if not r.success: result.err = if r.error.len > 0: r.error else: r.message
