import std/[asyncdispatch, strutils, tables, unicode]

import ../dcerpc/client as rpc
import ../smb/client as smbntlm

proc toUtf16Le*(s: string): string =
  for rune in s.runes:
    var code = int(rune)
    if code > 0xFFFF: code = 0xFFFD
    result.add char(code and 0xff)
    result.add char((code shr 8) and 0xff)

proc toUtf16LeZ*(s: string): string =
  result = toUtf16Le(s)
  result.add char(0)
  result.add char(0)

proc addU8*(d: var string; v: uint8) =
  d.add char(int(v) and 0xff)

proc addU16Le*(d: var string; v: uint16) =
  d.add char(int(v) and 0xff)
  d.add char((int(v) shr 8) and 0xff)

proc addU32Le*(d: var string; v: uint32) =
  d.add char(int(v) and 0xff)
  d.add char((int(v) shr 8) and 0xff)
  d.add char((int(v) shr 16) and 0xff)
  d.add char((int(v) shr 24) and 0xff)

proc addU64Le*(d: var string; v: uint64) =
  for i in 0 ..< 8:
    d.add char(int((v shr (i * 8))) and 0xff)

proc setU32Le*(d: var string; o: int; v: uint32) =
  d[o]   = chr(int(v) and 0xff)
  d[o+1] = chr((int(v) shr 8) and 0xff)
  d[o+2] = chr((int(v) shr 16) and 0xff)
  d[o+3] = chr((int(v) shr 24) and 0xff)

proc padTo4*(d: var string) =
  while d.len mod 4 != 0: d.add char(0)

proc bytesToStr*(b: openArray[byte]): string =
  result = newString(b.len)
  for i, x in b: result[i] = chr(int(x))

const
  CimTypeSint8*    = 0x10'u32
  CimTypeUint8*    = 0x11'u32
  CimTypeSint16*   = 0x02'u32
  CimTypeUint16*   = 0x12'u32
  CimTypeSint32*   = 0x03'u32
  CimTypeUint32*   = 0x13'u32
  CimTypeSint64*   = 0x14'u32
  CimTypeUint64*   = 0x15'u32
  CimTypeReal32*   = 0x04'u32
  CimTypeReal64*   = 0x05'u32
  CimTypeBoolean*  = 0x0b'u32
  CimTypeString*   = 0x08'u32
  CimTypeDatetime* = 0x65'u32
  CimTypeReference* = 0x66'u32
  CimTypeChar16*   = 0x67'u32
  CimTypeObject*   = 0x0d'u32
  CimArrayFlag*    = 0x2000'u32
  CimInheritedFlag* = 0x4000'u32

  HeapNullOffset*: uint32 = 0xffffffff'u32
  HeapReadOnlyFlag*: uint32 = 0x80000000'u32

  ObjectFlagCimInstance* = 0x02'u8
  ObjectFlagDecoration*  = 0x04'u8
  ObjectFlagPrototype*   = 0x10'u8

  PropertyFlagDefault* = 0x01'u8
  PropertyFlagInherited* = 0x02'u8

  QualifierFlavorPropagateToInstance* = 0x01'u32
  QualifierFlavorPropagateToSubclass* = 0x02'u32
  QualifierFlavorOverridable* = 0x10'u32
  QualifierFlavorAmended* = 0x80'u32

type
  WmioHeap* = ref object
    data*: string
    stringIndex: Table[string, uint32]

proc newHeap*(): WmioHeap =
  WmioHeap(data: "", stringIndex: initTable[string, uint32]())

proc heapStr*(h: WmioHeap; s: string): uint32 =
  if h.stringIndex.hasKey(s): return h.stringIndex[s]
  let off = uint32(h.data.len)
  h.stringIndex[s] = off
  h.data.addU8 0
  h.data.add s
  h.data.addU8 0
  return off

proc heapWStr*(h: WmioHeap; s: string): uint32 =
  let key = "W:" & s
  if h.stringIndex.hasKey(key): return h.stringIndex[key]
  let off = uint32(h.data.len)
  h.stringIndex[key] = off
  h.data.addU8 1
  h.data.add toUtf16Le(s)
  h.data.addU8 0; h.data.addU8 0
  return off

proc heapRaw*(h: WmioHeap; b: string): uint32 =
  let off = uint32(h.data.len)
  h.data.add b
  return off

proc len*(h: WmioHeap): int = h.data.len

proc encodeHeap*(h: WmioHeap): string =
  result.addU32Le uint32(h.data.len) or HeapReadOnlyFlag
  result.add h.data

type
  VariantKind* = enum
    vkNone, vkBool, vkSint8, vkUint8, vkSint16, vkUint16,
    vkSint32, vkUint32, vkSint64, vkUint64,
    vkReal32, vkReal64, vkString, vkReference, vkDatetime,
    vkChar16, vkObject

  WmioVariant* = object
    cimType*: uint32
    case kind*: VariantKind
    of vkBool: boolVal*: bool
    of vkSint8: i8Val*: int8
    of vkUint8: u8Val*: uint8
    of vkSint16: i16Val*: int16
    of vkUint16, vkChar16: u16Val*: uint16
    of vkSint32: i32Val*: int32
    of vkUint32: u32Val*: uint32
    of vkSint64: i64Val*: int64
    of vkUint64: u64Val*: uint64
    of vkReal32: f32Val*: float32
    of vkReal64: f64Val*: float64
    of vkString, vkReference, vkDatetime: strVal*: string
    of vkObject: objBytes*: string
    of vkNone: discard

proc encodeVariant*(h: WmioHeap; v: WmioVariant): string =
  case v.kind
  of vkBool: result.addU16Le (if v.boolVal: 0xffff'u16 else: 0'u16)
  of vkSint8: result.addU8 uint8(v.i8Val)
  of vkUint8: result.addU8 v.u8Val
  of vkSint16: result.addU16Le uint16(v.i16Val)
  of vkUint16, vkChar16: result.addU16Le v.u16Val
  of vkSint32: result.addU32Le uint32(v.i32Val)
  of vkUint32: result.addU32Le v.u32Val
  of vkSint64: result.addU64Le uint64(v.i64Val)
  of vkUint64: result.addU64Le v.u64Val
  of vkReal32: result.addU32Le cast[uint32](v.f32Val)
  of vkReal64: result.addU64Le cast[uint64](v.f64Val)
  of vkString, vkReference, vkDatetime: result.addU32Le h.heapStr(v.strVal)
  of vkObject: result.addU32Le h.heapRaw(v.objBytes)
  of vkNone: result.addU32Le HeapNullOffset

proc variantTypeSize*(cimType: uint32): int =
  case cimType and 0x1fff
  of CimTypeBoolean, CimTypeSint8, CimTypeUint8: 1
  of CimTypeSint16, CimTypeUint16, CimTypeChar16: 2
  of CimTypeSint32, CimTypeUint32, CimTypeReal32: 4
  of CimTypeSint64, CimTypeUint64, CimTypeReal64: 8
  of CimTypeString, CimTypeReference, CimTypeDatetime, CimTypeObject: 4
  else: 4

proc nullVariantBytes*(cimType: uint32): string =
  let sz = variantTypeSize(cimType)
  case cimType and 0x1fff
  of CimTypeString, CimTypeReference, CimTypeDatetime, CimTypeObject:
    result.addU32Le 0
  else:
    result = newString(sz)

proc strVariant*(s: string): WmioVariant =
  WmioVariant(cimType: CimTypeString, kind: vkString, strVal: s)

proc i32Variant*(v: int32): WmioVariant =
  WmioVariant(cimType: CimTypeSint32, kind: vkSint32, i32Val: v)

proc boolVariant*(b: bool): WmioVariant =
  WmioVariant(cimType: CimTypeBoolean, kind: vkBool, boolVal: b)

type
  WmioQualifier* = object
    name*: string
    flavor*: uint32
    cimType*: uint32
    value*: WmioVariant

proc qualifierNameRef(h: WmioHeap; name: string): uint32 =
  case name
  of "key":      return 0x80000001'u32
  of "dynamic":  return 0x80000007'u32
  of "provider": return 0x80000006'u32
  of "CIMTYPE":  return 0x8000000a'u32
  else:          return h.heapStr(name)

proc encodeQualifier*(h: WmioHeap; q: WmioQualifier): string =
  result.addU32Le qualifierNameRef(h, q.name)
  result.addU8 uint8(q.flavor and 0xff)
  result.addU32Le q.cimType
  result.add encodeVariant(h, q.value)

proc encodeQualifierSet*(h: WmioHeap; quals: seq[WmioQualifier]): string =
  var body = ""
  body.addU32Le 0
  for q in quals: body.add encodeQualifier(h, q)
  let total = uint32(body.len)
  setU32Le(body, 0, total)
  return body

proc emptyQualifierSet*(): string =
  result.addU32Le 4

proc mkQualifier*(name: string; flavor: uint32; v: WmioVariant): WmioQualifier =
  WmioQualifier(name: name, flavor: flavor, cimType: v.cimType, value: v)

proc qualifierKey*(): WmioQualifier =
  mkQualifier("key", QualifierFlavorPropagateToInstance or QualifierFlavorPropagateToSubclass, boolVariant(true))

proc qualifierIn*(): WmioQualifier =
  mkQualifier("in", QualifierFlavorPropagateToInstance or QualifierFlavorPropagateToSubclass, boolVariant(true))

proc qualifierOut*(): WmioQualifier =
  mkQualifier("out", QualifierFlavorPropagateToInstance or QualifierFlavorPropagateToSubclass, boolVariant(true))

proc qualifierId*(id: int32): WmioQualifier =
  mkQualifier("ID", QualifierFlavorPropagateToInstance or QualifierFlavorPropagateToSubclass, i32Variant(id))

proc qualifierDescription*(desc: string): WmioQualifier =
  mkQualifier("Description",
    QualifierFlavorAmended or QualifierFlavorPropagateToInstance or QualifierFlavorPropagateToSubclass,
    strVariant(desc))

proc qualifierAbstract*(): WmioQualifier =
  mkQualifier("abstract", QualifierFlavorPropagateToSubclass, boolVariant(true))

proc qualifierDynamic*(): WmioQualifier =
  mkQualifier("dynamic", QualifierFlavorPropagateToInstance or QualifierFlavorPropagateToSubclass, boolVariant(true))

proc qualifierProvider*(name: string): WmioQualifier =
  mkQualifier("provider", QualifierFlavorPropagateToInstance or QualifierFlavorPropagateToSubclass, strVariant(name))

proc qualifierCimType*(typeName: string): WmioQualifier =
  mkQualifier("CIMTYPE", QualifierFlavorPropagateToSubclass, strVariant(typeName))

proc encodeDerivationList*(parents: seq[string]): string =
  var body = ""
  for p in parents:
    body.addU8 0
    body.add p
    body.addU8 0
    body.addU32Le 0
  let total = uint32(body.len + 4)
  result.addU32Le total
  result.add body

proc emptyDerivationList*(): string =
  result.addU32Le 4


type
  WmioProperty* = object
    name*: string
    cimType*: uint32
    declaredOrder*: uint16
    valueOffset*: uint32
    classOfOrigin*: uint32
    qualifiers*: seq[WmioQualifier]
    hasDefault*: bool
    defaultValue*: WmioVariant
    isInherited*: bool

  WmioClass* = object
    className*: string
    parentClassName*: string
    derivation*: seq[string]
    properties*: seq[WmioProperty]
    qualifiers*: seq[WmioQualifier]
    methods*: string

proc encodePropertyInfoInHeap(h: WmioHeap; p: WmioProperty): uint32 =
  var info = ""
  info.addU32Le p.cimType
  info.addU16Le p.declaredOrder
  info.addU32Le p.valueOffset
  info.addU32Le p.classOfOrigin
  info.add encodeQualifierSet(h, p.qualifiers)
  return h.heapRaw(info)

proc encodePropertyLookupTable(h: WmioHeap; props: seq[WmioProperty]): string =
  result.addU32Le uint32(props.len)
  for p in props:
    let nameRef = h.heapStr(p.name)
    let infoRef = encodePropertyInfoInHeap(h, p)
    result.addU32Le nameRef
    result.addU32Le infoRef

proc encodeClassNdValueTable(props: seq[WmioProperty]): string =
  let n = props.len
  if n == 0: return ""
  let ndBytes = (n + 3) div 4
  var ndTable = newString(ndBytes)
  for i in 0 ..< n:
    let bit = i * 2
    ndTable[bit div 8] = chr(ord(ndTable[bit div 8]) or (1 shl (bit mod 8)))
  var valTable = ""
  for p in props:
    let ct = p.cimType and not (CimInheritedFlag or CimArrayFlag)
    case ct
    of CimTypeBoolean: valTable.addU16Le 0
    of CimTypeSint8, CimTypeUint8: valTable.addU8 0
    of CimTypeSint16, CimTypeUint16, CimTypeChar16: valTable.addU16Le 0
    else: valTable.addU32Le 0
  result = ndTable & valTable

proc encodeClassPart*(cls: WmioClass): string =
  let h = newHeap()
  let classNameRef = h.heapStr(cls.className)
  let derivList = encodeDerivationList(cls.derivation)
  let classQS = encodeQualifierSet(h, cls.qualifiers)
  let propTable = encodePropertyLookupTable(h, cls.properties)
  let ndValueTable = encodeClassNdValueTable(cls.properties)
  let ndValueTableLen = uint32(ndValueTable.len)
  let classHeap = encodeHeap(h)
  let bodyLen = uint32(derivList.len + classQS.len + propTable.len + ndValueTable.len)
  let encodingLength = 13'u32 + bodyLen + uint32(classHeap.len)
  var header = ""
  header.addU32Le encodingLength
  header.addU8 0
  header.addU32Le classNameRef
  header.addU32Le ndValueTableLen
  result = header & derivList & classQS & propTable & ndValueTable & classHeap

type
  WmioInstanceValue* = object
    name*: string
    cimType*: uint32
    isNull*: bool
    value*: WmioVariant

proc findValue(values: seq[WmioInstanceValue]; name: string): int =
  for i, v in values:
    if v.name == name: return i
  return -1

proc encodeInstanceNdTable*(cls: WmioClass; values: seq[WmioInstanceValue]): string =
  let n = cls.properties.len
  let nbytes = (n * 2 + 7) div 8
  result = newString(nbytes)
  for i, p in cls.properties:
    let idx = findValue(values, p.name)
    let isNull = idx < 0 or values[idx].isNull
    if isNull:
      let nullBit = i * 2
      result[nullBit div 8] = chr(ord(result[nullBit div 8]) or (1 shl (nullBit mod 8)))
      let ct = p.cimType and not (CimInheritedFlag or CimArrayFlag)
      if ct == CimTypeObject:
        let inhBit = i * 2 + 1
        result[inhBit div 8] = chr(ord(result[inhBit div 8]) or (1 shl (inhBit mod 8)))

proc encodeInstanceDataTable*(h: WmioHeap; cls: WmioClass;
                              values: seq[WmioInstanceValue]): string =
  for p in cls.properties:
    let idx = findValue(values, p.name)
    if idx < 0 or values[idx].isNull:
      result.add nullVariantBytes(p.cimType)
    else:
      let ct = p.cimType and not (CimInheritedFlag or CimArrayFlag)
      case ct
      of CimTypeString, CimTypeReference, CimTypeDatetime:
        result.addU32Le h.heapWStr(values[idx].value.strVal)
      else:
        result.add encodeVariant(h, values[idx].value)

type
  WmioObjectBlock* = object
    flags*: uint8
    serverName*: string
    namespace*: string
    ancestors*: seq[WmioClass]
    currentClass*: WmioClass
    instanceValues*: seq[WmioInstanceValue]
    methodsTail*: string

proc encodeObjectBlock*(blk: WmioObjectBlock): string =
  result.addU8 blk.flags
  let classPart = encodeClassPart(blk.currentClass)
  result.add classPart
  if (blk.flags and ObjectFlagCimInstance) != 0:
    let ih = newHeap()
    discard ih.heapStr(blk.currentClass.className)
    let instNd = encodeInstanceNdTable(blk.currentClass, blk.instanceValues)
    let instVal = encodeInstanceDataTable(ih, blk.currentClass, blk.instanceValues)
    let instNdValue = instNd & instVal
    let instQS = "\x04\x00\x00\x00\x01"
    let instHeap = encodeHeap(ih)
    let encLen = uint32(4 + 1 + 4 + instNdValue.len + instQS.len + instHeap.len)
    result.addU32Le encLen
    result.addU8 0
    result.addU32Le 0'u32
    result.add instNdValue
    result.add instQS
    result.add instHeap

proc encodeEncodingUnit*(objBlock: string): string =
  result.addU32Le 0x12345678'u32
  result.addU32Le uint32(objBlock.len)
  result.add objBlock

const IID_IWbemClassObject* = [
  byte 0x81, 0xa6, 0x12, 0xdc, 0x7f, 0x73, 0xcf, 0x11,
       0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24]

const CLSID_WbemClassObject* = [
  byte 0x12, 0xf8, 0x90, 0x45, 0x3a, 0x1d, 0xd0, 0x11,
       0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24]

proc encodeObjRefCustom*(encodingUnit: string): string =
  result.add "MEOW"
  result.addU32Le 0x00000004'u32
  result.add bytesToStr(IID_IWbemClassObject)
  result.add bytesToStr(CLSID_WbemClassObject)
  result.addU32Le 0
  result.addU32Le uint32(encodingUnit.len)
  result.add encodingUnit

proc buildSystemClass*(): WmioClass =
  WmioClass(className: "__SystemClass", parentClassName: "",
            derivation: @[], properties: @[],
            qualifiers: @[qualifierAbstract()], methods: "")

proc buildParametersClass*(): WmioClass =
  WmioClass(className: "__PARAMETERS", parentClassName: "__SystemClass",
            derivation: @["__SystemClass"], properties: @[],
            qualifiers: @[qualifierAbstract()], methods: "")

proc buildCimManagedSystemElement*(): WmioClass =
  WmioClass(
    className: "CIM_ManagedSystemElement", parentClassName: "",
    derivation: @[],
    qualifiers: @[qualifierAbstract(), qualifierDescription("CIM_ManagedSystemElement is the base class for the System Element hierarchy")],
    properties: @[
      WmioProperty(name: "Caption", cimType: CimTypeString, declaredOrder: 0, valueOffset: 0, classOfOrigin: 0, qualifiers: @[qualifierCimType("string")], hasDefault: false),
      WmioProperty(name: "Description", cimType: CimTypeString, declaredOrder: 1, valueOffset: 4, classOfOrigin: 0, qualifiers: @[qualifierCimType("string")], hasDefault: false),
      WmioProperty(name: "InstallDate", cimType: CimTypeDatetime, declaredOrder: 2, valueOffset: 8, classOfOrigin: 0, qualifiers: @[qualifierCimType("datetime")], hasDefault: false),
      WmioProperty(name: "Name", cimType: CimTypeString, declaredOrder: 3, valueOffset: 12, classOfOrigin: 0, qualifiers: @[qualifierCimType("string")], hasDefault: false),
      WmioProperty(name: "Status", cimType: CimTypeString, declaredOrder: 4, valueOffset: 16, classOfOrigin: 0, qualifiers: @[qualifierCimType("string")], hasDefault: false)
    ])

proc buildCimLogicalElement*(): WmioClass =
  WmioClass(className: "CIM_LogicalElement", parentClassName: "CIM_ManagedSystemElement",
            derivation: @["CIM_ManagedSystemElement"],
            qualifiers: @[qualifierAbstract(), qualifierDescription("Abstract base class")],
            properties: @[])

proc buildCimProcess*(): WmioClass =
  WmioClass(
    className: "CIM_Process", parentClassName: "CIM_LogicalElement",
    derivation: @["CIM_LogicalElement", "CIM_ManagedSystemElement"],
    qualifiers: @[qualifierAbstract(), qualifierDescription("Each instance describes a single process")],
    properties: @[
      WmioProperty(name: "Handle", cimType: CimTypeString, declaredOrder: 0, valueOffset: 0, classOfOrigin: 0, qualifiers: @[qualifierKey(), qualifierCimType("string")], hasDefault: false),
      WmioProperty(name: "CreationDate", cimType: CimTypeDatetime, declaredOrder: 1, valueOffset: 4, classOfOrigin: 0, qualifiers: @[qualifierCimType("datetime")], hasDefault: false),
      WmioProperty(name: "Priority", cimType: CimTypeUint32, declaredOrder: 2, valueOffset: 8, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint32")], hasDefault: false)
    ])

proc buildWin32ProcessFull*(): WmioClass =
  WmioClass(
    className: "Win32_Process", parentClassName: "CIM_Process",
    derivation: @["CIM_Process", "CIM_LogicalElement", "CIM_ManagedSystemElement"],
    qualifiers: @[qualifierDynamic(), qualifierProvider("CIMWin32"),
                  qualifierDescription("Win32_Process represents a sequence of events on a Windows system")],
    properties: @[
      WmioProperty(name: "Handle", cimType: CimTypeString or CimInheritedFlag, declaredOrder: 0, valueOffset: 0, classOfOrigin: 0, qualifiers: @[qualifierKey(), qualifierCimType("string")], hasDefault: false),
      WmioProperty(name: "ProcessId", cimType: CimTypeUint32, declaredOrder: 1, valueOffset: 4, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint32")], hasDefault: false),
      WmioProperty(name: "CommandLine", cimType: CimTypeString, declaredOrder: 2, valueOffset: 8, classOfOrigin: 0, qualifiers: @[qualifierCimType("string")], hasDefault: false),
      WmioProperty(name: "ExecutablePath", cimType: CimTypeString, declaredOrder: 3, valueOffset: 12, classOfOrigin: 0, qualifiers: @[qualifierCimType("string")], hasDefault: false)
    ])

proc buildWin32ProcessStartup*(): WmioClass =
  WmioClass(
    className: "Win32_ProcessStartup",
    parentClassName: "Win32_MethodParameterClass",
    derivation: @["Win32_MethodParameterClass", "__PARAMETERS", "__SystemClass"],
    qualifiers: @[qualifierAbstract(), qualifierDescription("Used to specify additional information for a Win32_Process")],
    properties: @[
      WmioProperty(name: "CreateFlags", cimType: CimTypeUint32, declaredOrder: 0, valueOffset: 0, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint32")], hasDefault: false),
      WmioProperty(name: "EnvironmentVariables", cimType: CimTypeString or CimArrayFlag, declaredOrder: 1, valueOffset: 4, classOfOrigin: 0, qualifiers: @[qualifierCimType("string")], hasDefault: false),
      WmioProperty(name: "ErrorMode", cimType: CimTypeUint16, declaredOrder: 2, valueOffset: 8, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint16")], hasDefault: false),
      WmioProperty(name: "FillAttribute", cimType: CimTypeUint32, declaredOrder: 3, valueOffset: 10, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint32")], hasDefault: false),
      WmioProperty(name: "PriorityClass", cimType: CimTypeUint32, declaredOrder: 4, valueOffset: 14, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint32")], hasDefault: false),
      WmioProperty(name: "ShowWindow", cimType: CimTypeUint16, declaredOrder: 5, valueOffset: 18, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint16")], hasDefault: false),
      WmioProperty(name: "Title", cimType: CimTypeString, declaredOrder: 6, valueOffset: 20, classOfOrigin: 0, qualifiers: @[qualifierCimType("string")], hasDefault: false),
      WmioProperty(name: "WinstationDesktop", cimType: CimTypeString, declaredOrder: 7, valueOffset: 24, classOfOrigin: 0, qualifiers: @[qualifierCimType("string")], hasDefault: false),
      WmioProperty(name: "X", cimType: CimTypeUint32, declaredOrder: 8, valueOffset: 28, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint32")], hasDefault: false),
      WmioProperty(name: "XCountChars", cimType: CimTypeUint32, declaredOrder: 9, valueOffset: 32, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint32")], hasDefault: false),
      WmioProperty(name: "XSize", cimType: CimTypeUint32, declaredOrder: 10, valueOffset: 36, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint32")], hasDefault: false),
      WmioProperty(name: "Y", cimType: CimTypeUint32, declaredOrder: 11, valueOffset: 40, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint32")], hasDefault: false),
      WmioProperty(name: "YCountChars", cimType: CimTypeUint32, declaredOrder: 12, valueOffset: 44, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint32")], hasDefault: false),
      WmioProperty(name: "YSize", cimType: CimTypeUint32, declaredOrder: 13, valueOffset: 48, classOfOrigin: 0, qualifiers: @[qualifierCimType("uint32")], hasDefault: false)
    ])

type
  WmioMethod* = object
    name*: string
    flags*: uint8
    origin*: uint32
    qualifiers*: seq[WmioQualifier]
    inputSignature*: string
    outputSignature*: string


const
  IRemoteSCMActivatorUuidBytes* = [
    byte 0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
  IRemoteSCMActivatorMajor* = 0'u16
  IRemoteSCMActivatorMinor* = 0'u16

  IObjectExporterUuidBytes* = [
    byte 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10,
         0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a]
  IObjectExporterMajor* = 0'u16
  IObjectExporterMinor* = 0'u16

  CLSID_WbemLevel1Login* = [
    byte 0x5e, 0xf0, 0xc3, 0x8b, 0x6b, 0xd8, 0xd0, 0x11,
         0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20]

  IID_IWbemLevel1Login* = [
    byte 0x18, 0xad, 0x09, 0xf3, 0x6a, 0xd8, 0xd0, 0x11,
         0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20]

  IID_IWbemServices* = [
    byte 0x99, 0xdc, 0x56, 0x95, 0x8c, 0x82, 0xcf, 0x11,
         0xa3, 0x7e, 0x00, 0xaa, 0x00, 0x32, 0x40, 0xc7]

  IID_IRemUnknown* = [
    byte 0x31, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]

const ObjRefSignature* = "MEOW"
const ObjRefStandard*: uint32 = 0x00000001
const ObjRefCustom*:   uint32 = 0x00000004

type
  StdObjRef* = object
    flags*: uint32
    publicRefs*: uint32
    oxid*: string
    oid*: string
    ipid*: string
  StringBinding* = object
    towerId*: uint16
    netAddr*: string
  ObjRef* = object
    objIid*: string
    std*: StdObjRef
    bindings*: seq[StringBinding]
    securityBindings*: seq[string]

const CommonTypeHeader = "\x01\x10\x08\x00\xcc\xcc\xcc\xcc"

proc wrapTs1(body: string): string =
  result.add CommonTypeHeader
  result.addU32Le uint32(body.len)
  result.add "\xcc\xcc\xcc\xcc"
  result.add body

proc padTo8WithFa*(d: var string) =
  while d.len mod 8 != 0: d.add char(0xfa)

const ClsidInstantiationInfo = [
  byte 0xab, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
const ClsidActivationContext = [
  byte 0xa5, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
const ClsidServerLocationInfo = [
  byte 0xa4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
const ClsidScmRequestInfo = [
  byte 0xaa, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
const IID_IActivationPropertiesIn = [
  byte 0xa2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
const CLSID_ActivationPropertiesIn = [
  byte 0x38, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]

proc buildInstantiationInfo(clsid, iid: string; thisSize: uint32): string =
  result.add clsid
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 1
  result.addU32Le 0
  result.addU32Le 0x00020000'u32
  result.addU32Le thisSize
  result.addU16Le 5
  result.addU16Le 7
  result.addU32Le 1
  result.add iid

proc buildActivationContextInfo(): string =
  result.addU32Le 0; result.addU32Le 0; result.addU32Le 0; result.addU32Le 0
  result.addU32Le 0; result.addU32Le 0

proc buildLocationInfo(): string =
  result.addU32Le 0; result.addU32Le 0; result.addU32Le 0; result.addU32Le 0

proc buildScmRequestInfo(): string =
  result.addU32Le 0
  result.addU32Le 0x00020000'u32
  result.addU32Le 0
  result.addU16Le 1
  result.addU16Le 0
  result.addU32Le 0x00020004'u32
  result.addU32Le 1
  result.addU16Le 7

proc buildCustomHeaderBody(propertySizes: openArray[uint32]): string =
  let count = propertySizes.len
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 0
  result.addU32Le 2
  result.addU32Le uint32(count)
  for _ in 0 ..< 16: result.add char(0)
  result.addU32Le 0x00020000'u32
  result.addU32Le 0x00020004'u32
  result.addU32Le 0
  result.addU32Le uint32(count)
  result.add bytesToStr(ClsidInstantiationInfo)
  result.add bytesToStr(ClsidActivationContext)
  result.add bytesToStr(ClsidServerLocationInfo)
  result.add bytesToStr(ClsidScmRequestInfo)
  result.addU32Le uint32(count)
  for s in propertySizes: result.addU32Le s

proc orpcThis*(): string =
  result.addU16Le 5
  result.addU16Le 7
  result.addU32Le 0
  result.addU32Le 0
  for _ in 0 ..< 16: result.add char(0)
  result.addU32Le 0
  padTo4(result)

proc parseOrpcThat*(stub: string; offset: var int) =
  if offset + 8 > stub.len: return
  offset += 8

proc parseObjRef*(blob: string; offset: var int): ObjRef =
  if offset + 8 > blob.len: return
  if blob[offset ..< offset + 4] != ObjRefSignature: return
  let flags = rpc.readU32Le(blob, offset + 4)
  let iid = blob[offset + 8 ..< offset + 24]
  result.objIid = iid
  offset += 24
  if flags == ObjRefStandard:
    result.std.flags = rpc.readU32Le(blob, offset); offset += 4
    result.std.publicRefs = rpc.readU32Le(blob, offset); offset += 4
    result.std.oxid = blob[offset ..< offset + 8]; offset += 8
    result.std.oid = blob[offset ..< offset + 8]; offset += 8
    result.std.ipid = blob[offset ..< offset + 16]; offset += 16
    if offset + 4 > blob.len: return
    let numEntries = int(rpc.readU16Le(blob, offset))
    let secOff = int(rpc.readU16Le(blob, offset + 2))
    offset += 4
    if offset + numEntries * 2 > blob.len: return
    let dsa = blob[offset ..< offset + numEntries * 2]
    offset += numEntries * 2
    var p = 0
    let strEnd = min(dsa.len, secOff * 2)
    while p + 4 <= strEnd:
      let towerId = rpc.readU16Le(dsa, p); p += 2
      if towerId == 0: break
      var s = ""
      while p + 2 <= strEnd:
        let w = rpc.readU16Le(dsa, p); p += 2
        if w == 0: break
        if w <= 0x7f'u16: s.add chr(int(w))
      result.bindings.add StringBinding(towerId: towerId, netAddr: s)

type ActivationReply* = object
  oxid*: string
  ipidRemUnknown*: string
  authnHint*: uint32
  bindings*: seq[StringBinding]
  iwbemObjRef*: ObjRef
  comError*: uint32

proc parseActivationReply*(stub: string): ActivationReply =
  var i = 0
  parseOrpcThat(stub, i)
  if i + 4 > stub.len: return
  let refId = rpc.readU32Le(stub, i); i += 4
  if refId == 0:
    if i + 4 <= stub.len: result.comError = rpc.readU32Le(stub, i)
    elif i + 8 <= stub.len: result.comError = rpc.readU32Le(stub, i + 4)
    return
  if i + 8 > stub.len: return
  let maxCount = int(rpc.readU32Le(stub, i)); i += 4
  discard maxCount
  let ulCnt = int(rpc.readU32Le(stub, i)); i += 4
  if i + ulCnt > stub.len: return
  let objBlob = stub[i ..< i + ulCnt]
  if objBlob.len < 48: return
  if objBlob[0 ..< 4] != ObjRefSignature: return
  if rpc.readU32Le(objBlob, 4) != ObjRefCustom: return
  let activationBlob = objBlob[48 ..< objBlob.len]
  const CommonMagic = "\x01\x10\x08\x00\xcc\xcc\xcc\xcc"
  let custStart = activationBlob.find(CommonMagic)
  if custStart < 0: return
  if custStart + 16 > activationBlob.len: return
  let custBodyLen = int(rpc.readU32Le(activationBlob, custStart + 8))
  let custBodyStart = custStart + 16
  if custBodyStart + custBodyLen > activationBlob.len: return
  let custBody = activationBlob[custBodyStart ..< custBodyStart + custBodyLen]
  if custBody.len < 48: return
  let cIfs = int(rpc.readU32Le(custBody, 16))
  let headerSize = int(rpc.readU32Le(custBody, 4))
  let pclsidStart = 48
  let pSizesStart = pclsidStart + 4 + cIfs * 16
  if pSizesStart + 4 + cIfs * 4 > custBody.len: return
  var sizes = newSeq[int](cIfs)
  for k in 0 ..< cIfs:
    sizes[k] = int(rpc.readU32Le(custBody, pSizesStart + 4 + k * 4))
  var propOff = custStart + headerSize
  if cIfs < 2: return
  if propOff + sizes[0] + sizes[1] > activationBlob.len: return
  let prop0 = activationBlob[propOff ..< propOff + sizes[0]]
  let prop1 = activationBlob[propOff + sizes[0] ..< propOff + sizes[0] + sizes[1]]

  block parseProp0:
    if prop0.len < 16: break parseProp0
    let body0 = prop0[16 ..< prop0.len]
    if body0.len < 16: break parseProp0
    let cIf0 = int(rpc.readU32Le(body0, 0))
    discard cIf0
    var bp = 16
    bp += 4 + 16
    bp += 4 + 4
    let pInArrMax = int(rpc.readU32Le(body0, bp)); bp += 4
    var refIds: seq[uint32]
    for k in 0 ..< pInArrMax:
      if bp + 4 > body0.len: break parseProp0
      refIds.add rpc.readU32Le(body0, bp); bp += 4
    for r in refIds:
      if r == 0: continue
      if bp + 8 > body0.len: break parseProp0
      let mc = int(rpc.readU32Le(body0, bp)); bp += 4
      let cnt = int(rpc.readU32Le(body0, bp)); bp += 4
      discard mc
      if bp + cnt > body0.len: break parseProp0
      let intf = body0[bp ..< bp + cnt]
      bp += cnt
      while bp mod 4 != 0: inc bp
      var p = 0
      let r2 = parseObjRef(intf, p)
      if r2.std.oxid.len == 8:
        result.iwbemObjRef = r2
        break

  block parseProp1:
    if prop1.len < 16: break parseProp1
    let body1 = prop1[16 ..< prop1.len]
    if body1.len < 8: break parseProp1
    let remRef = rpc.readU32Le(body1, 4)
    if remRef == 0: break parseProp1
    var bp = 8
    if bp + 8 > body1.len: break parseProp1
    result.oxid = body1[bp ..< bp + 8]; bp += 8
    let dsaRef = rpc.readU32Le(body1, bp); bp += 4
    if bp + 16 > body1.len: break parseProp1
    result.ipidRemUnknown = body1[bp ..< bp + 16]; bp += 16
    result.authnHint = rpc.readU32Le(body1, bp); bp += 4
    bp += 4
    if dsaRef == 0: break parseProp1
    while bp mod 4 != 0: inc bp
    if bp + 4 > body1.len: break parseProp1
    let mc = int(rpc.readU32Le(body1, bp)); bp += 4
    discard mc
    if bp + 4 > body1.len: break parseProp1
    let wNumEntries = int(rpc.readU16Le(body1, bp))
    let wSecOff = int(rpc.readU16Le(body1, bp + 2))
    bp += 4
    let wantLen = wNumEntries * 2
    if bp + wantLen > body1.len: break parseProp1
    let dsa = body1[bp ..< bp + wantLen]
    var p = 0
    let strEnd = min(dsa.len, wSecOff * 2)
    while p + 4 <= strEnd:
      let towerId = rpc.readU16Le(dsa, p); p += 2
      if towerId == 0: break
      var s = ""
      while p + 2 <= strEnd:
        let w = rpc.readU16Le(dsa, p); p += 2
        if w == 0: break
        if w <= 0x7f'u16: s.add chr(int(w))
      result.bindings.add StringBinding(towerId: towerId, netAddr: s)

proc buildRemoteCreateInstanceStub*(clsid, iid: string): string =
  if clsid.len != 16 or iid.len != 16:
    raise newException(ValueError, "CLSID and IID must each be 16 bytes")
  let instantBody = buildInstantiationInfo(clsid, iid, 0)
  var instantWrapped = wrapTs1(instantBody)
  padTo8WithFa(instantWrapped)
  var actCtxWrapped = wrapTs1(buildActivationContextInfo())
  padTo8WithFa(actCtxWrapped)
  let locationBody = buildLocationInfo()
  var locationWrapped = wrapTs1(locationBody)
  padTo8WithFa(locationWrapped)
  var scmWrapped = wrapTs1(buildScmRequestInfo())
  padTo8WithFa(scmWrapped)
  let propertySizes = [
    uint32(instantWrapped.len), uint32(actCtxWrapped.len),
    uint32(locationWrapped.len), uint32(scmWrapped.len)]
  let propsConcat = instantWrapped & actCtxWrapped & locationWrapped & scmWrapped
  let customBody = buildCustomHeaderBody(propertySizes)
  let customWrapped = wrapTs1(customBody)
  var activationBlob = ""
  activationBlob.addU32Le 0
  activationBlob.addU32Le 0
  activationBlob.add customWrapped
  activationBlob.add propsConcat
  let dwSize = customWrapped.len + propsConcat.len
  setU32Le(activationBlob, 0, uint32(dwSize))
  setU32Le(activationBlob, 24, uint32(dwSize))
  setU32Le(activationBlob, 28, uint32(customWrapped.len))
  var objref = ""
  objref.add ObjRefSignature
  objref.addU32Le ObjRefCustom
  objref.add bytesToStr(IID_IActivationPropertiesIn)
  objref.add bytesToStr(CLSID_ActivationPropertiesIn)
  objref.addU32Le 0
  objref.addU32Le uint32(activationBlob.len + 8)
  objref.add activationBlob
  result.add orpcThis()
  result.addU32Le 0
  result.addU32Le 0x00020000'u32
  result.addU32Le uint32(objref.len)
  result.addU32Le uint32(objref.len)
  result.add objref
  padTo4(result)

type ResolvedOxid* = object
  bindings*: seq[StringBinding]
  comVersionMajor*: uint16
  comVersionMinor*: uint16
  authnHint*: uint32

proc buildResolveOxid2Stub*(oxid: string; arRequestedProtseqs: openArray[uint16]): string =
  if oxid.len != 8:
    raise newException(ValueError, "OXID must be 8 bytes")
  result.add oxid
  result.addU16Le uint16(arRequestedProtseqs.len)
  result.addU32Le uint32(arRequestedProtseqs.len)
  for p in arRequestedProtseqs:
    result.addU16Le p
  while result.len mod 4 != 0: result.add char(0)

proc parseResolveOxid2Response*(stub: string): ResolvedOxid =
  var i = 0
  if i + 4 > stub.len: return
  let dsaRef = rpc.readU32Le(stub, i); i += 4
  if dsaRef == 0: return
  if i + 4 > stub.len: return
  i += 4
  if i + 4 > stub.len: return
  let dsaLen = int(rpc.readU16Le(stub, i))
  let secOff = int(rpc.readU16Le(stub, i + 2))
  i += 4
  if i + dsaLen * 2 > stub.len: return
  let dsa = stub[i ..< i + dsaLen * 2]
  i += dsaLen * 2
  let stringBytes = dsa[0 ..< min(dsa.len, secOff * 2)]
  var p = 0
  while p + 4 <= stringBytes.len:
    let towerId = rpc.readU16Le(stringBytes, p); p += 2
    if towerId == 0: break
    var s = ""
    while p + 2 <= stringBytes.len:
      let w = rpc.readU16Le(stringBytes, p); p += 2
      if w == 0: break
      if w <= 0x7f'u16: s.add chr(int(w))
    result.bindings.add StringBinding(towerId: towerId, netAddr: s)

proc resolveOxid2*(host: string; epmPort, timeoutMs: int;
                  oxid: string; cred: smbntlm.SmbCredential): Future[ResolvedOxid] {.async.} =
  let c = await rpc.connectAndBind(host, epmPort, timeoutMs,
    @IObjectExporterUuidBytes, IObjectExporterMajor, IObjectExporterMinor, cred)
  let stub = buildResolveOxid2Stub(oxid, [7'u16])
  let r = await c.call(5'u16, stub)
  c.close()
  if not r.ok:
    raise newException(IOError,
      "ResolveOxid2 fault 0x" & r.faultStatus.toHex(8))
  return parseResolveOxid2Response(r.stub)

proc tcpPortFromBindings*(bindings: seq[StringBinding]): int =
  for b in bindings:
    if b.towerId != 7'u16: continue
    let lb = b.netAddr.find('[')
    if lb < 0: continue
    let rb = b.netAddr.find(']', lb + 1)
    if rb < 0: continue
    try: return parseInt(b.netAddr[lb + 1 ..< rb])
    except CatchableError: continue
  return 0

proc toLpwstrDeferred(s: string): string =
  let utf = toUtf16Le(s) & "\x00\x00"
  let charCount = uint32(utf.len div 2)
  result.addU32Le charCount
  result.addU32Le 0
  result.addU32Le charCount
  result.add utf
  padTo4(result)

proc toBstr(s: string): string =
  let utf = toUtf16Le(s)
  let cBytes = uint32(utf.len)
  let charCount = uint32(utf.len div 2)
  result.addU32Le charCount
  result.addU32Le cBytes
  result.addU32Le charCount
  result.add utf
  padTo4(result)

proc buildNtlmLoginStub*(namespace: string): string =
  result.add orpcThis()
  result.addU32Le 0x00020000'u32
  result.add toLpwstrDeferred(namespace)
  result.addU32Le 0'u32
  result.addU32Le 0'u32
  result.addU32Le 0'u32

proc parseInterfacePointer*(stub: string; offset: var int): ObjRef =
  if offset + 4 > stub.len: return
  let ref0 = rpc.readU32Le(stub, offset); offset += 4
  if ref0 == 0: return
  if offset + 4 > stub.len: return
  let cnt = int(rpc.readU32Le(stub, offset)); offset += 4
  if offset + 4 > stub.len: return
  let maxCount = int(rpc.readU32Le(stub, offset)); offset += 4
  discard maxCount
  if offset + cnt > stub.len: return
  let blob = stub[offset ..< offset + cnt]
  offset += cnt
  while offset mod 4 != 0: inc offset
  var p = 0
  result = parseObjRef(blob, p)

proc buildExecMethodStub(objectPath, methodName: string; inParamsBlob: string): string =
  result.add orpcThis()
  result.addU32Le 0x00020000'u32
  result.add toBstr(objectPath)
  result.addU32Le 0x00020004'u32
  result.add toBstr(methodName)
  result.addU32Le 0'u32
  result.addU32Le 0'u32
  if inParamsBlob.len == 0:
    result.addU32Le 0'u32
  else:
    result.addU32Le 0x00020008'u32
    result.addU32Le uint32(inParamsBlob.len)
    result.addU32Le uint32(inParamsBlob.len)
    result.add inParamsBlob
    padTo4(result)
  result.addU32Le 0x0002000c'u32
  result.addU32Le 0'u32
  result.addU32Le 0'u32

type WmiSession* = ref object
  client*: rpc.DceRpcClient
  servicesObjRef*: ObjRef
  loginObjRef*: ObjRef
  cred*: smbntlm.SmbCredential

proc connectWbem*(host: string; epmPort, timeoutMs: int;
                 cred: smbntlm.SmbCredential;
                 namespace = "//./root/cimv2"): Future[WmiSession] {.async.} =
  proc bytesToStrLocal(b: openArray[byte]): string =
    result = newString(b.len)
    for i, x in b: result[i] = chr(int(x))
  let scm = await rpc.connectAndBind(host, epmPort, timeoutMs,
    @IRemoteSCMActivatorUuidBytes, IRemoteSCMActivatorMajor,
    IRemoteSCMActivatorMinor, cred)
  let createStub = buildRemoteCreateInstanceStub(
    bytesToStrLocal(CLSID_WbemLevel1Login), bytesToStrLocal(IID_IWbemLevel1Login))
  let createResp = await scm.call(4'u16, createStub)
  scm.close()
  if not createResp.ok:
    raise newException(IOError,
      "RemoteCreateInstance fault 0x" & createResp.faultStatus.toHex(8))
  let reply = parseActivationReply(createResp.stub)
  if reply.iwbemObjRef.std.oxid.len != 8:
    raise newException(IOError, "RemoteCreateInstance returned no IWbemLevel1Login OBJREF")
  var dynamicPort = 0
  for b in reply.bindings:
    if b.towerId != 7'u16: continue
    let lb = b.netAddr.find('[')
    let rb = b.netAddr.find(']', lb + 1)
    if lb < 0 or rb < 0: continue
    try: dynamicPort = parseInt(b.netAddr[lb + 1 ..< rb]); break
    except CatchableError: continue
  if dynamicPort == 0: dynamicPort = epmPort
  discard (await resolveOxid2(host, epmPort, timeoutMs,
                              reply.iwbemObjRef.std.oxid, cred))
  let cli = await rpc.connectAndBind(host, dynamicPort, timeoutMs,
    @IID_IWbemLevel1Login, 0, 0, cred, rpc.AuthLevelPktPrivacy)
  let ntlmStub = buildNtlmLoginStub(namespace)
  let ntlmResp = await cli.call(6'u16, ntlmStub, reply.iwbemObjRef.std.ipid)
  if not ntlmResp.ok:
    cli.close()
    raise newException(IOError,
      "IWbemLevel1Login::NTLMLogin fault 0x" & ntlmResp.faultStatus.toHex(8))
  var off2 = 0
  parseOrpcThat(ntlmResp.stub, off2)
  let servicesObjRef = parseInterfacePointer(ntlmResp.stub, off2)
  if servicesObjRef.std.oxid.len != 8:
    cli.close()
    raise newException(IOError, "NTLMLogin returned no IWbemServices OBJREF")
  await cli.alterContext(@IID_IRemUnknown, 0, 0, cred, 1'u16, 3'u32)
  await cli.alterContext(@IID_IWbemServices, 0, 0, cred, 2'u16, 5'u32)
  result = WmiSession(
    client: cli,
    servicesObjRef: servicesObjRef,
    loginObjRef: reply.iwbemObjRef,
    cred: cred
  )

proc connectWbemKerb*(host: string; epmPort, timeoutMs: int;
                      domain: string;
                      namespace = "//./root/cimv2"): Future[WmiSession] {.async.} =
  proc bytesToStrLocal(b: openArray[byte]): string =
    result = newString(b.len)
    for i, x in b: result[i] = chr(int(x))
  let scm = await rpc.connectAndBindKerb(host, epmPort, timeoutMs,
    @IRemoteSCMActivatorUuidBytes, IRemoteSCMActivatorMajor,
    IRemoteSCMActivatorMinor, domain)
  let createStub = buildRemoteCreateInstanceStub(
    bytesToStrLocal(CLSID_WbemLevel1Login), bytesToStrLocal(IID_IWbemLevel1Login))
  let createResp = await scm.call(4'u16, createStub)
  scm.close()
  if not createResp.ok:
    raise newException(IOError,
      "RemoteCreateInstance fault 0x" & createResp.faultStatus.toHex(8))
  let reply = parseActivationReply(createResp.stub)
  if reply.iwbemObjRef.std.oxid.len != 8:
    raise newException(IOError, "RemoteCreateInstance returned no IWbemLevel1Login OBJREF")
  var dynamicPort = 0
  for b in reply.bindings:
    if b.towerId != 7'u16: continue
    let lb = b.netAddr.find('[')
    let rb = b.netAddr.find(']', lb + 1)
    if lb < 0 or rb < 0: continue
    try: dynamicPort = parseInt(b.netAddr[lb + 1 ..< rb]); break
    except CatchableError: continue
  if dynamicPort == 0: dynamicPort = epmPort
  let cli = await rpc.connectAndBindKerb(host, dynamicPort, timeoutMs,
    @IID_IWbemLevel1Login, 0, 0, domain, rpc.AuthLevelPktPrivacy)
  let ntlmStub = buildNtlmLoginStub(namespace)
  let ntlmResp = await cli.call(6'u16, ntlmStub, reply.iwbemObjRef.std.ipid)
  if not ntlmResp.ok:
    cli.close()
    raise newException(IOError,
      "IWbemLevel1Login::NTLMLogin fault 0x" & ntlmResp.faultStatus.toHex(8))
  var off2 = 0
  parseOrpcThat(ntlmResp.stub, off2)
  let servicesObjRef = parseInterfacePointer(ntlmResp.stub, off2)
  if servicesObjRef.std.oxid.len != 8:
    cli.close()
    raise newException(IOError, "NTLMLogin returned no IWbemServices OBJREF")
  var emptyCred = smbntlm.SmbCredential()
  await cli.alterContext(@IID_IRemUnknown, 0, 0, emptyCred, 1'u16, 3'u32)
  await cli.alterContext(@IID_IWbemServices, 0, 0, emptyCred, 2'u16, 5'u32)
  result = WmiSession(
    client: cli,
    servicesObjRef: servicesObjRef,
    loginObjRef: reply.iwbemObjRef,
    cred: emptyCred
  )

proc close*(s: WmiSession) =
  if s.client != nil: s.client.close()

proc execMethod*(s: WmiSession; objectPath, methodName: string;
                inParamsBlob: string): Future[tuple[ok: bool;
                                              stub: string; faultStatus: uint32]] {.async.} =
  let stub = buildExecMethodStub(objectPath, methodName, inParamsBlob)
  return await s.client.call(24'u16, stub, s.servicesObjRef.std.ipid)

proc buildWin32ProcessCreateInputs*(commandLine: string): string =
  let cls = WmioClass(
    className: "__PARAMETERS",
    parentClassName: "",
    derivation: @[],
    properties: @[
      WmioProperty(name: "CommandLine", cimType: CimTypeString,
                   declaredOrder: 0, valueOffset: 0, classOfOrigin: 0,
                   qualifiers: @[qualifierIn(), qualifierId(0'i32), qualifierCimType("string")],
                   hasDefault: false),
      WmioProperty(name: "CurrentDirectory", cimType: CimTypeString,
                   declaredOrder: 1, valueOffset: 4, classOfOrigin: 0,
                   qualifiers: @[qualifierIn(), qualifierId(1'i32), qualifierCimType("string")],
                   hasDefault: false),
      WmioProperty(name: "ProcessStartupInformation", cimType: CimTypeObject,
                   declaredOrder: 2, valueOffset: 8, classOfOrigin: 0,
                   qualifiers: @[qualifierIn(), qualifierId(2'i32), qualifierCimType("object:Win32_ProcessStartup")],
                   hasDefault: false),
    ],
    qualifiers: @[qualifierAbstract()],
    methods: "")
  let blk = WmioObjectBlock(
    flags: ObjectFlagCimInstance,
    ancestors: @[],
    currentClass: cls,
    instanceValues: @[
      WmioInstanceValue(name: "CommandLine", cimType: CimTypeString, isNull: false,
                        value: strVariant(commandLine)),
      WmioInstanceValue(name: "CurrentDirectory", cimType: CimTypeString, isNull: false,
                        value: strVariant("C:\\")),
    ])
  let encUnit = encodeEncodingUnit(encodeObjectBlock(blk))
  return encodeObjRefCustom(encUnit)
