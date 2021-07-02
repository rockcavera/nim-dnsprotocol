# Std imports
import std/[streams, tables]

# Internal imports
import ./streams2, ./types, ./utils

proc newRData*(rr: var ResourceRecord) =
  case rr.class
  of Class.IN:
    case rr.`type`
    of Type.A: rr.rdata = new(RDataA)
    of Type.NS: rr.rdata = new(RDataNS)
    of Type.MD: rr.rdata = new(RDataMD)
    of Type.MF: rr.rdata = new(RDataMF)
    of Type.CNAME: rr.rdata = new(RDataCNAME)
    of Type.SOA: rr.rdata = new(RDataSOA)
    of Type.MB: rr.rdata = new(RDataMB)
    of Type.MG: rr.rdata = new(RDataMG)
    of Type.MR: rr.rdata = new(RDataMR)
    of Type.NULL: rr.rdata = new(RDataNULL)
    of Type.WKS: rr.rdata = new(RDataWKS)
    of Type.PTR: rr.rdata = new(RDataPTR)
    of Type.HINFO: rr.rdata = new(RDataHINFO)
    of Type.MINFO: rr.rdata = new(RDataMINFO)
    of Type.MX: rr.rdata = new(RDataMX)
    of Type.TXT: rr.rdata = new(RDataTXT)
    of Type.AAAA: rr.rdata = new(RDataAAAA)
    of Type.CAA: rr.rdata = new(RDataCAA)
    of Type.SRV: rr.rdata = new(RDataSRV)
    else:
      #raise newException(ValueError, "`newRData()` for Type " & $rr.`type` & " has not yet been implemented")
      rr.rdata = new(RDataUnknown) # Prevents execution errors when certain Type are not implemented
  else:
    #raise newException(ValueError, "`newRData()` for Class " & $rr.class & " has not yet been implemented")
    rr.rdata = new(RDataUnknown) # Prevents execution errors when certain Class are not implemented

method parseRData*(rdata: RData, rr: ResourceRecord, ss: StringStream) {.base.} =
  raise newException(ValueError, "`parseRData()` for Type " & $rr.`type` & " has not yet been implemented")

method parseRData*(rdata: RDataUnknown, rr: ResourceRecord, ss: StringStream) =
  # Prevents execution errors when certain Type are not implemented
  let l = int(rr.rdlength)

  setLen(rdata.data, l)

  if readData(ss, cstring(rdata.data), l) != l:
    raise newException(IOError, "Cannot read from StringStream")

method parseRData*(rdata: RDataA, rr: ResourceRecord, ss: StringStream) =
  if readData(ss, addr rdata.address, int(rr.rdlength)) != int(rr.rdlength):
    raise newException(IOError, "Cannot read from StringStream")

method parseRData*(rdata: RDataNS, rr: ResourceRecord, ss: StringStream) =
  parseDomainName(rdata.nsdname, ss)

method parseRData*(rdata: RDataMD, rr: ResourceRecord, ss: StringStream) =
  parseDomainName(rdata.madname, ss)

method parseRData*(rdata: RDataMF, rr: ResourceRecord, ss: StringStream) =
  parseDomainName(rdata.madname, ss)

method parseRData*(rdata: RDataCNAME, rr: ResourceRecord, ss: StringStream) =
  parseDomainName(rdata.cname, ss)

method parseRData*(rdata: RDataSOA, rr: ResourceRecord, ss: StringStream) =
  parseDomainName(rdata.mname, ss)
  parseDomainName(rdata.rname, ss)
  rdata.serial = readUInt32E(ss)
  rdata.refresh = readUInt32E(ss)
  rdata.retry = readUInt32E(ss)
  rdata.expire = readUInt32E(ss)
  rdata.minimum = readUInt32E(ss)

method parseRData*(rdata: RDataMB, rr: ResourceRecord, ss: StringStream) =
  parseDomainName(rdata.madname, ss)

method parseRData*(rdata: RDataMG, rr: ResourceRecord, ss: StringStream) =
  parseDomainName(rdata.mgmname, ss)

method parseRData*(rdata: RDataMR, rr: ResourceRecord, ss: StringStream) =
  parseDomainName(rdata.newname, ss)

method parseRData*(rdata: RDataNULL, rr: ResourceRecord, ss: StringStream) =
  let l = int(rr.rdlength)

  setLen(rdata.anything, l)

  if readData(ss, cstring(rdata.anything), l) != l:
    raise newException(IOError, "Cannot read from StringStream")

method parseRData*(rdata: RDataWKS, rr: ResourceRecord, ss: StringStream) =
  if readData(ss, addr rdata.address, 4) != 4:
    raise newException(IOError, "Cannot read from StringStream")

  rdata.protocol = readUint8(ss)

  let l = int(rr.rdlength) - 5

  setLen(rdata.bitmap, l)

  if readData(ss, cstring(rdata.bitmap), l) != l:
    raise newException(IOError, "Cannot read from StringStream")

method parseRData*(rdata: RDataPTR, rr: ResourceRecord, ss: StringStream) =
  parseDomainName(rdata.ptrdname, ss)

method parseRData*(rdata: RDataHINFO, rr: ResourceRecord, ss: StringStream) =
  parseCharacterString(rdata.cpu, ss)
  parseCharacterString(rdata.os, ss)

method parseRData*(rdata: RDataMINFO, rr: ResourceRecord, ss: StringStream) =
  parseDomainName(rdata.rmailbx, ss)
  parseDomainName(rdata.emailbx, ss)

method parseRData*(rdata: RDataMX, rr: ResourceRecord, ss: StringStream) =
  rdata.preference = readUInt16E(ss)
  parseDomainName(rdata.exchange, ss)

method parseRData*(rdata: RDataTXT, rr: ResourceRecord, ss: StringStream) =
  parseCharacterStrings(rdata.txtdata, ss, int(rr.rdlength))

method parseRData*(rdata: RDataAAAA, rr: ResourceRecord, ss: StringStream) =
  if readData(ss, addr rdata.address, int(rr.rdlength)) != int(rr.rdlength):
    raise newException(IOError, "Cannot read from StringStream")

method parseRData*(rdata: RDataCAA, rr: ResourceRecord, ss: StringStream) =
  if readData(ss, addr rdata.flags, 1) != 1:
    raise newException(IOError, "Cannot read from StringStream")

  rdata.tagLength = readUint8(ss)

  var l = int(rdata.tagLength)

  setLen(rdata.tag, l)

  if readData(ss, cstring(rdata.tag), l) != l:
    raise newException(IOError, "Cannot read from StringStream")

  l = int(rr.rdlength) - (l + 2)

  setLen(rdata.value, l)
  
  if readData(ss, cstring(rdata.value), l) != l:
    raise newException(IOError, "Cannot read from StringStream")

method parseRData*(rdata: RDataSRV, rr: ResourceRecord, ss: StringStream) =
  rdata.priority = readUInt16E(ss)
  rdata.weight = readUInt16E(ss)
  rdata.port = readUInt16E(ss)
  parseDomainName(rdata.target, ss)

method rdataToBinMsg*(rdata: RData, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) {.base.} =
  raise newException(ValueError, "`rdataToBinMsg()` for type " & $rr.`type` & " has not yet been implemented")

method rdataToBinMsg*(rdata: RDataA, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.A, "Record Data incompatible with type. Use `RDataA` for `Type.A`")

  addressToBinMsg(rdata.address, ss)

method rdataToBinMsg*(rdata: RDataNS, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.NS, "Record Data incompatible with type. Use `RDataNS` for `Type.NS`")
    
  domainNameToBinMsg(rdata.nsdname, ss, dictionary)

method rdataToBinMsg*(rdata: RDataMD, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.MD, "Record Data incompatible with type. Use `RDataMD` for `Type.MD`")
    
  domainNameToBinMsg(rdata.madname, ss, dictionary)

method rdataToBinMsg*(rdata: RDataMF, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.MF, "Record Data incompatible with type. Use `RDataMF` for `Type.MF`")
    
  domainNameToBinMsg(rdata.madname, ss, dictionary)

method rdataToBinMsg*(rdata: RDataCNAME, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.CNAME, "Record Data incompatible with type. Use `RDataCNAME` for `Type.CNAME`")
    
  domainNameToBinMsg(rdata.cname, ss, dictionary)

method rdataToBinMsg*(rdata: RDataSOA, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.SOA, "Record Data incompatible with type. Use `RDataSOA` for `Type.SOA`")
    
  domainNameToBinMsg(rdata.mname, ss, dictionary)
  domainNameToBinMsg(rdata.rname, ss, dictionary)
  writeSomeIntBE(ss, rdata.serial)
  writeSomeIntBE(ss, rdata.refresh)
  writeSomeIntBE(ss, rdata.retry)
  writeSomeIntBE(ss, rdata.expire)
  writeSomeIntBE(ss, rdata.minimum)

method rdataToBinMsg*(rdata: RDataMB, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.MB, "Record Data incompatible with type. Use `RDataMB` for `Type.MB`")
    
  domainNameToBinMsg(rdata.madname, ss, dictionary)

method rdataToBinMsg*(rdata: RDataMG, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.MG, "Record Data incompatible with type. Use `RDataMG` for `Type.MG`")
    
  domainNameToBinMsg(rdata.mgmname, ss, dictionary)

method rdataToBinMsg*(rdata: RDataMR, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.MR, "Record Data incompatible with type. Use `RDataMR` for `Type.MR`")
    
  domainNameToBinMsg(rdata.newname, ss, dictionary)

method rdataToBinMsg*(rdata: RDataNULL, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.NULL, "Record Data incompatible with type. Use `RDataNULL` for `Type.NULL`")
    
  write(ss, rdata.anything)

method rdataToBinMsg*(rdata: RDataWKS, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.WKS, "Record Data incompatible with type. Use `RDataWKS` for `Type.WKS`")
    
  addressToBinMsg(rdata.address, ss)
  writeSomeIntBE(ss, rdata.protocol)
  write(ss, rdata.bitmap)

method rdataToBinMsg*(rdata: RDataPTR, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.PTR, "Record Data incompatible with type. Use `RDataPTR` for `Type.PTR`")
    
  domainNameToBinMsg(rdata.ptrdname, ss, dictionary)

method rdataToBinMsg*(rdata: RDataHINFO, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.HINFO, "Record Data incompatible with type. Use `RDataHINFO` for `Type.HINFO`")

  characterStringToBinMsg(rdata.cpu, ss)
  characterStringToBinMsg(rdata.os, ss)

method rdataToBinMsg*(rdata: RDataMINFO, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.MINFO, "Record Data incompatible with type. Use `RDataMINFO` for `Type.MINFO`")
    
  domainNameToBinMsg(rdata.rmailbx, ss, dictionary)
  domainNameToBinMsg(rdata.emailbx, ss, dictionary)

method rdataToBinMsg*(rdata: RDataMX, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.MX, "Record Data incompatible with type. Use `RDataMX` for `Type.MX`")
    
  writeSomeIntBE(ss, rdata.preference)
  domainNameToBinMsg(rdata.exchange, ss, dictionary)

method rdataToBinMsg*(rdata: RDataTXT, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.TXT, "Record Data incompatible with type. Use `RDataTXT` for `Type.TXT`")
  
  for cs in rdata.txtdata:
    characterStringToBinMsg(cs, ss)

method rdataToBinMsg*(rdata: RDataAAAA, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.AAAA, "Record Data incompatible with type. Use `RDataAAAA` for `Type.AAAA`")

  addressToBinMsg(rdata.address, ss)

method rdataToBinMsg*(rdata: RDataCAA, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.AAAA, "Record Data incompatible with type. Use `RDataCAA` for `Type.CAA`")

  writeData(ss, addr rdata.flags, 1)
  writeSomeIntBE(ss, rdata.tagLength)
  write(ss, rdata.tag)
  write(ss, rdata.value)

method rdataToBinMsg*(rdata: RDataSRV, rr: ResourceRecord, ss: StringStream,
                      dictionary: var Table[string, uint16]) =
  assert(rr.`type` == Type.SRV, "Record Data incompatible with type. Use `RDataSRV` for `Type.SRV`")

  writeSomeIntBE(ss, rdata.priority)
  writeSomeIntBE(ss, rdata.weight)
  writeSomeIntBE(ss, rdata.port)
  domainNameToBinMsg(rdata.target, ss, dictionary)