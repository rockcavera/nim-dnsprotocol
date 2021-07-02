## Domain Name System (DNS) protocol for Nim programming language
##
## The current implementation was based on RFCs
## [1034](https://tools.ietf.org/html/rfc1035) and
## [1035](https://tools.ietf.org/html/rfc1035). There is still much to be
## done...
##
## This package does not transport data, that is, it is neither a DNS client nor
## a DNS server, but it can be used to implement them. If you need a client dns
## use [ndns](https://github.com/rockcavera/nim-ndns).
## 
## Current Support
## ===============
## Most types of the IN class are currently supported. However, if I need to add
## a type, I would be happy to receive a PR and a little less with an issue.
##
## For dns types, classes, rcodes, etc. that are supported, access
## [here](dnsprotocol/types.html). Unsupported types are stored in
## `RDataUnknown`, thus avoiding runtime errors.
## 
## Basic Use
## =========
## Creating a `Message` object with a `QType.A` query for the domain name
## nim-lang.org:
## ```nim
## import dnsprotocol
##
## let header = initHeader(id = 12345'u16, rd = true)
##
## let question = initQuestion("nim-lang.org", QType.A, QClass.IN)
##   # If the last character of "nim-lang.org" is not a '.', the initializer will
##   # add, as it is called the DNS root.
##
## let msg = initMessage(header, @[question])
##   # The initializer automatically changes `header.qdcount` to `1'u16`
##
## echo msg
##
## let bmsg = toBinMsg(msg)
##
## echo "\n", bmsg
## ```
##
## Creating a `Message` object with the query response from the previous example:
## ```nim
## import dnsprotocol
##
## let header = initHeader(id = 12345'u16, qr = QR.Response, rd = true, ra = true)
##
## let question = initQuestion("nim-lang.org.", QType.A, QClass.IN)
##
## let rr1 = initResourceRecord("nim-lang.org", Type.A, Class.IN, 299'i32, 4'u16,
##                              RDataA(address: [172'u8, 67, 132, 242]))
##   # If the last character of "nim-lang.org" is not a '.', the initializer will
##   # add, as it is called the DNS root.
##
## let rr2 = initResourceRecord("nim-lang.org.", Type.A, Class.IN, 299'i32, 4'u16,
##                              RDataA(address: [104'u8, 28, 19, 79]))
##   # The `rdlength` parameter does not need a value, as the `toBinMsg()` does not
##   # use it. The `toBinMsg()` takes the binary size of `rdata` and writes it to
##   # the binary DNS message.
##
## let rr3 = initResourceRecord("nim-lang.org.", Type.A, Class.IN, 299'i32, 4'u16,
##                              RDataA(address: [104'u8, 28, 18, 79]))
##
## let msg = initMessage(header, @[question], @[rr1, rr2, rr3])
##   # The initializer automatically changes: `header.qdcount` to `1'u16` and
##   # `header.ancount` to `3'u16`.
##
## echo repr(msg) # repr() to show RDatas (RDataA)
##
## let bmsg = toBinMsg(msg)
##
## echo "\n", bmsg
## ```

# Std imports
import std/[streams, tables]

# Internal imports
import ./dnsprotocol/[rdatas, streams2, types, utils]

export types

proc initHeader*(id: uint16 = 0'u16, qr: QR = QR.Query,
                 opcode: OpCode = OpCode.Query, aa: bool = false,
                 tc: bool = false, rd: bool = false, ra: bool = false,
                 rcode: RCode = RCode.NoError, qdcount: uint16 = 0'u16,
                 ancount: uint16 = 0'u16, nscount: uint16 = 0'u16,
                 arcount: uint16 = 0'u16): Header =
  ## Returns a created `Header` object.
  ## 
  ## The header includes fields that specify which of the remaining sections are
  ## present, and also specify whether the message is a query or a response, a
  ## standard query or some other opcode, etc.
  ## 
  ## **Parameters**
  ## - `id` is an identifier assigned to any kind of query. This identifier is
  ##   copied the corresponding reply and can be used to match up replies to
  ##   outstanding queries.
  ## - `qr` specifies whether this message is a query (`QR.Query`) or a response
  ##   (`QR.Response`).
  ## - `opcode` specifies kind of query. This value is set by the originator of
  ##   a query and copied into the response. See
  ##   `OpCode<dnsprotocol/types.html#OpCode>`_.
  ## - `aa` is a parameter valid in responses, and if it is `true`, specifies
  ##   that the responding name server is an authority for the domain name in
  ##   question section.
  ## - `tc`, if `true`, specifies that this message was truncated due to length
  ##   greater than permitted on the transmission channel.
  ## - `rd` is a parameter set in a query and is copied into the response. If it
  ##   is `true`, it directs the name server to pursue the query recursively.
  ## - `ra` is set in a response. If it is `true`, denotes whether recursive
  ##   query support is available in the name server.
  ## - `rcode` is a parameter set as part of responses. See
  ##   `RCode<dnsprotocol/types.html#RCode>`_.
  ## - `qdcount` specifies the number of entries in the question section.
  ## - `ancount` specifies the number of resource records in the answer section.
  ## - `nscount` specifies the number of name server resource records in the
  ##   authority records section.
  ## - `arcount` specifies the number of resource records in the additional
  ##   records section.
  result.id = id

  result.flags.qr = qr
  result.flags.opcode = opcode
  result.flags.aa = aa
  result.flags.tc = tc
  result.flags.rd = rd
  result.flags.ra = ra
  result.flags.rcode = rcode

  result.qdcount = qdcount
  result.ancount = ancount
  result.nscount = nscount
  result.arcount = arcount

proc initQuestion*(qname: string, qtype: QType, qclass: QClass = QClass.IN):
                   Question =
  ## Returns a created `Question` object.
  ## 
  ## The question contains fields that describe a question to a name server.
  ## 
  ## **Parameters**
  ## - `qname` is a domain name. It can be an empty string `""`
  ## - `qtype` specifies the type of the query. See
  ##   `QType<dnsprotocol/types.html#QType>`_.
  ## - `qclass` specifies the class of the query. See
  ##   `QClass<dnsprotocol/types.html#QClass>`_.
  result.qname = qname

  if 0 == len(result.qname) or '.' != result.qname[^1]:
    add(result.qname, '.')

  result.qtype = qtype
  result.qclass = qclass

proc initResourceRecord*(name: string, `type`: Type, class: Class, ttl: int32,
                         rdlength: uint16, rdata: RDatas): ResourceRecord =
  ## Returns a created `ResourceRecord` object.
  ## 
  ## The answer, authority, and additional sections all share the same format: a
  ## variable number of resource records, where the number of records is
  ## specified in the corresponding count field in the header.
  ## 
  ## **Parameters**
  ## - `name` is an owner name, i.e., the name of the node to which this
  ##   resource record pertains.
  ## - `type` specifies the type of the resource record. See
  ##   `Type<dnsprotocol/types.html#Type>`_.
  ## - `class` specifies the class of the resource record. See
  ##   `Class<dnsprotocol/types.html#Class>`_.
  ## - `ttl` specifies the time interval that the resource record may be cached
  ##   before the source of the information should again be consulted.
  ## - `rdlength` specifies the length of the `rdata`.
  ## - `rdata` describes the resource. The format of this information varies
  ##   according to the `Type` and `Class` of the resource record. See
  ##   `RDatas<dnsprotocol/types.html#RDatas>`_.
  ## 
  ## **Note**
  ## * `rdata` can be initialized as `nil`, but it is not recommended.
  result.name = name

  if 0 == len(result.name) or '.' != result.name[^1]:
    add(result.name, '.')

  result.`type` = `type`
  result.class = class
  result.ttl = ttl
  result.rdlength = rdlength
  result.rdata = rdata

proc initMessage*(header: Header, questions: Questions = @[],
                  answers: Answers = @[], authorities: Authorities = @[],
                  additionals: Additionals = @[]): Message =
  ## Returns a created `Message` object.
  ## 
  ## All communications inside of the DNS protocol are carried in a single
  ## format called a message. The top level format of message is divided into 5
  ## sections (some of which are empty in certain cases) shown below:
  ## 
  ## **Parameters**
  ## - `header` includes fields that specify which of the remaining sections are
  ##   present, and also specify whether the message is a query or a response, a
  ##   standard query or some other opcode, etc.
  ## - `question` contains zero or more questions for a name server.
  ## - `answers` contains zero or more resource records that answer the
  ##   question.
  ## - `authorities` contains zero or more resource records that point toward an
  ##   authoritative name server.
  ## - `additionals` contains zero or more resource records which relate to the
  ##   query, but are not strictly answers for the question.
  result.header = header
  result.questions = questions
  result.answers = answers
  result.authorities = authorities
  result.additionals = additionals

  if len(result.questions) > 65535:
    raise newException(ValueError, "The number of questions exceeds 65535")
  
  result.header.qdcount = len(result.questions).uint16

  if len(result.questions) > 65535:
    raise newException(ValueError, "The number of answers exceeds 65535")
  
  result.header.ancount = len(result.answers).uint16

  if len(result.questions) > 65535:
    raise newException(ValueError, "The number of authorities exceeds 65535")

  result.header.nscount = len(result.authorities).uint16

  if len(result.questions) > 65535:
    raise newException(ValueError, "The number of additionals exceeds 65535")

  result.header.arcount = len(result.additionals).uint16

proc toBinMsg*(header: Header, ss: StringStream) =
  ## Turns a `Header` object into a binary DNS protocol message stored in `ss`.
  ## 
  ## The use of this procedure is advised for optimization purposes when you
  ## know what to do. Otherwise, use `toBinMsg<#toBinMsg,Message,bool>`_
  writeSomeIntBE(ss, header.id)

  var a = uint8(header.flags.qr) shl 7

  a = a or (uint8(header.flags.opcode) shl 3)
  a = a or (uint8(header.flags.aa) shl 2)
  a = a or (uint8(header.flags.tc) shl 1)
  a = a or uint8(header.flags.rd)

  writeData(ss, addr a, 1)

  a = uint8(header.flags.ra) shl 7

  a = a or header.flags.z shl 4
  a = a or uint8(header.flags.rcode)

  writeData(ss, addr a, 1)
  
  # https://github.com/nim-lang/Nim/issues/16313
  # writeData(ss, unsafeAddr(header.flags), 2)

  writeSomeIntBE(ss, header.qdcount)
  writeSomeIntBE(ss, header.ancount)
  writeSomeIntBE(ss, header.nscount)
  writeSomeIntBE(ss, header.arcount)

proc toBinMsg*(question: Question, ss: StringStream,
               dictionary: var Table[string, uint16]) =
  ## Turns a `Question` object into a binary DNS protocol message stored in
  ## `ss`.
  ## 
  ## The use of this procedure is advised for optimization purposes when you
  ## know what to do. Otherwise, use `toBinMsg<#toBinMsg,Message,bool>`_
  domainNameToBinMsg(question.qname, ss, dictionary)
  writeSomeIntBE(ss, uint16(question.qtype))
  writeSomeIntBE(ss, uint16(question.qclass))

proc toBinMsg*(rr: ResourceRecord, ss: StringStream,
               dictionary: var Table[string, uint16]) =
  ## Turns a `ResourceRecord` object into a binary DNS protocol message stored
  ## in `ss`.
  ## 
  ## The use of this procedure is advised for optimization purposes when you
  ## know what to do. Otherwise, use `toBinMsg<#toBinMsg,Message,bool>`_
  domainNameToBinMsg(rr.name, ss, dictionary)
  writeSomeIntBE(ss, uint16(rr.`type`))
  writeSomeIntBE(ss, uint16(rr.class))
  writeSomeIntBE(ss, rr.ttl)

  let rdlengthOffset = getPosition(ss)

  writeSomeIntBE(ss, rr.rdlength)

  rdataToBinMsg(rr.rdata, rr, ss, dictionary)

  let aOffset = getPosition(ss)

  #rr.rdlength = uint16(aOffset - (rdlengthOffset + 2))

  let rdlength = uint16(aOffset - (rdlengthOffset + 2))

  setPosition(ss, rdlengthOffset)

  writeSomeIntBE(ss, rdlength)

  setPosition(ss, aOffset)

proc toBinMsg*(msg: Message, isTcp: bool = false): BinMsg =
  ## Returns a binary DNS protocol message from the `msg`. If `isTcp` is `true`,
  ## the message is prefixed with a two byte length field which gives the
  ## message length, excluding the two byte length field.
  var ss = newStringStream()

  setLen(ss.data, 512) # maximum message size by UDP protocol

  if isTcp:
    setPosition(ss, 2)

  toBinMsg(msg.header, ss)

  var dictionary = initTable[string, uint16]() # Dictionary for message compression

  for question in msg.questions:
    toBinMsg(question, ss, dictionary)
  
  for answer in msg.answers:
    toBinMsg(answer, ss, dictionary)
    
  for authorith in msg.authorities:
    toBinMsg(authorith, ss, dictionary)
  
  for additional in msg.additionals:
    toBinMsg(additional, ss, dictionary)
  
  setLen(ss.data, getPosition(ss))

  if isTcp:
    setPosition(ss, 0)

    writeSomeIntBE(ss, uint16(len(ss.data) - 2))

  result = ss.data

  close(ss)

proc parseHeader(header: var Header, ss: StringStream) =
  ## Parses a header contained in `ss` and stores into `header`.
  header.id = readUInt16E(ss)

  var a = readUint8(ss)

  header.flags.qr = QR((a and 0b10000000'u8) shr 7)
  header.flags.opcode = OpCode((a and 0b01111000'u8) shr 3)
  header.flags.aa = bool((a and 0b00000100'u8) shr 2)
  header.flags.tc = bool((a and 0b00000010'u8) shr 1)
  header.flags.rd = bool(a and 0b00000001'u8)

  a = readUint8(ss)

  header.flags.ra = bool((a and 0b10000000'u8) shr 7)
  header.flags.z = (a and 0b01110000'u8) shr 4
  header.flags.rcode = RCode(a and 0b00001111'u8)
  
  # https://github.com/nim-lang/Nim/issues/16313
  # if readData(ss, addr header.flags, 2) != 2:
  #   raise newException(IOError, "Cannot read from StringStream")

  header.qdcount = readUInt16E(ss)
  header.ancount = readUInt16E(ss)
  header.nscount = readUInt16E(ss)
  header.arcount = readUInt16E(ss)

proc parseQuestion(question: var Question, ss: StringStream) =
  ## Parses a question contained in `ss` and stores into `question`.
  parseDomainName(question.qname, ss)

  question.qtype = QType(readUInt16E(ss))
  question.qclass = QClass(readUInt16E(ss))

proc parseResourceRecord(rr: var ResourceRecord, ss: StringStream) =
  ## Parses a resource record contained in `ss` and stores into `rr`.
  parseDomainName(rr.name, ss)

  rr.`type` = cast[Type](readInt16E(ss)) # Prevents execution errors when certain Type are not implemented
  rr.class = cast[Class](readInt16E(ss)) # Prevents execution errors when certain Class are not implemented or when the RR is used differently from the ideal, as in Type 41 (OPT)
  rr.ttl = readInt32E(ss)
  rr.rdlength = readUInt16E(ss)
  
  newRData(rr)

  parseRData(rr.rdata, rr, ss)

proc parseMessage*(bmsg: BinMsg): Message =
  ## Parses a binary DNS protocol message contained in `bmsg`.
  var ss = newStringStream(bmsg)

  parseHeader(result.header, ss)

  setLen(result.questions, result.header.qdcount)

  for i in 0'u16 ..< result.header.qdcount:
    parseQuestion(result.questions[i], ss)
  
  setLen(result.answers, result.header.ancount)
  
  for i in 0'u16  ..< result.header.ancount:
    parseResourceRecord(result.answers[i], ss)
  
  setLen(result.authorities, result.header.nscount)
  
  for i in 0'u16  ..< result.header.nscount:
    parseResourceRecord(result.authorities[i], ss)
  
  setLen(result.additionals, result.header.arcount)
  
  for i in 0'u16  ..< result.header.arcount:
    parseResourceRecord(result.additionals[i], ss)

  close(ss)