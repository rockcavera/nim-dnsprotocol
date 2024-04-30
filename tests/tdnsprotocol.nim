import std/[streams, tables, unittest]

import dnsprotocol

const
  strQHeader = "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
  strRHeader = "\x00\x01\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00"
  strQuestion = "\x08\x6e\x69\x6d\x2d\x6c\x61\x6e\x67\x03\x6f\x72\x67\x00\x00\x01\x00\x01"
  strRResourceRecord1 = "\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\xac\x43\x84\xf2"
  strRResourceRecord2 = "\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x68\x15\x05\x2a"

proc `==`(a, b: ResourceRecord): bool =
  if a.`type` == b.`type` and a.name == b.name and a.rdlength == b.rdlength and
     cmpMem(addr a.rdata[], addr b.rdata[], a.rdlength) == 0:
    case a.`type`
    of Type.OPT:
      result = a.udpSize == b.udpSize and a.extRCode == b.extRCode and
               a.version == b.version and a.`do` == b.`do` and a.z == b.z
    else:
      result = a.class == b.class and a.ttl == b.ttl

suite "Query A IN":
  let
    header = initHeader(1'u16, QR.Query, OpCode.Query, false, false, true, false, RCode.NoError, 1'u16, 0'u16, 0'u16, 0'u16)
    question = initQuestion("nim-lang.org", QType.A, QClass.IN)

  test "Header for binary msg":
    var ss = newStringStream()

    toBinMsg(header, ss)

    check(ss.data == strQHeader)

  test "Question for binary msg":
    var
      dictionary = initTable[string, uint16]()
      ss = newStringStream()

    toBinMsg(question, ss, dictionary)

    check(ss.data == strQuestion)

  test "Message for binary msg UDP":
    let bmsg = toBinMsg(initMessage(header, @[question]), false)

    check(bmsg == (strQHeader & strQuestion))

  test "Message for binary msg TCP":
    let bmsg = toBinMsg(initMessage(header, @[question]), true)

    check(bmsg == ("\x00\x1E" & strQHeader & strQuestion))

  test "Parse to Message":
    let
      msg = parseMessage(strQHeader & strQuestion)
      tmsg = initMessage(header, @[question])

    check(msg.header == tmsg.header)
    check(len(msg.questions) == 1)
    check(msg.questions[0] == tmsg.questions[0])
    check(len(msg.answers) == 0)
    check(len(msg.authorities) == 0)
    check(len(msg.additionals) == 0)

suite "Query Response A IN":
  let
    header = initHeader(1'u16, QR.Response, OpCode.Query, false, false, true, true, RCode.NoError, 1'u16, 2'u16, 0'u16, 0'u16)
    question = initQuestion("nim-lang.org", QType.A, QClass.IN)
    rr1 = initResourceRecord("nim-lang.org", Type.A, Class.IN, 300'i32, 4'u16, RDataA(address: [0xac'u8, 0x43, 0x84, 0xf2]))
    rr2 = initResourceRecord("nim-lang.org", Type.A, Class.IN, 300'i32, 4'u16, RDataA(address: [0x68'u8, 0x15, 0x05, 0x2a]))

  var
    dictionary = initTable[string, uint16]()
    ss = newStringStream()

  test "Header for binary msg":
    toBinMsg(header, ss)

    check(ss.data == strRHeader)

  toBinMsg(question, ss, dictionary)

  test "Resource Record for binary msg":
    let startRR = getPosition(ss)

    toBinMsg(rr1, ss, dictionary)
    toBinMsg(rr2, ss, dictionary)

    check(ss.data[startRR..^1] == (strRResourceRecord1 & strRResourceRecord2))

  test "Message for binary msg UDP":
    let bmsg = toBinMsg(initMessage(header, @[question], @[rr1, rr2]), false)

    check(bmsg == (strRHeader & strQuestion & strRResourceRecord1 & strRResourceRecord2))

  test "Message for binary msg TCP":
    let bmsg = toBinMsg(initMessage(header, @[question], @[rr1, rr2]), true)

    check(bmsg == ("\x00\x3E" & strRHeader & strQuestion & strRResourceRecord1 & strRResourceRecord2))

  test "Parse to Message":
    let
      msg = parseMessage(strRHeader & strQuestion & strRResourceRecord1 & strRResourceRecord2)
      tmsg = initMessage(header, @[question], @[rr1, rr2])

    check(msg.header == tmsg.header)
    check(len(msg.questions) == 1)
    check(msg.questions[0] == tmsg.questions[0])
    check(len(msg.answers) == 2)
    check(msg.answers[0] == tmsg.answers[0])
    check(msg.answers[1] == tmsg.answers[1])
    check(len(msg.authorities) == 0)
    check(len(msg.additionals) == 0)
