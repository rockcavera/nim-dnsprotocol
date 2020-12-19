import dnsprotocol

let header = initHeader(id = 12345'u16, qr = QR.Response, rd = true, ra = true)

let question = initQuestion("nim-lang.org.", QType.A, QClass.IN)

let rr1 = initResourceRecord("nim-lang.org", Type.A, Class.IN, 299'i32, 4'u16,
                             RDataA(address: [172'u8, 67, 132, 242]))
  # If the last character of "nim-lang.org" is not a '.', the initializer will
  # add, as it is called the DNS root.

let rr2 = initResourceRecord("nim-lang.org.", Type.A, Class.IN, 299'i32, 4'u16,
                             RDataA(address: [104'u8, 28, 19, 79]))
  # The `rdlength` parameter does not need a value, as the `toBinMsg()` does not
  # use it. The `toBinMsg()` takes the binary size of `rdata` and writes it to
  # the binary DNS message.

let rr3 = initResourceRecord("nim-lang.org.", Type.A, Class.IN, 299'i32, 4'u16,
                             RDataA(address: [104'u8, 28, 18, 79]))

let msg = initMessage(header, @[question], @[rr1, rr2, rr3])
  # The initializer automatically changes: `header.qdcount` to `1'u16` and
  # `header.ancount` to `3'u16`.

echo repr(msg) # repr() to show RDatas (RDataA)

let bmsg = toBinMsg(msg)

echo "\n", bmsg