Domain Name System (DNS) protocol for Nim programming language

The current implementation was based on RFCs [1034](https://tools.ietf.org/html/rfc1035) and [1035](https://tools.ietf.org/html/rfc1035). There is still much to be done...

This package does not transport data, that is, it is neither a DNS client nor a DNS server, but it can be used to implement them. If you need a client dns use [ndns](https://github.com/rockcavera/nim-ndns).
# Current Support
Most types of the IN class are currently supported. However, if I need to add a type, I would be happy to receive a PR and a little less with an issue.

For dns types, classes, rcodes, etc. that are supported, access [here](https://rockcavera.github.io/nim-dnsprotocol/dnsprotocol/types.html). Unsupported types are stored in `RDataUnknown`, thus avoiding runtime errors.
# Install
`nimble install dnsprotocol`

or

`nimble install https://github.com/rockcavera/nim-dnsprotocol.git`
# Basic Use
Creating a `Message` object with a `QType.A` query for the domain name nim-lang.org:
```nim
import dnsprotocol

let header = initHeader(id = 12345'u16, rd = true)

let question = initQuestion("nim-lang.org", QType.A, QClass.IN)
  # If the last character of "nim-lang.org" is not a '.', the initializer will
  # add, as it is called the DNS root.

let msg = initMessage(header, @[question])
  # The initializer automatically changes `header.qdcount` to `1'u16`

echo msg

let bmsg = toBinMsg(msg)

echo "\n", bmsg
```

Creating a `Message` object with the query response from the previous example:
```nim
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
```
# Documentation
https://rockcavera.github.io/nim-dnsprotocol/theindex.html
# Project Layout
The project currently has 6 Nim code files.

`dnsprotocol.nim` contains object initializers; the builders of binary DNS messages; and the binary DNS message parsers. **It is the only file that must be imported into your project**.

`dnsprotocol/rdatas.nim` does all the "magic" of transforming RDatas (specific objects for each type and class) into binary DNS messages and the reverse way too, that is, it transforms binary DNS messages into RDatas. **It should never be imported directly into your project**.

`dnsprotocol/rdatatypes.nim` is where all types of RDatas are declared. **It should never be imported directly into your project**.

`dnsprotocol/streams2.nim` provides some stream procedures, for reading and writing, making the conversion, if necessary, between endians (order of bytes). **It should never be imported directly into your project**.

`dnsprotocol/types.nim` is where all types, enumerators and objects of the project are declared. **It should never be imported directly into your project**.

`dnsprotocol/utils.nim` has some procedures to build binary DNS messages and binary DNS message parsers, which could not be in other files due to the impossibility of cyclic import in Nim. **It should never be imported directly into your project**.

The layout of the project has changed several times since I started and can continue to change, if necessary. If you have a suggestion, please send it to me, as I would be grateful to discuss improvements.