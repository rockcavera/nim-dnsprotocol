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