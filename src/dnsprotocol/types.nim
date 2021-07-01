# DNS protocol use bigEndian
#
# Size limits (https://tools.ietf.org/html/rfc1035#section-2.3.4):
# * labels < 64
# * names < 256
# * TTL positive int32
# * UDP messages < 513
#
# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

# Não consegui testar esses RRs:
# MD* MF* MB* MG* MR* NULL* WKS HINFO MINFO
# * estão obsoletos

type
  Type* {.pure, size: 2.} = enum ## Are used in resource records.
    A = 1 ## A host address
    NS = 2 ## An authoritative name server
    MD = 3 ## A mail destination (Obsolete - use MX)
    MF = 4 ## A mail forwarder (Obsolete - use MX)
    CNAME = 5 ## The canonical name for an alias
    SOA = 6 ## Marks the start of a zone of authority
    MB = 7 ## A mailbox domain name (EXPERIMENTAL)
    MG = 8 ## A mail group member (EXPERIMENTAL)
    MR = 9 ## A mail rename domain name (EXPERIMENTAL)
    NULL = 10 ## A null RR (EXPERIMENTAL)
    WKS = 11 ## A well known service description
    PTR = 12 ## A domain name pointer
    HINFO = 13 ## Host information
    MINFO = 14 ## Mailbox or mail list information
    MX = 15 ## Mail exchange
    TXT = 16 ## Text strings
    AAAA = 28 ## Host IPv6 address - RFC-1886
    SRV = 33 ## Location of services - RFC-2782
    CAA = 257 ## Certification Authority Authorization - RFC-8659
  
  QType* {.pure, size: 2.} = enum ## Appear in the question part of a query.
    A = 1 ## A host address
    NS = 2 ## An authoritative name server
    MD = 3 ## A mail destination (Obsolete - use MX)
    MF = 4 ## A mail forwarder (Obsolete - use MX)
    CNAME = 5 ## The canonical name for an alias
    SOA = 6 ## Marks the start of a zone of authority
    MB = 7 ## A mailbox domain name (EXPERIMENTAL)
    MG = 8 ## A mail group member (EXPERIMENTAL)
    MR = 9 ## A mail rename domain name (EXPERIMENTAL)
    NULL = 10 ## A null RR (EXPERIMENTAL)
    WKS = 11 ## A well known service description
    PTR = 12 ## A domain name pointer
    HINFO = 13 ## Host information
    MINFO = 14 ## Mailbox or mail list information
    MX = 15 ## Mail exchange
    TXT = 16 ## Text strings
    AAAA = 28 ## Host IPv6 address - RFC-1886
    SRV = 33 ## Location of services - RFC-2782
    IXFR = 251 ## Incremental zone transfer - RFC-1995
    AXFR = 252 ## A request for a transfer of an entire zone
    MAILB = 253 ## A request for mailbox-related records (MB, MG or MR)
    MAILA = 254 ## A request for mail agent RRs (Obsolete - see MX)
    ANY = 255 ## A request for all records
    CAA = 257 ## Certification Authority Restriction - RFC-8659
  
  Class* {.pure, size: 2.} = enum ## Appear in resource records.
    IN = 1 ## The Internet
    CS = 2 ## The CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3 ## The CHAOS class - not supported
    HS = 4 ## Hesiod [Dyer 87] - not supported
    #NONE = 254 ## RFC-2136

  QClass* {.pure, size: 2.} = enum ## Appear in the question section of a query.
    IN = 1 ## The Internet
    CS = 2 ## The CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3 ## The CHAOS class - not supported
    HS = 4 ## Hesiod [Dyer 87] - not supported
    ANY = 255 ## Any class

  QR* {.pure.} = enum ## A one bit field that specifies whether this message is a query (0), or a response (1).
    Query = 0 ## Message is a query
    Response = 1 ## Message is a response
  
  OpCode* {.pure.} = enum ## A four bit field that specifies kind of query in this message. This value is set by the originator of a query and copied into the response. The values are:
    Query = 0 ## A standard query
    IQuery = 1 ## An inverse query (Obsolete - RFC-3425)
    Status = 2 ## A server status request
    #Notify = 4 ## Notify - RFC-1996
    #Update = 5 ## Update - RFC-2136
  
  RCode* {.pure.} = enum ## Response code - this 4 bit field is set as part of responses. The values have the following interpretation:
    NoError = 0 ## No error condition
    FormatError = 1 ## The name server was unable to interpret the query.
    ServerFailure = 2 ## The name server was unable to process this query due to a problem with the name server.
    NameError = 3 ## Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
    NotImplemented = 4 ## The name server does not support the requested kind of query.
    Refused = 5 ## The name server refuses to perform the specified operation for policy reasons. For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
    #YXDOMAIN = 6 ## RFC-2136
    #YXRRSET = 7 ## RFC-2136
    #NXRRSET = 8 ## RFC-2136
    #NOTAUTH = 9 ## RFC-2136
    #NOTZONE = 10 ## RFC-2136
  
  Flags* = object
      qr*: QR ## A one bit field that specifies whether this message is a query (0), or a response (1).
      opcode*: OpCode ## A four bit field that specifies kind of query in this message. This value is set by the originator of a query and copied into the response.
      aa*: bool ## Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section. Note that the contents of the answer section may have multiple owner names because of aliases. The AA bit corresponds to the name which matches the query name, or the first owner name in the answer section.
      tc*: bool ## TrunCation - specifies that this message was truncated due to length greater than that permitted on the transmission channel.
      rd*: bool ## Recursion Desired - this bit may be set in a query and is copied into the response. If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional.
      ra*: bool ## Recursion Available - this be is set or cleared in a response, and denotes whether recursive query support is available in the name server.
      z*: uint8 ## Reserved for future use.  Must be zero in all queries and responses.
      rcode*: RCode ## Response code - this 4 bit field is set as part of responses.

  #[ https://github.com/nim-lang/Nim/issues/16313
  Flags* {.size: 2.} = object
    when system.cpuEndian == bigEndian:
      qr* {.bitsize:1.}: QR ## A one bit field that specifies whether this message is a query (0), or a response (1).
      opcode* {.bitsize:4.}: OpCode ## A four bit field that specifies kind of query in this message. This value is set by the originator of a query and copied into the response.
      aa* {.bitsize:1.}: bool ## Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section. Note that the contents of the answer section may have multiple owner names because of aliases. The AA bit corresponds to the name which matches the query name, or the first owner name in the answer section.
      tc* {.bitsize:1.}: bool ## TrunCation - specifies that this message was truncated due to length greater than that permitted on the transmission channel.
      rd* {.bitsize:1.}: bool ## Recursion Desired - this bit may be set in a query and is copied into the response. If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional.
      ra* {.bitsize:1.}: bool ## Recursion Available - this be is set or cleared in a response, and denotes whether recursive query support is available in the name server.
      z* {.bitsize:3.}: uint8 ## Reserved for future use.  Must be zero in all queries and responses.
      rcode* {.bitsize:4.}: RCode ## Response code - this 4 bit field is set as part of responses.
    else:
      rd* {.bitsize:1.}: bool
      tc* {.bitsize:1.}: bool
      aa* {.bitsize:1.}: bool
      opcode* {.bitsize:4.}: OpCode
      qr* {.bitsize:1.}: QR
      rcode* {.bitsize:4.}: RCode
      z* {.bitsize:3.}: uint8
      ra* {.bitsize:1.}: bool
  ]#

  Header* = object ## The header includes fields that specify which of the remaining sections are present, and also specify whether the message is a query or a response, a standard query or some other opcode, etc.
    id*: uint16 ## A 16 bit identifier assigned by the program that generates any kind of query. This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.
    flags*: Flags
    qdcount*: uint16 ## An unsigned 16 bit integer specifying the number of entries in the question section.
    ancount*: uint16 ## An unsigned 16 bit integer specifying the number of resource records in the answer section.
    nscount*: uint16 ## An unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
    arcount*: uint16 ## An unsigned 16 bit integer specifying the number of resource records in the additional records section.
  
  Question* = object ## The question contains fields that describe a question to a name server.
    qname*: string ## A domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets. The domain name terminates with the zero length octet for the null label of the root. Note that this field may be an odd number of octets; no padding is used.
    qtype*: QType ## A two octet code which specifies the type of the query. The values for this field include all codes valid for a TYPE field, together with some more general codes which can match more than one type of RR.
    qclass*: QClass ## A two octet code that specifies the class of the query. For example, the QCLASS field is IN for the Internet.
  
  Questions* = seq[Question] ## It is an alias for `seq[Question]`

  RData* = ref object of RootObj ## A variable length string of octets that describes the resource. The format of this information varies according to the TYPE and CLASS of the resource record.
  
  ResourceRecord* = object ## The answer, authority, and additional sections all share the same format: a variable number of resource records, where the number of records is specified in the corresponding count field in the header.
    name*: string ## An owner name, i.e., the name of the node to which this resource record pertains.
    `type`*: Type ## Two octets containing one of the RR TYPE codes.
    class*: Class ## Two octets containing one of the RR CLASS codes.
    ttl*: int32 ## A 32 bit signed integer that specifies the time interval that the resource record may be cached before the source of the information should again be consulted. Zero values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached. For example, SOA records are always distributed with a zero TTL to prohibit caching. Zero values can also be used for extremely volatile data.
    rdlength*: uint16 ## An unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    rdata*: RData ## A variable length string of octets that describes the resource. The format of this information varies according to the TYPE and CLASS of the resource record.
  
  Answers* = seq[ResourceRecord] ## It is an alias for `seq[ResourceRecord]`
  Authorities* = seq[ResourceRecord] ## It is an alias for `seq[ResourceRecord]`
  Additionals* = seq[ResourceRecord] ## It is an alias for `seq[ResourceRecord]`

  Message* = object ## All communications inside of the domain protocol are carried in a single format called a message. The top level format of message is divided into 5 sections (some of which are empty in certain cases) shown below:
    header*: Header ## The header includes fields that specify which of the remaining sections are present, and also specify whether the message is a query or a response, a standard query or some other opcode, etc.
    questions*: Questions ## The question for the name server
    answers*: Answers ## Resource records answering the question
    authorities*: Authorities ## Resource records pointing toward an authority
    additionals*: Additionals ## Resource records holding additional information

  BinMsg* = string ## Binary DNS protocol message.

include ./rdatatypes