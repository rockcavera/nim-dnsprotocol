# Don't import! Included in types

# <domain-name> is a domain name represented as a series of labels, and terminated by a label with zero length.
# <character-string> is a single length octet followed by that number of characters.

type
  RDataUnknown* = ref object of RData # Used for unspecified Type
    data*: string ## Stores all data in the rdata field according to rdlength

  # RDatas specified in RFC-1035 (https://tools.ietf.org/html/rfc1035)
  RDataA* = ref object of RData
    address*: array[4, uint8] ## A 32 bit Internet address.
  
  RDataNS* = ref object of RData
    nsdname*: string ## A <domain-name> which specifies a host which should be authoritative for the specified class and domain.
  
  RDataMD* = ref object of RData
    madname*: string ## A <domain-name> which specifies a host which has a mail agent for the domain which should be able to deliver mail for the domain.

  RDataMF* = ref object of RData
    madname*: string ## A <domain-name> which specifies a host which has a mail agent for the domain which will accept mail for forwarding to the domain.

  RDataCNAME* = ref object of RData
    cname*: string ## A <domain-name> which specifies the canonical or primary name for the owner.  The owner name is an alias.
  
  RDataSOA* = ref object of RData
    mname*: string ## The <domain-name> of the name server that was the original or primary source of data for this zone.
    rname*: string ## A <domain-name> which specifies the mailbox of the person responsible for this zone.
    serial*: uint32 ## The unsigned 32 bit version number of the original copy of the zone.  Zone transfers preserve this value.  This value wraps and should be compared using sequence space arithmetic.
    refresh*: uint32 ## A 32 bit time interval before the zone should be refreshed.
    retry*: uint32 ## A 32 bit time interval that should elapse before a failed refresh should be retried.
    expire*: uint32 ## A 32 bit time value that specifies the upper limit on the time interval that can elapse before the zone is no longer authoritative.
    minimum*: uint32 ## The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.

  RDataMB* = ref object of RData
    madname*: string # A <domain-name> which specifies a host which has the specified mailbox.
  
  RDataMG* = ref object of RData
    mgmname*: string ## A <domain-name> which specifies a mailbox which is a member of the mail group specified by the domain name.
  
  RDataMR* = ref object of RData
    newname*: string ## A <domain-name> which specifies a mailbox which is the proper rename of the specified mailbox.
  
  RDataNULL* = ref object of RData
    anything*: string ## Anything at all may be in the RDATA field so long as it is 65535 octets or less.

  RDataWKS* = ref object of RData
    address*: array[4, uint8] ## An 32 bit Internet address
    protocol*: uint8 ## An 8 bit IP protocol number
    bitmap*: string ## A variable length bit map. The bit map must be a multiple of 8 bits long.

  RDataPTR* = ref object of RData
    ptrdname*: string ## A <domain-name> which points to some location in the domain name space.
  
  RDataHINFO* = ref object of RData
    cpu*: string ## A <character-string> which specifies the CPU type.
    os*: string ## A <character-string> which specifies the operating system type.

  RDataMINFO* = ref object of RData
    rmailbx*: string ## A <domain-name> which specifies a mailbox which is responsible for the mailing list or mailbox.  If this domain name names the root, the owner of the MINFO RR is responsible for itself.  Note that many existing mailing lists use a mailbox X-request for the RMAILBX field of mailing list X, e.g., Msgroup-request for Msgroup.  This field provides a more general mechanism.
    emailbx*: string ## A <domain-name> which specifies a mailbox which is to receive error messages related to the mailing list or mailbox specified by the owner of the MINFO RR (similar to the ERRORS-TO: field which has been proposed).  If this domain name names the root, errors should be returned to the sender of the message.
  
  RDataMX* = ref object of RData
    preference*: uint16 ## A 16 bit integer which specifies the preference given to this RR among others at the same owner.  Lower values are preferred.
    exchange*: string ## A <domain-name> which specifies a host willing to act as a mail exchange for the owner name.

  RDataTXT* = ref object of RData
    txtdata*: seq[string] ## One or more <character-string>s
  
  # END - RDatas specified in RFC-1035

  # RDatas specified in RFC-1886 (https://tools.ietf.org/html/rfc1886)

  RDataAAAA* = ref object of RData
    address*: array[16, uint8] ## A 128 bit IPv6 address is encoded in the data portion of an AAAA resource record in network byte order (high-order byte first).

  # END - RDatas specified in RFC-1886

  # RDatas specified in RFC-8659 (https://tools.ietf.org/html/rfc8659)

  CAAFlags* {.size: 1.} = object
    when system.cpuEndian == bigEndian:
      issuerCritical* {.bitsize:1.}: bool ## Issuer Critical Flag:  If the value is set to "1", the Property is critical. A CA MUST NOT issue certificates for any FQDN if the Relevant RRset for that FQDN contains a CAA critical Property for an unknown or unsupported Property Tag.
      reserved* {.bitsize:7.}: uint8 ## Reserved for future use.
    else:
      reserved* {.bitsize:7.}: uint8
      issuerCritical* {.bitsize:1.}: bool

  RDataCAA* = ref object of RData
    flags*: CAAFlags
    tagLength*: uint8 ## A single octet containing an unsigned integer specifying the tag length in octets. The tag length MUST be at least 1.
    tag*: string ## A non-zero-length sequence of ASCII letters and numbers in lowercase.
    value*: string ## A sequence of octets representing the Property Value. Property Values are encoded as binary values and MAY employ sub-formats.

  # END - RDatas specified in RFC-8659

  RDataSRV* = ref object of RData
    priority*: uint16 ## The priority of this target host.  A client MUST attempt to contact the target host with the lowest-numbered priority it can reach; target hosts with the same priority SHOULD be tried in an order defined by the weight field.  The range is 0-65535.  This is a 16 bit unsigned integer in network byte order.
    weight*: uint16 ## A server selection mechanism.  The weight field specifies a relative weight for entries with the same priority. Larger weights SHOULD be given a proportionately higher probability of being selected. The range of this number is 0-65535.  This is a 16 bit unsigned integer in network byte order.
    port*: uint16 ## The port on this target host of this service.  The range is 0- 65535.  This is a 16 bit unsigned integer in network byte order.
    target*: string ## A <domain-name> which specifies a host willing to act as a mail exchange for the owner name.

  # All RDatas
  RDatas* = RDataA|RDataNS|RDataMD|RDataMF|RDataCNAME|RDataSOA|RDataMB|RDataMG|
            RDataMR|RDataNULL|RDataWKS|RDataPTR|RDataHINFO|RDataMINFO|RDataMX|
            RDataTXT|RDataAAAA|RDataCAA|RDataSRV