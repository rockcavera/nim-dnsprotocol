# Std imports
import std/[streams, tables, strformat]

# Nimble packages imports
import pkg/[stew/endians2]

const
  bMsgCompress = 0b11000000'u8 # Bit flag Message Compression
  bOffset = 0b11111111111111 # Maximum size of a message compression offset

proc addressToBinMsg*(x: openArray[uint8], ss: StringStream) =
  ## Turns an Address stored in `x` into a binary dns protocol message stored in
  ## `ss`.
  for i in x:
    writeData(ss, unsafeAddr(i), 1)

proc characterStringToBinMsg*(cs: string, ss: StringStream) =
  ## Turns a Character-String stored in `cs` into a binary dns protocol message
  ## stored in `ss`.
  if len(cs) > 255:
    raise newException(ValueError, fmt"'{cs}' not a legal character-string (exceeds 255 characters)")

  let l = len(cs).uint8

  writeData(ss, unsafeAddr(l), 1)

  write(ss, cs)

proc domainNameToBinMsg*(name: string, ss: StringStream,
                         dictionary: var Table[string, uint16]) =
  ## Turns a Domain Name stored in `name` into a binary dns protocol message
  ## stored in `ss`.
  if 0 == len(name):
    raise newException(ValueError, "Domain name is empty")
  elif "." == name:
    write(ss, '\0')
  elif len(name) > 254: # a string converted to name will have the length of: string length + 1
    raise newException(ValueError,
                       fmt"'{name}' this domain name is too long (exceeds 255 octets in binary representation or 254 characters in textual representation)")
  else:
    const
      alphanum = {'0' .. '9'} + {'A' .. 'Z', 'a' .. 'z'}
      ldh = {'-'} + alphanum

    var
      i = 0
      c: char
      labelLen = 0'u8
      lastChar: char
    
    while true:
      let remainder = name[i..^1]

      if hasKey(dictionary, remainder):
        let offset = toBytesBE(static(uint16(bMsgCompress) shl 8) or dictionary[remainder])

        writeData(ss, unsafeAddr(offset), 1)

        break

      let lenOffset = getPosition(ss)

      c = name[i]

      if '.' == c:
        raise newException(ValueError, "Invalid domain name (empty label '.' is reserved for the root)")
      elif c notin alphanum and c != '_':
        raise newException(ValueError, "Invalid domain name (label must start with a letter or digit)")

      writeData(ss, addr c, 1) # add a length
      writeData(ss, addr c, 1) # add a char

      lastChar = c

      inc(i)
      inc(labelLen)

      while i < len(name):
        c = name[i]

        if '.' == c:
          inc(i)

          break
        elif 63'u8 == labelLen:
          raise newException(ValueError, "Invalid domain name (label exceeds 63 characters)")
        elif c notin ldh:
          raise newException(ValueError, "Invalid domain name (labels must contain only letters, digits and hyphens as internal characters)")

        writeData(ss, addr c, 1)

        lastChar = c

        inc(i)
        inc(labelLen)
      
      if lastChar notin alphanum:
        raise newException(ValueError, "Invalid domain name (label must end with a letter or digit)")

      if lenOffset <= bOffset:
        dictionary[remainder] = lenOffset.uint16
      
      let lastOffset = getPosition(ss)

      setPosition(ss, lenOffset)

      writeData(ss, addr labelLen, 1)
      
      setPosition(ss, lastOffset)

      if i == len(name):
        write(ss, '\0')

        break

      labelLen = 0'u8

proc parseCharacterString*(cs: var string, ss: StringStream) =
  ## Parses a Character-String contained in `ss` binary dns protocol message and
  ## stores it in `cs`.
  let length = readUint8(ss).int

  setLen(cs, length)

  if readData(ss, cstring(cs), length) != length:
    raise newException(IOError, "Cannot read characterString from StringStream")

proc parseCharacterStrings*(css: var seq[string], ss: StringStream,
                            rdlength: int) =
  ## Parses a Character-Strings contained in `ss` binary dns protocol message
  ## and stores it in `css`.
  var
    sizeRead = 0
    i = 0

  while sizeRead < rdlength:
    setLen(css, len(css) + 1)
    
    parseCharacterString(css[i], ss)

    inc(sizeRead, len(css[i]) + 1)
    inc(i)

proc parseDomainName*(name: var string, ss: StringStream) =
  ## Parses a Domain Name contained in `ss` binary dns protocol message and
  ## stores it in `name`.
  setLen(name, 254) # Seria 253, no entanto há o '.' adicionado ao final que é removido quando terminado.

  var
    mainOffset = -1
    lenName = 0
    
  while true:
    let length = readUint8(ss)

    if (length and bMsgCompress) == bMsgCompress:
      let offset = ((uint16(length) shl 8) or uint16(readUint8(ss))) and static(uint16(bOffset))
      
      if -1 == mainOffset:
        mainOffset = getPosition(ss)
      
      setPosition(ss, offset.int)
      
      continue
    elif 0'u8 == length:
      break
    elif 63'u8 < length:
      raise newException(ValueError, "Not a legal name (label exceeds 63 octets)")
    else:
      let l = length.int

      if (lenName + l) > 254:
        raise newException(ValueError, "Not a legal name (exceeds 253 octets)")

      if readData(ss, addr name[lenName], l) != l:
        raise newException(ValueError, "Cannot read label from StringStream")

      inc(lenName, l)

      name[lenName] = '.'

      inc(lenName)
  
  if -1 != mainOffset:
    setPosition(ss, mainOffset)
  
  setLen(name, lenName)