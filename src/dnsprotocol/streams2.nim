# Std imports
import std/[streams]

# Nimble packages imports
import pkg/[stew/endians2]

proc readInt16E*(ss: StringStream): int16 =
  if readData(ss, addr result, 2) != 2:
    raise newException(IOError, "Cannot read from StringStream")

  when system.cpuEndian == littleEndian:
    result = cast[int16](swapBytes(cast[uint16](result))) # use of cast to prevent overflowing

proc readInt32E*(ss: StringStream): int32 =
  if readData(ss, addr result, 4) != 4:
    raise newException(IOError, "Cannot read from StringStream")

  when system.cpuEndian == littleEndian:
    result = cast[int32](swapBytes(cast[uint32](result))) # use of cast to prevent overflowing

proc readInt64E*(ss: StringStream): int64 =
  if readData(ss, addr result, 8) != 8:
    raise newException(IOError, "Cannot read from StringStream")

  when system.cpuEndian == littleEndian:
    result = cast[int64](swapBytes(cast[uint64](result))) # use of cast to prevent overflowing

proc readUInt16E*(ss: StringStream): uint16 =
  if readData(ss, addr result, 2) != 2:
    raise newException(IOError, "Cannot read from StringStream")

  when system.cpuEndian == littleEndian:
    result = swapBytes(result)

proc readUInt32E*(ss: StringStream): uint32 =
  if readData(ss, addr result, 4) != 4:
    raise newException(IOError, "Cannot read from StringStream")

  when system.cpuEndian == littleEndian:
    result = swapBytes(result)

proc readUInt64E*(ss: StringStream): uint64 =
  if readData(ss, addr result, 8) != 8:
    raise newException(IOError, "Cannot read from StringStream")

  when system.cpuEndian == littleEndian:
    result = swapBytes(result)

proc writeSomeIntBE*(ss: StringStream, x: SomeEndianInt) =
  let x = toBytesBE(x)

  writeData(ss, unsafeAddr(x), sizeof(x))

proc writeSomeIntBE*[T: SomeSignedInt|uint](ss: StringStream, x: T) =
  when sizeof(T) == 1:
    writeSomeIntBE(ss, uint8(x))
  elif sizeof(T) == 2:
    writeSomeIntBE(ss, uint16(x))
  elif sizeof(T) == 4:
    writeSomeIntBE(ss, uint32(x))
  elif sizeof(T) == 8:
    writeSomeIntBE(ss, uint64(x))