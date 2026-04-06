#!/usr/bin/env python3
import struct, sys
from loader import NSO

def decode(inst):
    if inst == 0x00000000:                                           return "---"
    if inst == 0xd503201f:                                           return "NOP"
    if inst == 0xd65f03c0:                                           return "RET"

    top6 = (inst >> 26)
    top8 = (inst >> 24)

    if top6 == 0x05:                                                return "B"
    if top6 == 0x25:                                                return "BL"
    if top8 == 0x54:                                                return "B.cond"
    if (top8 & 0x7E) == 0x34:                                       return "CBZ/CBNZ"
    if ((inst >> 25) & 0x7F) == 0x6B:                               return "BR/BLR"

    if ((inst >> 23) & 0x3F) == 0x22 and (inst >> 30) == 0x01:      return "SUB imm"
    if ((inst >> 23) & 0x3F) == 0x22:                               return "ADD imm"

    if ((inst >> 24) & 0x1F) == 0x0B:                               return "DP reg"
    if ((inst >> 24) & 0x1F) == 0x0A:                               return "Logic reg"
    if ((inst >> 23) & 0x3F) == 0x25:                               return "MOV wide"
    if ((inst >> 24) & 0x1F) == 0x10:                               return "ADR"
    if ((inst >> 24) & 0x3F) == 0x39:                               return "LDR/STR"
    if ((inst >> 25) & 0x3F) == 0x14:                               return "STP/LDP"

    if (inst >> 21) == 0x6A0:                                       return "SVC"

    return "???"


def disasm(text, start=0, count=50):
    results = []
    for i in range(start, min(start + count * 4, len(text)), 4):
        inst = struct.unpack("<I", text[i:i+4])[0]
        results.append((i, inst, decode(inst)))
    return results


if __name__ == "__main__":
      nso = NSO(sys.argv[1])
      count = int(sys.argv[2]) if len(sys.argv) > 2 else 50
      hand = "--hand" in sys.argv

      if hand:
          for addr, inst, name in disasm(nso.text, 0, count):
              print(f"  {addr:08x}:  {inst:08x}  {name}")
      else:
          from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
          md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
          md.skipdata = True
          for inst in list(md.disasm(nso.text, 0))[:count]:
              print(f"  {inst.address:08x}:  {inst.bytes.hex()}  {inst.mnemonic} {inst.op_str}")
