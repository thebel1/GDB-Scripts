#!/usr/bin/python3

# Documentation:
# - http://ref.x86asm.net/geek32.html
# - https://c9x.me/x86/
# - https://www.felixcloutier.com/x86/

import sys
import os
import argparse
import re
import struct
from capstone import *

def main():
    prog_desc = (
        'A barebones x86 disassembler created using the Capstone engine.'
        '\n\nOutput format: <address> <offset> <bytes> <mnemonic> <operands>'
        '\n\nAll hex data is in big-endian notation.'
        '\n\nAll instructions are in Intel notation.'
    )
    parser = argparse.ArgumentParser(
                prog='ud',
                description=prog_desc,
                formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('file',
                        help='the file to disassemble')
    parser.add_argument('offset',
                        type=(lambda x: int(x, 16)),
                        nargs='?',
                        default='0x0',
                        help='the starting offset, e.g. 0xbd0')
    parser.add_argument('length',
                        type=(lambda x: int(x, 16)),
                        nargs='?',
                        default='0x0',
                        help='the number of bytes to read, e.g. 0x62')
    parser.add_argument('-m', '--mode',
                        choices=['32', '64'],
                        default=64,
                        help='disassemble as either 32-bit or 64-bit x86')
    parser.add_argument('-f', '--force',
                        action='store_true',
                        default=False,
                        help='keep disassembling through invalid instructions')
    args = parser.parse_args()
    offset = args.offset
    mode = (CS_MODE_32 if args.mode == '32' else CS_MODE_64)
    file = open(args.file, 'rb')
    binlen = os.path.getsize(args.file)
    # We have to seek because for some reason, Capstone doesn't disassemble
    # correctly when providing an offset != 0x0. I think this might be because
    # it tries to disassemble from the beginning of the file regardless of the
    # offset provided. If the binary is corrupted or a fragment, this may fail.
    if offset < binlen:
        file.seek(offset)
    else:
        print('Cannot seek past EOF. File size: 0x{:x} bytes.'.format(binlen))
        exit()
    binary = file.read()
    md = Cs(CS_ARCH_X86, mode)
    md.syntax = CS_OPT_SYNTAX_INTEL
    length = (args.length if args.length > 0 else binlen)
    cursor = 0
    addr_regex = re.compile(r'^0x[a-f0-9]+$')
    while cursor <= binlen:
        for (address, size, mnemonic, op_str) in md.disasm_lite(binary, cursor):
            cursor = address
            tmp = '{:x}'.format(
                int.from_bytes(reversed(binary[address:address+size]), 'little')
            )
            hexbytes = tmp.zfill(len(tmp) + len(tmp) % 2)
            hexarr = [hexbytes[i:i+2] for i in range(0, len(hexbytes), 2)]
            printable = ' '.join(hexarr)
            # Calculate relative addresses, but only if they are immediate. We
            # need to do this because of the fact that Capstone calculates re-
            # lative addresses based on the offset to which we have seek'ed.
            if mnemonic == 'call'                                               \
                    and hexarr[0] == 'e8'                                       \
                    and addr_regex.match(op_str):
                zero_filled = format(int(op_str, 16), 'x').zfill(16)
                unpacked = struct.unpack('>q', bytes.fromhex(zero_filled))[0]
                # Sometimes, Capstone seems to leave the original relative
                # address in the operand string, so we need to account for that.
                if unpacked < 0:
                    rel_addr = unpacked - size - address
                    abs_addr = rel_addr + address + offset + size
                else:
                    rel_addr =     unpacked - address - size
                    abs_addr = rel_addr + address + offset + size
                sign = ('-' if rel_addr < 0 else '+')
                register = ('rip' if mode == CS_MODE_64 else 'eip')
                print(
                    '0x{:x}\t+{:x}\t{:32s} {:s}\t[{:s} {:s} 0x{:x}] # 0x{:x}'   \
                        .format(
                            address + offset,
                            address,
                            printable,
                            mnemonic,
                            register,
                            sign,
                            abs(rel_addr),
                            abs_addr
                        )
                )
            elif mnemonic[0] == 'j'                                             \
                    and is_rel_jump(hexarr)                                     \
                    and addr_regex.match(op_str):
                zero_filled = format(int(op_str, 16), 'x').zfill(16)
                unpacked = struct.unpack('>q', bytes.fromhex(zero_filled))[0]
                if unpacked < 0:
                    rel_addr = unpacked - size - address
                    abs_addr = rel_addr + address + offset + size
                else:
                    rel_addr =     unpacked - address - size
                    abs_addr = rel_addr + address + offset + size
                sign = ('-' if rel_addr < 0 else '+')
                register = ('rip' if mode == CS_MODE_64 else 'eip')
                print(
                    '0x{:x}\t+{:x}\t{:32s} {:s}\t[{:s} {:s} 0x{:x}] # 0x{:x}'   \
                        .format(
                            address + offset,
                            address,
                            printable,
                            mnemonic,
                            register,
                            sign,
                            abs(rel_addr),
                            abs_addr
                        )
                )
            else:
                print(
                    '0x{:x}\t+{:x}\t{:32s} {:s}\t{:s}'.format(address + offset,
                                                               address,
                                                                 printable,
                                                                 mnemonic,
                                                                 op_str)
                )
            if cursor >= length:
                break
        if cursor < binlen:
            if cursor < length:
                print('Invalid instruction at 0x{:x}'.format(offset + cursor),
                    end='')
                if not args.force:
                    print(', truncated 0x{:x} bytes.'.format(length - cursor),
                          end='\n')
                    break
                else:
                    print('', end='\n')
            else:
                break

def is_rel_jump(hexarr):
    if hexarr[0] in ['e9', 'ea', 'eb']:
        return True
    elif hexarr[0] in [format(x, 'x') for x in range(112, 128)]:
        return True
    elif hexarr[0] in [format(x, 'x') for x in range(224, 228)]:
        return True
    elif hexarr[0] == '0f'                                                      \
            and len(hexarr) > 1                                                 \
            and hexarr[1] in [format(x, 'x') for x in range(128, 144)]:
        return True
    return False

if __name__ == '__main__':
    main()