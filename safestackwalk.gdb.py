#######################################################################
# -- safestackwalk.gdb.py
#
# Written by Tom Hebel, 2020
#######################################################################

# python exec(open("/home/thebel/programming/gdb/safestackwalk.gdb.py").read())

#
# To be used when `info frame` fails. This script only uses information
# present in memory starting with a given address as well as GDB's symbol
# resolution. It does not use DWARF debugging information, as this is
# unreliable for the use case. As a result, however, the output of this
# script and that of the `backtrace` command may be different.
#

# TODO
#   - Implement variable resolution.
#   - Align to pep8 style guide.

import gdb
import sys
from typing import List, Dict

# Maximum number of bytes from a frame's low address until we give up
# looking for a frame boundary.
MAX_FRAME_SIZE = 512

# Max. size in bytes of a valid x86 instruction.
# https://stackoverflow.com/questions/14698350/x86-64-asm-maximum-bytes-for-an-instruction
MAX_INSTRUCTION_SIZE = 15

# -----------------------------------------------------------------------
# class GDB_SafeStackWalk --
#
#   Walks up the stack from a supplied address. The address supplied is
#   treated as if it were the stack pointer. Each pointer-sized chunk
#   is examined to determine whether it is a return address. We use a
#   simple heuristic to determine the boundary of a stack frame:
#
#       (1) Does `info symbol` resolve the value of the chunk to an
#           instruction inside a function?
#       (2) Is the preceding instruction a CALL instruction?
#
#   If both conditions are true, then the chunk's value is deemed the
#   saved return address, which marks the frame boundary.
#
#   NOTE: This means that the function arguments are considered to be
#   part of the caller's stack frame rather than the callee's.
# -----------------------------------------------------------------------


class GDB_SafeStackWalk(gdb.Command):

    def __init__(self):
        super(GDB_SafeStackWalk, self).__init__("stackwalk", gdb.COMMAND_USER)

    # TODO:
    #   - Use argparse for argument parsing.
    def invoke(self, args, from_tty):
        argv = args.split()
        argc = len(argv)

        maxFrameSize = MAX_FRAME_SIZE

        if argc == 0:
            print((
                "Must supply low address of stack as argument."
                "\nFor example, the stack pointer for frame #0."
            ))
            return
        elif argc == 2:
            try:
                if 'x' in argv[1]:
                    maxFrameSize = int(argv[1], 16)
                else:
                    maxFrameSize = int(argv[1])
            except:
                print(sys.exc_info())
                return

        try:
            if 'x' in argv[0]:
                stackLoAddr = int(argv[0], 16)
            else:
                stackLoAddr = int(argv[0])
        except:
            print(sys.exc_info())
            return

        stackFrames = self.__processMemory(stackLoAddr, maxFrameSize)
        self.__printStack(stackFrames)

    # Perform a walk from a given memory address up until we can't find any
    # more frames, i.e. while frameHiAddr - frameLoAddr <= maxFrameSize.
    def __processMemory(self, stackLoAddr: int, maxFrameSize: int):
        stackFrames = []
        frameLoAddr = stackLoAddr
        frameHiAddr = frameLoAddr
        addrSize = int(gdb.parse_and_eval('sizeof(void*)'))
        while frameHiAddr - frameLoAddr <= maxFrameSize:
            chunkAddr = frameHiAddr
            try:
                chunkValue = int(gdb.parse_and_eval('*(void**){}'.format(chunkAddr)))
            except gdb.MemoryError:
                print('Inaccessible address: {}'.format(hex(chunkAddr)))
                break
            frameVars = {}
            symbolInfo = gdb.execute('info symbol {}'.format(hex(chunkValue)), to_string=True)
            #print(symbolInfo)
            symbolName = ''
            symbolOffset = 0
            symbolSection = ''
            symbolIsReturnAddrCandidate = False
            symbolIsReturnAddress = False
            if 'in section .text' in symbolInfo:
                symbolInfoArr = self.extractFieldsLikeAwk(symbolInfo)
                #print(symbolInfoArr)
                symbolName = symbolInfoArr[0]
                if ' + ' in symbolInfo:
                    #print('yoohoo')
                    symbolOffset = int(symbolInfoArr[2])
                    symbolSection = symbolInfoArr[5]
                    symbolIsReturnAddrCandidate = True
                else:
                    symbolSection = symbolInfoArr[3]
            if symbolIsReturnAddrCandidate:
                # What this does is attempt to find the previous instruction.
                # Problem is, we don't know its size a priori. So, we count down
                # from MAX_INSTRUCTION_SIZE in bytes until we either reach 1 byte
                # or find a valid call instruction.
                # TODO: figure out a better way of doing this.
                for instrSize in range(MAX_INSTRUCTION_SIZE, 0, -1):
                    prevInstrRaw = gdb.execute('x/i {} - {}'.format(chunkValue, hex(instrSize)), to_string=True)
                    functionCallArr = self.extractFieldsLikeAwk(prevInstrRaw)
                    if len(functionCallArr) > 3                                \
                            and 'call' in functionCallArr[2].lower():
                        symbolIsReturnAddress = True
                        break
                #print(functionCallArr)
                if symbolIsReturnAddress:
                    #print('foobar')
                    chunkCount = int((frameHiAddr - frameLoAddr) / addrSize) + 1
                    #print('x/{}gx {}'.format(chunkCount, frameLoAddr))
                    hexDump = gdb.execute('x/{}gx {}'.format(
                        chunkCount, frameLoAddr), to_string=True)
                    stackFrame = self.__getStackFrameDict()
                    stackFrame['loAddr'] = frameLoAddr
                    stackFrame['hiAddr'] = frameHiAddr
                    stackFrame['returnAddrLoc'] = chunkAddr
                    stackFrame['returnAddr'] = chunkValue
                    stackFrame['returnFunction'] = symbolInfoArr[0]
                    stackFrame['returnFunctionOffset'] = int(symbolInfoArr[2])
                    stackFrame['functionCallAddr'] = int(functionCallArr[0], 16)
                    stackFrame['functionAddr'] = functionCallArr[3]
                    if len(functionCallArr) > 4                         \
                            and len(functionCallArr[4][1:-1]) > 0:
                        stackFrame['functionName'] = functionCallArr[4][1:-1]
                    else:
                        stackFrame['functionName'] = '??'
                    stackFrame['hexDump'] = hexDump
                    stackFrame['returnAddrMismatch'] = False
                    if len(stackFrames) > 0:
                        stackFrame['returnAddrMismatch'] = (
                            stackFrame['functionName']          \
                            != stackFrames[-1]['functionName']  \
                        )
                    stackFrames.append(stackFrame)
                    #print(stackFrame)
                    frameHiAddr += addrSize
                    frameLoAddr = frameHiAddr
            else:   # symbolIsReturnAddrCandidate
                # Put the var resolution code here.
                pass
            frameHiAddr += addrSize
            #break
            #if len(self.__stackFrames) == 5:
            #    #break
            #    pass
        return stackFrames

    def __printStack(self, stackFrames):
        if len(stackFrames) == 0:
            print('No stack frames found.')
            return

        print('{} possible stack frames found.'.format(len(stackFrames)), end='\n\n')
        print('Note: the frame boundary is assumed to be the location of the return address.', end='\n\n')

        mismatchedReturnAddrs = 0
        frameNum = 0
        for stackFrame in stackFrames:
            print(
                'Frame\t#{:<d}\t\t{:>s}(...) at {:<s}'.format(
                    frameNum,
                    stackFrame['functionName'],
                    stackFrame['functionAddr']
                )
            )
            print(
                'Returns to:\t\t{:>s} + {:<s} at {:<s}'.format(
                    stackFrame['returnFunction'],
                    hex(stackFrame['returnFunctionOffset']),
                    hex(stackFrame['returnAddr'])
                )
            )
            if stackFrame['returnAddrMismatch']:
                mismatchedReturnAddrs += 1
                # Let's not be alarmist...
                #print('\t<RETURN ADDRESS DOES NOT MATCH NEXT FRAME>', end='')
            print('Called at\t\t{}'.format(
                hex(stackFrame['functionCallAddr'])))    
            print('Return address at\t{}'.format(
                hex(stackFrame['returnAddrLoc'])))
            print('Hex Dump:')
            print(stackFrame['hexDump'], end='\n\n')
            frameNum += 1
        #print(
        #    'Out of {} frames, {} did not match the return address of the next frame.'.format(
        #        len(self.__stackFrames),
        #        mismatchedReturnAddrs
        #    )
        #)

    @staticmethod
    def extractFieldsLikeAwk(line: str, delim: str=' ') -> List[str]:
        # The split() then join() is done to eliminate multiple occurrences
        #   of delim.
        return delim.join(line.split()).split(delim)

    @staticmethod
    def __getStackFrameDict() -> Dict:
        return {
            'loAddr': 0,
            'hiAddr': 0,
            'returnAddrLoc': 0,
            'returnAddr': 0,
            'returnFunction' : '',
            'returnFunctionOffset': 0,
            'functionCallAddr': 0,
            'functionAddr': 0,
            'functionName': '',
            'returnAddrMismatch': False,
            'variables': {},
            'hexDump': ''
        }


GDB_SafeStackWalk()
