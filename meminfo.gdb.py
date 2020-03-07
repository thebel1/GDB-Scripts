#######################################################################
# -- meminfo.gdb.py
# Written by Tom Hebel, 2020
#######################################################################

# TODO:
# - Implement an algorithm for finding mmapped chunks (<https://dfrws.org/sites/default/files/session-files/paper_linux_memory_forensics_-_dissecting_the_user_space_process_heap.pdf>)
# - Implement verbosity flag in cmd line args.
# - Align to Python style guide PEP8.

# NOTE:
# - Always re-initialize class members in the constructur, e.g.:
#
#   class SomeClass:
#       someMember = []
#       def __init__ (self):
#           someMember = []
#
#   Reason: https://stackoverflow.com/questions/25401619/python-is-reusing-variables-from-one-instance-of-an-object-for-a-new-one
#
# - Use class member access "modifiers":
#       member1     <- public
#       _member2    <- protected
#       __member3   <- private
#
# See: https://www.tutorialsteacher.com/python/private-and-protected-access-modifiers-in-python
#
# REFERENCES:
#   - malloc source: https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#1772
#   - malloc internals:
#       https://sourceware.org/glibc/wiki/MallocInternals
#       http://core-analyzer.sourceforge.net/index_files/Page335.html
#
# - Cool GDB Python stuff: https://mcgdb.0x972.info/doc/_modules/mcgdb/toolbox/my_gdb.html

import gdb

# ------------------------------------------------
# CONSTANTS
# ------------------------------------------------

# See: https://code.woboq.org/userspace/glibc/sysdeps/x86/bits/wordsize.h.html
MALLOC_WORD_SIZE = 64

# See: https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#853
MALLOC_SIZE_OF_LONG = 8
MALLOC_DEFAULT_MMAP_THRESHOLD_MAX = 4 * 1024 * 1024 * MALLOC_SIZE_OF_LONG

# Used for calculating the max size of a heap. We are assuming x64 for this.
# See:
#   - usage of top() and heap_for_ptr() macros:
#       https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#5486
#   - top() macro: https://code.woboq.org/userspace/glibc/malloc/arena.c.html#47
#   - heap_for_ptr() macro: https://code.woboq.org/userspace/glibc/malloc/arena.c.html#127
MALLOC_HEAP_MAXSIZE = 2 * MALLOC_DEFAULT_MMAP_THRESHOLD_MAX

# Size in bytes for a stack frame's red zone.
# See: https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64
STACK_FRAME_REDZONE_SIZE = 128

# The minimum threshold for (rsp - rbp) before the stack frame is considered
#   to be small enough to likely "spill" its local variables into the 128 bytes
#   past rsp.
# See: ibid.
STACK_FRAME_MINSIZE = 8 + 4

# The threshold in bytes for abs(rsp - rbp) before we consider the frame pointer
#   to have been omitted during compilation. We will then use the rsp of the
#   previous stack frame as our rbp. Note: this value is arbitrary and chosen
#   based on my gut feeling rather than anything concrete.
# See: ibid.
STACK_FRAME_MAXSIZE = 512

# ------------------------------------------------
# UTILS
# ------------------------------------------------
# NOTE: Make sure all member functions are static!

# Usage notes:
#   - All pointers must be passed as ints.
#   - All pointers are returned as ints and must be parse_and_eval'd or "cast"
#       to hex() as needed. This is to keep things generic and avoid the performance
#       hit of loading malloc structs into Gdb.
class MallocMacros:
    
    # See: https://code.woboq.org/userspace/glibc/malloc/arena.c.html#47
    @staticmethod
    def top (ar_ptr):
        return int(gdb.parse_and_eval("(unsigned long)((struct malloc_state*){})->top" \
                    .format(ar_ptr)))

    # See: https://code.woboq.org/userspace/glibc/malloc/arena.c.html#125
    @staticmethod
    def heap_for_ptr (ptr):
        return int(gdb.parse_and_eval("(unsigned long)((unsigned long){} & ~({} - 1))" \
                    .format(ptr, MALLOC_HEAP_MAXSIZE)))

# ------------------------------------------------

class MemInfoUtils:

    @staticmethod
    def findContainerForAddress (containerList):        # Type: MemoryContainer
        pass

# ------------------------------------------------
# MALLOC INFO
# ------------------------------------------------

# type = struct malloc_par {
#     unsigned long trim_threshold;
#     size_t top_pad;
#     size_t mmap_threshold;
#     size_t arena_test;
#     size_t arena_max;
#     int n_mmaps;
#     int n_mmaps_max;
#     int max_n_mmaps;
#     int no_dyn_threshold;
#     size_t mmapped_mem;
#     size_t max_mmapped_mem;
#     size_t max_total_mem;
#     char *sbrk_base;
# }
class MallocInfo:

    malloc_parPtr = None        # Type: gdb.Type (struct malloc_par)
    sbrkBase = 0
    arenas = []                 # Type: List[MallocArenaInfo]
    loAddr = 0
    hiAddr = 0

    __memoryContainers = None   # Type: List[MemoryContainer]

    def __init__ (self, memoryContainers):
        self.malloc_parPtr = gdb.parse_and_eval("mp_")
        self.sbrkBase = int(gdb.parse_and_eval("(unsigned long)mp_->sbrk_base"))
        self.arenas = []
        self.loAddr = self.sbrkBase
        self.__memoryContainers = memoryContainers

    def loadArenas (self, loadHeaps=True):
        mainArenaAddr = int(gdb.parse_and_eval("(unsigned long)&main_arena"))
        currArenaAddr = mainArenaAddr
        isMain = True
        while True:
            # DEBUG
            if len(self.arenas) == 2: break
            # /DEBUG
            print("\t[{}] Arena (struct malloc_state*){}".format(len(self.arenas)+1, hex(currArenaAddr)))
            currArena = MallocArenaInfo(self.__memoryContainers, currArenaAddr, isMain)
            if loadHeaps:
                currArena.loadHeaps()
            self.arenas.append(currArena)
            if currArena.hiAddr > self.hiAddr:
                self.hiAddr = currArena.hiAddr
            currArenaAddr = int(gdb.parse_and_eval(("(unsigned long)((struct malloc_state*){})->next") \
                                .format(currArenaAddr)))
            isMain = False
            if currArenaAddr == mainArenaAddr:
                break

        print("\t[Done]\n")

        self.__memoryContainers.append(MemoryContainer(self.loAddr, self.hiAddr, self, "All_Heaps"))

# ------------------------------------------------

# type = struct malloc_state {
#     mutex_t mutex;
#     int flags;
#     mfastbinptr fastbinsY[10];
#     mchunkptr top;
#     mchunkptr last_remainder;
#     mchunkptr bins[254];
#     unsigned int binmap[4];
#     struct malloc_state *next;
#     struct malloc_state *next_free;
#     size_t system_mem;
#     size_t max_system_mem;
# }
class MallocArenaInfo:
    
    malloc_stateAddr = 0        # Type: int (struct malloc_state*)
    isMain = 0
    topChunkAddr = 0
    currSize = 0
    maxSize = 0
    loAddr = 0                  # Where the arena starts
    hiAddr = 0                  # Where the arena ends
    heaps = []                  # Type: List[MallocHeapInfo]

    __memoryContainers = None   # Type: List[MemoryContainer]

    def __init__ (self, memoryContainers, malloc_stateAddr, isMain=False):
        self.malloc_stateAddr = int(malloc_stateAddr)
        self.isMain = isMain
        self.topChunkAddr = int(gdb.parse_and_eval("(unsigned long)((struct malloc_state*){})->top" \
                                .format(hex(malloc_stateAddr))))

        # See:
        #   - https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/implementation/malloc/
        #   - https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#malloc_state
        self.currSize = int(gdb.parse_and_eval("((struct malloc_state*){})->system_mem" \
                            .format(hex(malloc_stateAddr))))
        self.maxSize = int(gdb.parse_and_eval("((struct malloc_state*){})->max_system_mem" \
                            .format(hex(malloc_stateAddr))))
        
        self.loAddr = 0
        self.hiAddr = 0
        self.heaps = []
        self.__memoryContainers = memoryContainers

    def loadHeaps (self):
        currHeapAddr = MallocMacros.heap_for_ptr(self.topChunkAddr)
        while True:
            print("\t\t({}) Heap (heap_info*){}".format(len(self.heaps)+1, hex(currHeapAddr)))
            currHeap = MallocHeapInfo(self.__memoryContainers, self, currHeapAddr)
            self.heaps.append(currHeap)
            if currHeap.loAddr < self.loAddr:
                self.loAddr = currHeap.loAddr
            if currHeap.hiAddr > self.hiAddr:
                self.hiAddr = currHeap.hiAddr
            currHeapAddr = int(gdb.parse_and_eval("(unsigned long)((heap_info*){})->prev".format(currHeapAddr)))
            if currHeapAddr == 0:
                break

# ------------------------------------------------

# See:
#   - https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#5485
#   - https://sourceware.org/glibc/wiki/MallocInternals#Arenas_and_Heaps
class MallocHeapInfo:
    
    arenaObj = None             # Type: MallocArenaInfo
    heap_infoAddr = 0           # Type: int (heap_info*)
    size = 0
    loAddr = 0
    hiAddr = 0

    __memoryContainers = None   # Type: List[MemoryContainer]

    def __init__ (self, memoryContainers, arenaObj, heap_infoAddr):
        self.arenaObj = arenaObj
        self.heap_infoAddr = int(heap_infoAddr)
        self.size = int(gdb.parse_and_eval("((heap_info*){})->size".format(heap_infoAddr)))
        self.loAddr = int(gdb.parse_and_eval("{}+sizeof(*(heap_info*)0)".format(heap_infoAddr)))
        self.hiAddr = self.loAddr + self.size
        self.__memoryContainers = memoryContainers
        self.__memoryContainers.append(MemoryContainer(self.loAddr, self.hiAddr, self, "Heap"))

# ------------------------------------------------
# CALL STACK INFO
# ------------------------------------------------

class GdbInferiorInfo:
    
    threads = []                # Type: List[GdbThreadInfo]
    
    __inferior = None           # Type: gdb.Inferior
    __memoryContainers = None   # Type: List[MemoryContainer]

    def __init__ (self, memoryContainers):
        self.threads = []
        self.__inferior = gdb.inferiors()[0]
        self.__memoryContainers = memoryContainers

    def loadThreads(self, loadCallStacks=True):
        gdbThreads = self.__inferior.threads()

        currThreadNum = 1
        for gdbThread in reversed(gdbThreads):
            # DEBUG
            if currThreadNum == 10: break
            # /DEBUG
            thread = GdbThreadInfo(self.__memoryContainers, gdbThread)
            print("\t[{}/{}] {} {}".format(currThreadNum,   \
                                           len(gdbThreads), \
                                           thread.funcName, \
                                           "".join(thread.threadInfo.split(' ')[4:6]).split(']')[0]))
            if loadCallStacks:
                thread.loadCallStack()
            self.threads.append(thread)
            currThreadNum += 1
        print("\t[Done]\n")

# ------------------------------------------------

class GdbThreadInfo:
    
    rip = 0
    funcName = ""
    threadInfo = ""
    callStack = None            # Type: GdbCallStackInfo
    
    __gdbThread = None          # Type: gdb.Thread
    __origGdbState = None       # Type: GdbState
    __memoryContainers = None   # Type: List[MemoryContainer]

    def __init__ (self, memoryContainers, gdbThread):
        self.__origGdbState = GdbState(gdb.selected_thread(), gdb.selected_frame())
        gdbThread.switch()
        lastGdbFrame = gdb.newest_frame()
        lastGdbFrame.select()
        self.rip = int(gdb.parse_and_eval("(long) $rip"))
        self.threadInfo = gdb.execute("thread", to_string=True).strip()
        self.funcName = str(lastGdbFrame.name()).strip()
        self.callStack = None
        self.__gdbThread = gdbThread
        self.__origGdbState.restore()
        self.__memoryContainers = memoryContainers

    def loadCallStack (self):
        self.callStack = GdbCallStackInfo(self.__memoryContainers, self.__origGdbState, self.__gdbThread)
        self.callStack.loadCallStackFrames()

# ------------------------------------------------

# NOTE: There are "gaps" between consecutive stack frames, which is where the
#   function arguments live as well as the saved pc and the return address.
#   Thus, for consecutive frames F1 and F0 (where F0 is newer),
#   rsp(F1) - rbp(F0) > 0. We can use this fact in order to distinguish
#   between local variables and arguments.
class GdbCallStackInfo:
    
    loAddr = 0
    hiAddr = 0
    frames = []                 # Type: List[GdbCallStackFrameInfo]
    
    __gdbThread = None          # Type: gdb.Thread
    __gdbLatestFrame = None     # Type: gdb.Frame
    __origGdbState = None       # Type: GdbState
    __memoryContainers = None   # Type: List[MemoryContainer]

    def __init__ (self, memoryContainers, gdbState, gdbThread):
        self.__origGdbState = gdbState
        gdbThread.switch()
        self.__gdbThread = gdb.selected_thread()
        self.__gdbLatestFrame = gdb.selected_frame()
        self.__origGdbState.restore()
        self.__memoryContainers = memoryContainers

    def loadCallStackFrames (self):
        self.__gdbThread.switch()
        self.__gdbLatestFrame.select()

        currGdbFrame = gdb.selected_frame()
        isNewestFrame = True

        while True:
            currFrame = GdbCallStackFrameInfo(self.__memoryContainers, self.__origGdbState, currGdbFrame)
            self.frames.append(currFrame)
            currGdbFrame = currGdbFrame.older()
            isNewestFrame = False
            if currGdbFrame is None:
                break
            else:
                currGdbFrame.select()
        
        self.loAddr = self.frames[len(self.frames)-1].loAddr
        self.hiAddr = self.frames[0].hiAddr
        self.__memoryContainers.append(MemoryContainer(self.loAddr, self.hiAddr, self, "Call_Stack"))

        self.__origGdbState.restore()

# ------------------------------------------------

class GdbCallStackFrameInfo:

    isGood = 0                  # If this is True, it means that the loAddr & hiAddr are wonky.
    loAddr = 0
    hiAddr = 0
    rsp = 0
    rbp = 0
    arguments = set()           # Type: set(gdb.Symbol)
    locals = set()              # Type: set(gdb.Symbol)

    __gdbFrame = None           # Type: gdb.Frame
    __memoryContainers = None   # Type: List[MemoryContainer]

    def __init__ (self, memoryContainers, gdbState, gdbFrame):
        gdbFrame.select()
        self.__gdbFrame = gdbFrame
        self.rsp = int(gdb.parse_and_eval("(unsigned long)$rsp"))
        self.rsp = int(gdb.parse_and_eval("(unsigned long)$rbp"))
        frameBoundaries = self.__findFrameBoundaries(self.rsp, self.rbp)
        self.loAddr = frameBoundaries[0]
        self.hiAddr = frameBoundaries[1]
        self.arguments = set()
        self.locals = set()
        self.__memoryContainers = memoryContainers
        self.__memoryContainers.append(MemoryContainer(self.loAddr, self.hiAddr, self, "Stack_Frame"))
        gdbState.restore()

    # Traverse symbols until you find the ones that demark the frame boundaries.
    # See: https://stackoverflow.com/questions/30013252/get-all-global-variables-local-variables-in-gdbs-python-interface
    def __findFrameBoundaries (self, loAddrFallback, hiAddrFallback):

        gdbBlock = None
        loAddr = pow(2, 64)
        hiAddr = 0
        try:
            gdbBlock = self.__gdbFrame.block()
            # Determine the frame boundaries based on the addresses of local variables.
            for gdbSymbol in gdbBlock:
                if gdbSymbol.is_argument:
                    self.arguments.add(gdbSymbol)
                elif gdbSymbol.is_variable:
                    self.locals.add(gdbSymbol)
                # TODO: decide if gdbSymbol.is_argument should count as well as .is_variable.
                if gdbSymbol.is_variable:
                        currSymbolAddr = 0
                        currSymbolSize = 0
                        try:
                            currSymbolAddr = int(gdb.parse_and_eval("(unsigned long)&{}".format(gdbSymbol.name)))
                            currSymbolSize = int(gdb.parse_and_eval("sizeof({})".format(gdbSymbol.name)))
                        except:
                            continue
                        if currSymbolAddr < loAddr:
                            loAddr = currSymbolAddr + currSymbolSize
                        if currSymbolAddr > hiAddr:
                            hiAddr = currSymbolAddr
        except:
            # If GDB can't find the block for this frame, we gracefully degrade
            #   to using the fallback addresses supplied (probably rsp & rbp).
            loAddr = loAddrFallback
            hiAddr = hiAddrFallback

        # Check if the stack frame is too large & fall back if yes.
        # This will likely be the case because rbp is garbage or used as a general
        #   purpose register.
        if abs(hiAddr - loAddr) > STACK_FRAME_MAXSIZE:
            loAddr = loAddrFallback
            hiAddr = hiAddrFallback
        
        # If the frame is still too large, use rsp as both loAddr and hiAddr.
        # TODO: Consider running a second pass over the frames array and use
        #   the outer boundaries of adjacent frames as the inner boundaries for
        #   the current one. I.e. frameA]<--frameB-->[frameC
        if abs(hiAddr - loAddr) > STACK_FRAME_MAXSIZE:
            loAddr = self.rsp
            hiAddr = self.rsp

        return [loAddr, hiAddr]

# ------------------------------------------------

# Since we have to switch to the current thread and newest frame, we have to
#   store the original thread and frame so we can cleanly restore GDB's state
#   to where the user left off.
class GdbState:

    __gdbThread = None          # Type: gdb.Thread
    __gdbFrame = None           # Type: gdb.Frame

    def __init__ (self, gdbThread, gdbFrame):
        self.__gdbThread = gdbThread
        self.__gdbFrame = gdbFrame

    def restore (self):
        self.__gdbThread.switch()
        self.__gdbFrame.select()

# ------------------------------------------------
# MISC.
# ------------------------------------------------

# Used to store the start and end of arenas, heaps, stacks, and individual stack frames.
class MemoryContainer:

    loAddr = 0
    hiAddr = 0
    obj = None                  # Type: [MallocArenaInfo,MallocHeapInfo,GdbCallStackInfo,GdbCallStackFrameInfo]
    objTypeName = ""

    def __init__ (self, loAddr, hiAddr, obj, objTypeName):
        self.loAddr = loAddr
        self.hiAddr = hiAddr
        self.obj = obj
        self.objTypeName = objTypeName

# ------------------------------------------------
# GDB COMMAND
# ------------------------------------------------

class Gdb_UWMallocInfo (gdb.Command):

    __hasRun = 0
    __memoryContainers = []     # Type: List[MemoryContainer]
    __mallocInfo = None         # Type: MallocInfo
    __inferiorInfo = None       # Type: GdbInferiorInfo

    def __init__ (self):
        super (Gdb_UWMallocInfo, self).__init__("meminfo", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        argv = arg.split()
        argc = len(argv)
        return self.__UWMallocInfo(argc, argv)

    def __UWMallocInfo (self, argc, argv):
        
        # Handle cmdline args.
        if argc > 0:
            if argv[0] == "refresh":
                self.__hasRun = 0
            elif argv[0] == "address":
                if argc > 1:
                    expr = "{}".format(" ".join(argv[1:]))
                    memContDict = self.__findAddress(expr)
                    if len(memContDict["theList"]) == 0:
                        print("The address \"{}\" could not be found inside any heap or stack.\n".format(memContDict["addr"])  \
                                + "If this is a variable, it may be allocted statically.\n"                                    \
                                + "If it is a class, function, or other symbol, it will not be located in a heap or stack.")
                        return
                    print("The address \"{}\" was found in:".format(memContDict["addr"]))
                    for memCont in memContDict["theList"]:
                        pass
                else:
                    self.__printHelpText()
            elif argv[0] == "containers":
                if not self.__hasRun:
                    self.__refreshData()
                print("Memory Containers:")
                print("---")
                memContNum = 1
                for memCont in self.__memoryContainers:
                    print("[{}]\t\tType={:<32s} lowAddress={:<16s} highAddress={:<16s}" \
                            .format(memContNum, memCont.objTypeName, hex(memCont.loAddr), hex(memCont.hiAddr)))
                    memContNum += 1
                print("[Done]")
            elif argv[0] == "help":
                self.__printHelpText()
        else:
            if not self.__hasRun:
                self.__refreshData()
            self.__prettyPrintSummary()

    def __loadMallocInfo (self):
        self.__mallocInfo = MallocInfo(self.__memoryContainers)
        self.__mallocInfo.loadArenas()

    def __loadThreadInfo (self):
        self.__inferiorInfo = GdbInferiorInfo(self.__memoryContainers)
        self.__inferiorInfo.loadThreads()

    def __findAddress (self, expr):
        if not self.__hasRun:
            self.__refreshData()
        addr = 0
        try:
            addr = int(gdb.parse_and_eval("(unsigned long)({})".format(expr)))
            return self.__findInMemoryContainers(addr)
        except:
            return {"addr": 0, "theList": []}

    def __findInMemoryContainers (self, addr):
        memContList = []
        for memCont in self.__memoryContainers:
            if addr >= memCont.loAddr and addr <= memCont.hiAddr:
                memContList.append(memCont)
        return {"addr": addr, "theList": memContList}

    def __refreshData (self):
        self.__memoryContainers = []
        print("Loading heap info...")
        self.__loadMallocInfo()
        print("Loading stack info...")
        self.__loadThreadInfo()
        self.__hasRun = 1

    def __prettyPrintSummary (self):
        heapCount = 0
        for arena in self.__mallocInfo.arenas:
            heapCount += len(arena.heaps)
        
        frameCount = 0
        for thread in self.__inferiorInfo.threads:
            for frame in thread.callStack.frames:
                frameCount += 1
        
        print("Summary:")
        print("---")
        print("Heap Start Address (sbrk_base):\t{}".format(hex(self.__mallocInfo.sbrkBase)))
        print("Number of Arenas:\t\t{}".format(len(self.__mallocInfo.arenas)))
        print("Number of Heaps:\t\t{}".format(heapCount))
        print("Number of Threads:\t\t{}".format(len(self.__inferiorInfo.threads)))
        print("Number of Stack Frames:\t\t{}".format(frameCount))
        print("Number of Memory Containers:\t{}".format(len(self.__memoryContainers)))

        print("")
        print("Type `meminfo help` for a list of commands.")

    # TODO: Implement this.
    def _printHelpText (self):
        pass

# ------------------------------------------------

Gdb_UWMallocInfo()

# ================================================
