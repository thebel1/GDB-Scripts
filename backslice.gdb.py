# gdb /usr/bin/true
# py exec(open('/home/thebel/programming/gdb/backslice.gdb.py').read())
# bs &main '&main + 185' &main+161
# bs 0x0000000000001680 0x0000000000001739 0x0000000000001721
# bs &main &main+190 &main+16 rsi '{"regs":{"rdi":"0x2","rsi":"0x1"}}'

# TODO:
# - Figure out how to package all dependencies and make the script portable.

import gdb
import sys
import shlex
import argparse
import pprint
import json
import triton

x64RegToTritonSymbolMapping = {
	"rax":  triton.REG.X86_64.RAX,
	"rbx":  triton.REG.X86_64.RBX,
	"rcx":  triton.REG.X86_64.RCX,
	"rdx":  triton.REG.X86_64.RDX,
	"rsi":  triton.REG.X86_64.RSI,
	"rdi":  triton.REG.X86_64.RDI,
	"rbp":	triton.REG.X86_64.RBP,
	"rsp":	triton.REG.X86_64.RSP,
	"rip":	triton.REG.X86_64.RIP,
	"r8":	triton.REG.X86_64.R8,
	"r9":	triton.REG.X86_64.R9,
	"r10":  triton.REG.X86_64.R10,
	"r11":  triton.REG.X86_64.R11,
	"r12":  triton.REG.X86_64.R12,
	"r13":  triton.REG.X86_64.R13,
	"r14":  triton.REG.X86_64.R14,
	"r15":  triton.REG.X86_64.R15
}

backSliceParams = {
	"regs": {
		"rax": 0, "rbx": 0, "rcx": 0, "rdx": 0,
		"rsi": 0, "rdi": 0,
		"rbp": 0x7fffffffffff, "rsp": 0x7fffffffffff,
		"rip": -1, # Rip is set to -1 to differentiate it from a valid rip of 0x0.
		"r8": 0, "r9": 0, "r10": 0, "r11": 0,
		"r12": 0, "r13": 0, "r14": 0, "r15": 0
	},
	"mem": {}
}

backSliceParamsSample = {
	"regs": {
		"rax": 0, "rbx": 0, "rcx": 0, "rdx": 0,
		"rsi": 0, "rdi": 0,
		"rbp": 0, "rsp": 0,
		"rip": 0,
		"r8": 0, "r9": 0, "r10": 0, "r11": 0,
		"r12": 0, "r13": 0, "r14": 0, "r15": 0
	},
	"mem": {"0x1000": "0x1", "0x2000": "0x2", "0x3000": "0x3"}
}

def info(msg):
	print(f'info: {msg}')

def warn(msg):
	print(f'warning: {msg}')

def error(msg):
	print(f'error: {msg}')

def fatal(msg):
	print(f'fatal: {msg}')

class ArgumentParser(argparse.ArgumentParser):

	def exit(self, *argv):
		raise TypeError

class GDB_Alias(gdb.Command):

	def __init__(self, alias, command):
		super().__init__(alias, gdb.COMMAND_NONE)
		self.command = command

	def invoke(self, args, from_tty):
		gdb.execute(f'{self.command} {args}')

class GDB_BackSlice(gdb.Command):

	def __init__(self, command):
		super().__init__(command, gdb.COMMAND_USER)
		self.command = command
		self.pprint = pprint.PrettyPrinter(compact=True)

	def invoke(self, argstr, from_tty):
		argv = None
		try:
			argv = shlex.split(argstr)
		except ValueError:
			fatal('unable to parse arguments; check syntax')
			return
		sampleJson = self.pprint.pformat(backSliceParamsSample)
		
		parser = ArgumentParser(prog=self.command,
								formatter_class=argparse.RawTextHelpFormatter,
								description=(
									'A simple binary backwards slicer. Works on'
									' blobs of binary x86-64 code. Put in a'
									' target instruction and register, and find'
									' out where it got its value from.'
									'\n\nUses the powerful Triton library from'
									' Quarkslab: https://triton.quarkslab.com/'
									'\n\nComplete JSON dictionary of "params"'
									f' argument:\n{sampleJson}'
								))
		parser.add_argument('start_addr',
							help=(
								'the start address of the code to analyze;'
								' takes a GDB expression'
							),
							type=str)
		parser.add_argument('end_addr',
							help=(
								'the end address of the code to analyze;'
								' takes a GDB expression'
							),
							type=str)
		parser.add_argument('target_addr',
							help=(
								'the address from which to backslice;'
								' takes a GDB expression'
							),
							type=str)
		parser.add_argument('target_reg',
							help='the target register whose value to track',
							type=str)
		parser.add_argument('params',
							nargs='?',
							help=(
								'a nested dictionary of configuration'
								' parameters; must be typed on one line'
							),
							type=str)
		try:
			args = parser.parse_args(argv)
		except TypeError:
			return
		
		# Validate and initialize JSON params.
		params = None
		if args.params:
			try:
				new_params = json.loads(args.params)
				try:
					self.validateParams(new_params)
					params = self.mergeParams(new_params)
				except TypeError:
					fatal('invalid "params" argument supplied')
					return
			except json.decoder.JSONDecodeError as exc:
				fatal(f'unable to decode "params" argument as JSON: {exc}')
				return
		else:
			params = backSliceParams

		# Validate and initialize addresses.
		start_addr = 0
		end_addr = 0
		target_addr = 0
		entry_addr = 0
		try:
			start_addr = int(gdb.parse_and_eval(args.start_addr))
		except gdb.error:
			fatal('unable to evaluate start_addr expression')
			return
		try:
			end_addr = int(gdb.parse_and_eval(args.end_addr))
		except gdb.error:
			fatal('unable to evaluate end_addr expression')
			return
		try:
			target_addr = int(gdb.parse_and_eval(args.target_addr))
		except gdb.error:
			fatal('unable to evaluate target_addr expression')
			return
		if start_addr > end_addr:
			fatal('start_addr must be smaller than end_addr')
			return
		elif target_addr < start_addr or target_addr > end_addr:
			fatal('target_addr must be in [start_addr, end_addr]')
			return
		if params['regs']['rip'] == -1:
			params['regs']['rip'] = start_addr
			entry_addr = start_addr
		elif params['regs']['rip'] < start_addr									\
				or params['regs']['rip'] > end_addr:
			fatal('the initial rip must be in [start_addr, end_addr]')
			return
		else:
			entry_addr = params['regs']['rip']

		# Validate and initialize target_reg.
		target_reg = None
		target_reg_name = ''
		if args.target_reg in x64RegToTritonSymbolMapping:
			target_reg = x64RegToTritonSymbolMapping[args.target_reg]
			target_reg_name = args.target_reg
		else:
			fatal(f'invalid target_reg: {args.target_reg}')
			return

		inferior = gdb.selected_inferior()
		arch_raw = gdb.execute('show architecture', to_string=True)
		arch = arch_raw.split(' ')[-1][0:-2]
		if arch != 'i386:x86-64':
			printable_arch = arch.replace('"', '\\"')
			fatal((f'unsupported architecture "{printable_arch}";'
				  ' only x86-64 currently supported'))
			return

		# Ensure memory at start_addr, end_addr, target_addr, and entry_addr is
		# accessible.
		mem_bytes = None
		try:
			test_addr = start_addr
			inferior.read_memory(test_addr, 1)
			test_addr = end_addr
			inferior.read_memory(test_addr - 1, 1)
			test_addr = target_addr
			if target_addr > start_addr:
				inferior.read_memory(test_addr - 1, 1)
			else:
				inferior.read_memory(test_addr, 1)
			test_addr = entry_addr
			if entry_addr > start_addr:
				inferior.read_memory(test_addr - 1, 1)
			else:
				inferior.read_memory(test_addr, 1)
			mem_bytes = inferior.read_memory(start_addr, end_addr)
		except gdb.MemoryError as exc:
			fatal(f'unable to read memory at address 0x{test_addr:x}')
			return

		# Build instruction bytes dictionary for Triton to consume.
		disas_raw = gdb.execute(f'disassemble/r 0x{start_addr:x},0x{end_addr:x}',
								to_string=True)
		disas_lines = disas_raw.split('\n')[1:-2]
		bytes_dict = {}
		curr_offset = 0
		for line in disas_lines:
			instr_len = len(line.split('\t')[1].split(' '))
			bytes_dict[start_addr+curr_offset] = bytes(mem_bytes[curr_offset	\
												   :curr_offset+instr_len])
			curr_offset +=  instr_len
		
		# Set up Triton.
		ctx = triton.TritonContext()
		ctx.setArchitecture(triton.ARCH.X86_64)
		ctx.setMode(triton.MODE.ALIGNED_MEMORY, True)
		ctx.setAstRepresentationMode(triton.AST_REPRESENTATION.SMT)
		
		try:
			for reg, val in params['regs'].items():
				ctx.setConcreteRegisterValue(ctx.registers.__dict__[reg], val)
		except TypeError:
			fatal(f'invalid value {val} for register {reg}')
			return

		for addr, val in params['mem'].items():
			ctx.setConcreteMemoryValue(addr, val)
		
		# Emulate.
		rip = entry_addr
		exec_path = []
		while rip in bytes_dict:
			instr = triton.Instruction()
			instr.setOpcode(bytes_dict[rip])
			instr.setAddress(rip)
			ctx.processing(instr)
			exec_path.append(instr)
			for se in instr.getSymbolicExpressions():
				se.setComment(str(instr))
			if rip == target_addr:
				try:
					symreg = ctx.getSymbolicRegisters()[target_reg]
				except KeyError as exc:
					warn((f'target register `{target_reg_name}` does not have a'
						  f' symbolic value yet at final address 0x{rip:x};'
						  ' execution_path:'))
					for instr in exec_path:
						print(instr)
					return
				sliced = ctx.sliceExpressions(symreg)
				if len(sliced.items()) > 0:
					print(('backsliced instructions from target address'
						   f' 0x{target_addr:x}:'))
					for k, v in sorted(sliced.items()):
						print(v.getComment())
				else:
					error((f'unable to backslice {target_reg:s}'
						   f' from target 0x{target_addr:x}'
						   f' to entry 0x{entry_addr:x}.'))
				break
			rip = ctx.getConcreteRegisterValue(ctx.registers.rip)
		if rip == entry_addr:
			error(f'unable to progress from entry 0x{entry_addr:x}')
			return
		elif rip != target_addr:
			error((f'unable to get from entry 0x{entry_addr:x}'
				  f' to target 0x{target_addr:x}; execution path:'))
			for instr in exec_path:
				print(instr)
			return

	def validateParams(self, params):
		for k, v in params.items():
			if k not in backSliceParams:
				printable_key = k.replace('"', '\\"')
				error(f'invalid key: params["{printable_key}"]')
				raise TypeError
			elif type(v) != type(backSliceParams[k]):
				printable_val = v.replace('"', '\\"')
				error(f'type of {printable_val} != {type(backSliceParams[k])}')
				raise TypeError
		if 'regs' in params:
			for k, v in params['regs'].items():
				if k not in x64RegToTritonSymbolMapping:
					error(f'invalid register: {k}')
					raise TypeError
		if 'mem' in params and type(params['mem']) != dict:
			error(f'params["mem"] must be a dictionary')
			raise TypeError

	def mergeParams(self, new_params):
		params = backSliceParams
		if 'regs' in new_params:
			for k, v in new_params['regs'].items():
				try:
					params['regs'][k] = int(gdb.parse_and_eval(v))
				except (gdb.error, ValueError):
					printable_val = v.replace('"', '\\"')
					error(('unable to parse register expression: params["mem"]'
						   f'["{k}"]="{printable_val}"'))
					raise TypeError
		if 'mem' in new_params:
			for k, v in new_params['mem'].items():
				try:
					evaled_key = int(gdb.parse_and_eval(k))
					evaled_val = int(gdb.parse_and_eval(v))
					params['mem'][evaled_key] = evaled_val
				except (gdb.error, ValueError):
					printable_key = k.replace('"', '\\"')
					printable_val = v.replace('"', '\\"')
					error(('unable to parse params["mem"]'
						   f'["{printable_key}"]="{printable_val}"'))
					raise TypeError
		return params

	def mapRegToTritonSymbol(self, reg):
		if reg not in x64RegToTritonSymbolMapping:
			return None
		else:
			return x64RegToTritonSymbolMapping[reg]

GDB_BackSlice('backslice')
GDB_Alias('bs', 'backslice')