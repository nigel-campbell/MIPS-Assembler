# CS 3220 Project 1 Assembler
# Nigel Campbell and Aditya Somani

import re
import copy
import sys

def is_digit(s):
	try:
		float(s); return True;
	except ValueError:
		return False

# Returns the string representation of 
# the machine code used for a particular instr
# register specified as part of the instruction.
def parseLine(line, labels, address):
	while '' in line: line.remove('')
	if len(line) == 0:
		return '', address
	machineBits = '';
	firstToken = line[0];
	R_TYPE1 = '0000'; R_TYPE2 = '0010'; LW_TYPE = '1001'; SW_TYPE = '0101';
	I_TYPE1 = '1000'; I_TYPE2 = '1010'; J_TYPE1 = '0110'; J_TYPE2 = '1011';
	special_inst = ['br', 'not','ble','bge','call','ret','jmp']
	instr_type_bits = { R_TYPE1: generate_R_TYPE_BITS,
				   R_TYPE2: generate_R_TYPE_BITS,
				   LW_TYPE: generate_M_TYPE_BITS,
				   SW_TYPE: generate_M_TYPE_BITS,
				   I_TYPE1: generate_I_TYPE_BITS,
				   I_TYPE2: generate_I_TYPE_BITS,
				   J_TYPE1: generate_J_TYPE_BITS,
				   J_TYPE2: generate_J_TYPE_BITS }
	if len(firstToken) == 0:
		return line, address;
	elif firstToken[0] == ';':
		return line, address;
	elif generateOpcode(firstToken.lower()) != ('FFFF', 'FFFF'):
		address = address + 1; dest_reg = ''
		prim_opcode, sec_opcode = generateOpcode(firstToken.lower()); # Fetches opcodes
		if prim_opcode == SW_TYPE: # Spe
			temp_reg_addr = generateRegAddr( line[2].split('(')[1].replace(')', '') ) # Gets RS1 from line
			dest_reg = '{0:04b}'.format(temp_reg_addr) 
		else:
			dest_reg = '{0:04b}'.format(generateRegAddr( line[1]) ) # Fetches RD address 
		machineBits = machineBits + prim_opcode + sec_opcode + dest_reg + instr_type_bits[prim_opcode](line, labels, address); # Concatenates primary and secondary opcodes

		return (hex(int(machineBits,2)), address);
	elif line[0].lower() in special_inst:
		# print '__ACTUAL__ ' + str(line) + ' __ACTUAL__'
		temp = '';
		if len(line) >= 3:
			special_inst_dict = {'br': ['beq', 's0', 's0', line[1]],
								 'not':['nand',line[1],line[2],line[2]],
								 'call': ['jal', 'ra', line[1] ],
								 'ret': ['jal','s3','0(ra)'],
								 'jmp': ['jal','s3','0(a1)']
								 }
			temp, addr =  parseLine(special_inst_dict[line[0].lower()], labels, address)
			return temp, addr
		else:
			return parseLine(['jal','s3','0(ra)'], labels, address)
		
	else:
		return line, address

# Generates last 16-bits for R-type instr (e.g. add, sub, and, or, etc)
def generate_R_TYPE_BITS(line,label,addr):
	additional_bits = ''
	reg_src_1 = '{0:04b}'.format( generateRegAddr( line[2]) );
	reg_src_2 = '{0:04b}'.format( generateRegAddr( line[3]) );
	additional_bits = additional_bits + reg_src_1 + reg_src_2 + '000000000000'
	# print hex(int(additional_bits,2)) + ' - ' + hex(addr) + ' - ' + str(line) 
	return additional_bits

# Generates last 16-bits for I-type instr (e.g. addi, andi, ori, etc)
# Minor bug with regards to handling labels (may have been a bug in there assembler)
def generate_I_TYPE_BITS(line,label,addr):
	print line
	additional_bits = ''; imm_val = ''
	if len(line) >= 4: 
		imm_val = line[3]
	elif len(line) == 3:
		imm_val = line[2]
	if line[0].lower() == 'mvhi':
		# Special Case Implementation for mvhi instr.
		reg_src_1 = '0000'
		imm_val = line[2];
		if imm_val in label: 
			imm_val = label[imm_val];
		else: imm_val = int(imm_val,0)
		imm_val_bits = '{0:016b}'.format( (int( str(imm_val), 0 ) >> 16) & 0xffff )
		additional_bits = additional_bits + reg_src_1 + imm_val_bits
		return additional_bits
	reg_src_1 = '{0:04b}'.format(generateRegAddr( line[2]) );
	if ( is_digit(imm_val) ) or ('0x' in imm_val):
		imm_val_bits = '{0:016b}'.format( int( line[3], 0 ) & 0xffff )
	else:
		# If immediate value is a label
		label_value = label[imm_val]
		imm_val_bits = '{0:016b}'.format( int( str(label_value), 0 ) & 0xffffffffffff )
	additional_bits = additional_bits + reg_src_1 + imm_val_bits
	return additional_bits

# Generates last 16-bits for J-type instructions (e.g jal, bt, any branch instructions)
# Still very buggy with regards to determining pcrel and getting addresses from labels
def generate_J_TYPE_BITS(line,label,addr):
	print line
	additional_bits = ''; dest_value = ''
	special_cases = ['bnez', 'bgtez', 'bgtz']
	if '(' not in line[2]:
		if  line[0].lower() not in special_cases:
			reg_value = '{0:04b}'.format( generateRegAddr( line[2]) );
			dest_value = label[line[3]];
			pc_rel = dest_value - addr - 1;
			imm_val_bits = '{0:016b}'.format( int( str(pc_rel), 0 ) & 0xffff )
		else:
			reg_value = '0000';
			dest_value = label[line[2]]
			pc_rel = dest_value - addr - 1;
			imm_val_bits = '{0:016b}'.format( int( str(pc_rel), 0 ) & 0xffff )
		
		print reg_value
		additional_bits = additional_bits + reg_value + imm_val_bits;
		print pc_rel
		print hex(int(additional_bits,2)) + ' - ' + hex(addr) + '-' + str(line) 
	else:
		reg_addr_bits = ''; imm_val_bits = ''
		reg_label = line[2].split('(')[1].replace(')','')
		imm_val_label = line[2].split('(')[0]
			
		if imm_val_label not in label:
			imm_val_bits = '{0:016b}'.format( int( str(imm_val_label), 0 ) & 0xffff )
		else:
			imm_val_bits = '{0:016b}'.format( int( str(label[imm_val_label]), 0 ) & 0xffff )

		reg_addr = generateRegAddr(reg_label);
		reg_addr_bits = '{0:04b}'.format( int( str(reg_addr), 0 ) & 0xffff )
		additional_bits = additional_bits + reg_addr_bits + imm_val_bits
	 	# print hex(int(additional_bits,2)) + ' - ' + hex(addr) + ' - ' + str(line) 
	return additional_bits

# Generates last 16-bits for M-type instructions (lw, sw, and any instruction manipulating data memory )
def generate_M_TYPE_BITS(line,label,addr):
	additional_bits = ''
	imm_val_bits = ''; reg_label = ''
	mem_addr_operand = line[2]
	tokenized_operand = mem_addr_operand.split('(')
	if line[0].lower() == 'lw':
		print line
		reg_label = tokenized_operand[1].replace(')', '')
	else:
		reg_label = line[1]
	reg_addr_bits = '{0:04b}'.format( int( str(generateRegAddr(reg_label)), 0 ) & 0xffff );
	if tokenized_operand[0] in label:
		imm_val_bits = '{0:016b}'.format( int( label[tokenized_operand[0]], 0 ) & 0xffff );
	else:
		imm_val_bits = '{0:016b}'.format( int( tokenized_operand[0], 0 ) & 0xffff );
	additional_bits = additional_bits + reg_addr_bits + imm_val_bits;
	if line[0].lower() == 'lw':
		print hex(int(additional_bits,2)) + '-' + hex(addr) + ' - ' + str(line) 
	return additional_bits

# Generates register address based off a 
# a string representation of the register input.
def generateRegAddr(reg):
	reg_dict = {'a0': 0, # Register 0
				'a1': 1,
				'a2': 2,
				'a3': 3,
				't0': 4,
				't1': 5,
				's0': 6,
				's1': 7,
				's2': 8,
				's3': 9,
				'gp': 12,
				'fp': 13,
				'sp': 14,
				'ra': 15}
	if reg.lower() in reg_dict:
		return reg_dict[reg.lower()];
	return -1


# Generates the opcode for the given
# instruction. Currently based off of Hadi's ISA. 
def generateOpcode(instr):
	dictionary = {'add': ('0000', '0000'),
				  'sub': ('0000', '0001'),
				  'and': ('0000', '0100'),
				  'or':  ('0000', '0101'),
				  'xor': ('0000', '0110'),
				  'nand':('0000', '1100'),
				  'nor': ('0000', '1101'),
				  'nxor':('0000', '1110'),

				  'addi': ('1000', '0000'),
				  'subi': ('1000', '0001'),
				  'andi': ('1000', '0100'),
				  'ori':  ('1000', '0101'),
				  'xori': ('1000', '0110'),
				  'nandi':('1000', '1100'),
				  'nori': ('1000', '1101'),
				  'nxori':('1000', '1110'),
				  'mvhi': ('1000', '1011'),

				  'lw':   ('1001', '0000'),
				  'sw':   ('0101', '0000'),

				  'f':    ('0010', '0000'),
				  'eq':   ('0010', '0001'),
				  'lt':   ('0010', '0010'),
				  'lte':  ('0010', '0011'),
				  't':    ('0010', '1000'),
				  'ne':   ('0010', '1001'),
				  'gte':  ('0010', '1010'),
				  'gt':   ('0010', '1011'),

				  'fi':   ('1010', '0000'),
				  'eqi':  ('1010', '0001'),
				  'lti':  ('1010', '0010'),
				  'ltei': ('1010', '0011'),
				  'ti':   ('1010', '1000'),
				  'nei':  ('1010', '1001'),
				  'gtei': ('1010', '1010'),
				  'gti':  ('1010', '1011'),

				  'bf':   ('0110', '0000'),
				  'beq':  ('0110', '0001'),
				  'blt':  ('0110', '0010'),
				  'blte': ('0110', '0011'),
				  'beqz': ('0110', '0101'),
				  'bltz': ('0110', '0110'),
				  'bltez':('0110', '0111'),

				  'bt':   ('0110', '1000'),
				  'bne':  ('0110', '1001'),
				  'bgte': ('0110', '1010'),
				  'bgt':  ('0110', '1011'),
				  'bnez': ('0110', '1101'),
				  'bgtez':('0110', '1110'),
				  'bgtz': ('0110', '1111'),

				  'jal':  ('1011', '0000')

				  };
	if instr.lower() in dictionary:
		return dictionary[instr.lower()]
	return ('FFFF', 'FFFF')

# Reads every line in the file and stores 
# each line individually in an array. Removes initial spaces. 
def readfile(fileName):
	linesInFile = []
	pattern = "(\t)+|(\n)+|( )+(\=)*|(\=)+"
	with open(fileName, 'rU') as fp:
		for line in fp:
			if line[0] == '\t':
				linesInFile.append( re.sub(pattern, ",", line[1:] ).split(',') )
			else:
				if line[0] != '\n':
					linesInFile.append( re.sub(pattern, ",", line ).split(',') )
	# print linesInFile
	return linesInFile

# Parses assembly file and gets and assigns values
# to all labels within the file
def getLabels(parsed_code):
	count = 0; label_dict = {}
	special_inst = ['br', 'not','ble','bge','call','ret','jmp']
	lines = parsed_code;
	for line in parsed_code:
		while '' in line: line.remove('')
		if len(line) > 0:
			if '.' in line[0]:
				if line[0] == '.ORIG':
					count = int(line[1], 0) / 4;
					if '.ORIG' not in label_dict:
						label_dict['.ORIG'] = count
					else:
						pass
					continue;
				elif line[0] == '.NAME':
					label_dict[line[1]] = line[2]
			elif ':' in line[0]:
				temp = line[0].replace(':','')
				label_dict[''.join(re.findall('[\w]', temp))] = count

			elif ';' not in line[0]:
				count = count + 1;
	# print label_dict
	return label_dict

def writeToFile(lines, label_dict,outputname):
	addr = label_dict['.ORIG'] - 1;
	depth = 2048;
	with open(outputname, 'w') as new_file:
		header = 'WIDTH=32;\nDEPTH=2048;\nADDRESS_RADIX=HEX;\nDATA_RADIX=HEX;\nCONTENT BEGIN\n'
		if addr != -1:
			initial_nulls = '[' + format(0, '08x') + '..' + format(addr,'08x') + '] : DEAD;\n'
			header = header + initial_nulls
		new_file.write(header)
		for line in lines:
			(machineCode, addr) = parseLine(line, label_dict, addr)
			if len(machineCode) > 0:
				if ';' not in machineCode[0] and ':' not in machineCode[0] and '.' not in machineCode[0] and len(machineCode[0]) > 0:
					# print str(machineCode) + ' - ' + hex(addr) + ' - ' + str(line)
					comment_to_write = '-- ' + ' '.join(line) + '\n'
					line_to_write = format(addr, '08x') + ' : ' + str(machineCode)[2:] + ';\n'
					new_file.write(comment_to_write)
					new_file.write(line_to_write)
		footer = '[' + format(addr+1, '04x') + '..' + format(depth - 1, '04x') + '] : DEAD;\nEND;'
		new_file.write(footer) 
	print 'Success'
	return

def main():
	filename1 = ''; filename2 = '';
	if (len(sys.argv) == 1):
		filename1 = raw_input("Enter raw input file: ")
		outputname = raw_input("Enter raw output file: ")
	elif (len(sys.argv) == 3):
		filename1 = sys.argv[1]
		outputname = sys.argv[2]
	else:
		print "Standard format is"
		print "python assembler.py <inputfile> <outfile.mif>"
		print len(sys.argv)
		return
		
	lines = readfile(filename1);
	label_dict = getLabels(copy.deepcopy(lines))
	writeToFile(lines, label_dict,outputname)

if __name__ == "__main__": main()