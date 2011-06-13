/*
 * Code to test the 68K disassembler used by GDB. This should be extended
 * to cover a large subset of 68000 machine code and run as part of the
 * patch & build process to make sure the switch to Motorola syntax for
 * the disassembly hasn't broken anything.
 * 
 * Copyright (C) 2011 Chris McClelland
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dis-asm.h>
#include <stdarg.h>

typedef unsigned char      uint8;
typedef unsigned short     uint16;
typedef unsigned long      uint32;

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

extern const bfd_arch_info_type bfd_m68k_arch;
static char disassembly[1024];
static const uint8 *insBase;

uint8 *readFile(const char *name, uint32 *length);

static void print_address(bfd_vma addr, struct disassemble_info *info) {
	(*info->fprintf_func)(info->stream, "0x%X", addr);
}

static int read_memory(
	bfd_vma memaddr, uint8 *myaddr, unsigned int len, struct disassemble_info *UNUSED(info))
{
	memcpy(myaddr, insBase + memaddr, len);
	return 0;
}

static int fprintf_disasm(void *stream, const char *format, ...) {
	va_list args;
	char chunk[1024];
	va_start(args, format);
	vsprintf(chunk, format, args);
	va_end(args);
	strcat((char*)stream, chunk);
	/* Something non -ve.  */
	return 0;
}


#define VERIFY1(e, o) if ( verify1(&di, e, o) ) { expected = e; goto fail; }
int verify1(struct disassemble_info *di, const char *ex, uint16 opcode) {
	int bytesEaten;
	uint8 insn[16];
	insn[0] = opcode >> 8;
	insn[1] = opcode & 0x00FF;
	*disassembly = '\0';
	insBase = insn;
	bytesEaten = print_insn_m68k(0x000000, di);
	if ( !strcmp(ex, disassembly) && bytesEaten == 2 ) {
		return 0;
	} else {
		return -1;
	}
}
#define VERIFY2(e, o, p0) if ( verify2(&di, e, o, p0) ) { expected = e; goto fail; }
int verify2(struct disassemble_info *di, const char *ex, uint16 opcode, uint16 param0) {
	int bytesEaten;
	uint8 insn[16];
	insn[0] = opcode >> 8;
	insn[1] = opcode & 0x00FF;
	insn[2] = param0 >> 8;
	insn[3] = param0 & 0x00FF;
	*disassembly = '\0';
	insBase = insn;
	bytesEaten = print_insn_m68k(0x000000, di);
	if ( !strcmp(ex, disassembly) && bytesEaten == 4 ) {
		return 0;
	} else {
		return -1;
	}
}

void init(struct disassemble_info *di) {
	init_disassemble_info(di, disassembly, (fprintf_ftype)fprintf_disasm);
	di->flavour = bfd_target_unknown_flavour;
	di->memory_error_func = NULL;
	di->print_address_func = print_address;
	di->read_memory_func = read_memory;
	di->arch = bfd_m68k_arch.arch;
	di->mach = bfd_m68k_arch.mach;
	di->endian = BFD_ENDIAN_BIG;
	di->endian_code = BFD_ENDIAN_BIG;
	di->application_data = NULL;
	disassemble_init_for_target(di);
}

uint32 disassemble(struct disassemble_info *di, const uint8 *baseAddress, uint32 offset) {
	*disassembly = '\0';
	insBase = baseAddress;
	return print_insn_m68k(offset, di);
}

int main(int argc, const char *argv[]) {
	struct disassemble_info di;
	const uint8 *rom;
	uint32 romLength;
	uint32 address;
	uint32 numLines;
	uint32 bytesEaten;
	init(&di);
	if ( argc != 4 ) {
		fprintf(stderr, "Synopsis: %s <file> <address> <numLines>\n", argv[0]);
		exit(1);
	}
	rom = readFile(argv[1], &romLength);
	if ( !rom ) {
		fprintf(stderr, "File not found\n");
		exit(1);
	}
	address = strtoul(argv[2], NULL, 0);
	if ( !address ) {
		fprintf(stderr, "Address \"%s\" cannot be parsed\n", argv[2]);
		exit(1);
	}
	numLines = strtoul(argv[3], NULL, 0);
	if ( !numLines ) {
		fprintf(stderr, "NumLines \"%s\" cannot be parsed\n", argv[3]);
		exit(1);
	}
	while ( numLines-- ) {
		bytesEaten = disassemble(&di, rom, address);
		printf("0x%06lX  %s\n", address, disassembly);
		address += bytesEaten;
	}
	free((void*)rom);
	return 0;
}

int main2(void) {
	struct disassemble_info di;
	const char *expected;
	init(&di);

	VERIFY1("rts", 0x4E75);
	VERIFY1("moveq #-1, d0", 0x70FF);
	VERIFY2("move.w 126(a5, d1.w), d0", 0x3035, 0x107E);
	VERIFY2("move.w 126(a5), d0", 0x302D, 0x007E);
	VERIFY2("move.w 0x00001A(pc, d1.w), d0", 0x303B, 0x1018);
	return 0;
fail:
	fprintf(stderr, "Expected \"%s\", got \"%s\"\n", expected, disassembly);
	return -1;
}

/*
 * Allocate a buffer big enough to fit file into, then read the file into it,
 * then write the file length to the location pointed to by 'length'. Naturally,
 * responsibility for the allocated buffer passes to the caller.
 */
uint8 *readFile(const char *name, uint32 *length) {
	FILE *file;
	uint8 *buffer;
	uint32 fileLen;
	uint32 returnCode;

	file = fopen(name, "rb");
	if ( !file ) {
		return NULL;
	}
	
	fseek(file, 0, SEEK_END);
	fileLen = ftell(file);
	fseek(file, 0, SEEK_SET);

	// Allocate enough space for an extra byte just in case the file size is odd
	buffer = (uint8 *)malloc(fileLen + 1);
	if ( !buffer ) {
		fclose(file);
		return NULL;
	}
	returnCode = fread(buffer, 1, fileLen, file);
	if ( returnCode == fileLen ) {
		if ( fileLen & 1 ) {
			fileLen++;
		}
		*length = fileLen;
	}
	fclose(file);
	return buffer;
}
