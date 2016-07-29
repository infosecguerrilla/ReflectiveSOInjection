//===============================================================================================//
// Copyright (c) 2016, Infosec Guerilla (infosecguerilla.wordpress.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#ifndef _REFLECTIVESOINJECTION_REFLECTIVELOADER_H
#define _REFLECTIVESOINJECTION_REFLECTIVELOADER_H
//===============================================================================================//

#include <dlfcn.h>
#include <elf.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

//===============================================================================================//

#define DYNSYM_HASH   0x32E01F5C
#define DYNSTR_HASH   0x32e01ec6
#define RELAPLT_HASH  0x83203420
#define RELADYN_HASH  0x832008A1
#define DYNAMIC_HASH  0x291B7051
#define CALLOC_HASH   0xAE7968B2
#define MPROTECT_HASH 0x2874F1C2

#define DLOPEN_HASH   0x08AD428F
#define DLCLOSE_HASH  0x73B0998F
#define DLSYM_HASH    0xDBE4741E

//===============================================================================================//

typedef struct {
	unsigned char *maps;
	unsigned char *pos;
	unsigned int size;
} MAPS_FILE; 

typedef struct {
	void *startaddr;
	void *endaddr;
	char *perms;
	char *name;
} MAPS_ENTRY;

typedef struct { 
/* ELF Header and Baseaddr */
	Elf64_Ehdr *header;
	void *baseaddr;

/* ELF Section Headers */
	Elf64_Shdr *secdynsym;
	Elf64_Shdr *secdynamic;
	Elf64_Shdr *secrelaplt;
	Elf64_Shdr *secreladyn;
	Elf64_Shdr *secdynstr;	
	Elf64_Shdr *sections;
	Elf64_Phdr *segments;

/* ELF Sections */
	Elf64_Dyn *dynamic;
	Elf64_Sym *dynsym;
	char *dynstr;
	char *SH_STRTAB;
	void *gnu_hash;
	Elf64_Rela *relaplt;
	Elf64_Rela *reladyn;

/* Counters of "things" */
	unsigned int dynsymcount;
} ELF_FILE;

//===============================================================================================//

#ifdef RSOI_DEBUG_MODE
int ReflectiveLoader(char *debugFile);
Elf64_Ehdr* load_file_debug_mode(char *debugfile);
#else
int ReflectiveLoader();
#endif

__attribute__((always_inline)) inline void* get_libc_base_addr();
__attribute__((always_inline)) inline MAPS_ENTRY get_next_maps_entry(MAPS_FILE *maps);

__attribute__((always_inline)) inline unsigned int get_num_dynsym_entries(ELF_FILE *e);

__attribute__((always_inline)) inline uint64_t convert_string_to_64bit_pointer(unsigned char *x);
__attribute__((always_inline)) inline unsigned int copy_in(int fd, void *address);
__attribute__((always_inline)) unsigned int get_program_memory_size(Elf64_Ehdr *header);

__attribute__((always_inline)) unsigned int check_elf_magic(Elf64_Ehdr *elfHdr);
__attribute__((always_inline)) Elf64_Ehdr* find_elf_header();
__attribute__((always_inline)) void call_program_constructors(ELF_FILE e);

__attribute__((always_inline)) inline void* crt_mmap(void *start, unsigned long length, int prot, int flags, int fd, unsigned long offset);
__attribute__((always_inline)) inline int crt_close(int fd);
__attribute__((always_inline)) inline int crt_munmap(void *start, unsigned long length);
__attribute__((always_inline)) inline void *crt_memcpy(void *dest, const void *src, unsigned long n);
__attribute__((always_inline)) inline int crt_read(int fd, char *buffer, unsigned long bufferlen);
__attribute__((always_inline)) inline int crt_stat(const char *path, void *buf);
__attribute__((always_inline)) inline unsigned long crt_strlen(const char *s);

__attribute__((always_inline)) inline unsigned int hash(unsigned char *word);
__attribute__((always_inline)) inline unsigned int find_section_by_hash(unsigned int sectionHash, Elf64_Shdr *sections, unsigned char *SH_STRTAB, unsigned int numSections);

//===============================================================================================//
#endif
//===============================================================================================//
