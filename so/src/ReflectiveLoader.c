//===============================================================================================//
// Copyright (c) 2016, Infosec Guerilla (infosecguerrilla.wordpress.com)
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
#include "ReflectiveLoader.h"

//===============================================================================================//
//	Debug mode used to test loader capabilities													 //
//===============================================================================================//

#ifdef RSOI_DEBUG_MODE
#define debug(M, ...) { \
printf("DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
}
#else
#define debug(M, ...)
#endif

//===============================================================================================//

#ifdef RSOI_DEBUG_MODE

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("Usage: %s <file path of SO to test loading>\n", argv[0]);
		return -1;
	}

	ReflectiveLoader(argv[1]);
	return 0;
}
#endif

//===============================================================================================//

/*
 * This is a position independent ELF loader which is capable of being used to allow
 * a program to load itself into memory. 
 *
 * More details on the implementation of this loader can be found at the following address
 * https://infosecguerrilla.wordpress.com/2016/07/21/reflective-so-injection/ 
 *
 */
#ifdef RSOI_DEBUG_MODE
int ReflectiveLoader(char *debugFile)
#else
int ReflectiveLoader()
#endif
{	
	ELF_FILE this; /* ELF file we are going to be loading since we are loading ourselves into memory it is this file */
	ELF_FILE libc; /* C library we are using to find dynamic linker functions */

	/* 
	* Functions we need from libc for ELF loading, we resolve these on 
	* the fly by locating LIBC and finding these functions ourselves 
	*/
	int   (*libc_mprotect)(void *addr, size_t len, int prot);
	void* (*libc_calloc)(size_t, size_t size);
	void* (*libc_dlsym)(void *, char *);
	void* (*libc_dlopen)(char *, int mode);
	int   (*libc_dlclose)(void *);
	void*  (*libdl_dlsym)(void *handle, const char *symbol); /* We used dlsym because it is able to handle IFUNC function type something __libc_dlsym cannot for some reason   */
												     /* See this post for more information - https://infosecguerrilla.wordpress.com/2016/07/28/glibc-strange-behavior/ */
	unsigned int index;
	char libdl_s[11];
		 libdl_s[0] = 'l';
		 libdl_s[1] = 'i';
		 libdl_s[2] = 'b';
		 libdl_s[3] = 'd';
		 libdl_s[4] = 'l';
		 libdl_s[5] = '.';
		 libdl_s[6] = 's';
	     libdl_s[7] = 'o';
		 libdl_s[8] = '.';
		 libdl_s[9] = '2';
		 libdl_s[10] = '\0';

	char dlsym_s[6];
		 dlsym_s[0] = 'd';
		 dlsym_s[1] = 'l';
		 dlsym_s[2] = 's';
		 dlsym_s[3] = 'y';
		 dlsym_s[4] = 'm';
		 dlsym_s[5] = '\0';

	//Locate libc in memory
	libc.baseaddr = get_libc_base_addr();
	libc.header = (Elf64_Ehdr *)libc.baseaddr;
	libc.segments = libc.header->e_phoff + libc.baseaddr;
	debug("[+] LIBC base address found at %p", libc.baseaddr);

	//Locate ELF header for this file
	this.header = find_elf_header();
	debug("[+] Found my ELF header at %p", this.header);

#ifdef RSOI_DEBUG_MODE /* Debug mode testing loader capabilities while being able to print debug info */
	this.header = load_file_debug_mode(debugFile);
	debug("[+] Debug header located at %p", this.header);
#endif

	this.segments = this.header->e_phoff + (void *)this.header; /* Program Segments */
	this.sections = this.header->e_shoff + (void *)this.header; /* Program Sections */

	//Find dynamiic program segment for libc
	debug("[i] Looking for dynamic program segment for libc in program headers");
	for(int i = 0; i < libc.header->e_phnum; i++)
	{
		if(libc.segments[i].p_type == PT_DYNAMIC)
		{
			libc.dynamic = libc.segments[i].p_vaddr + libc.baseaddr;
			debug("[+] LIBC PT_DYNAMIC segment at address %p", libc.dynamic);
		}

	}

	//Find .dynsym table for libc
	debug("[i] Looking for dynsym program segment for libc in dynamic segment");
	for(int i = 0; libc.dynamic[i].d_tag != DT_NULL; i++)
	{
		if(libc.dynamic[i].d_tag == DT_SYMTAB)
		{
			libc.dynsym = (Elf64_Sym *)libc.dynamic[i].d_un.d_val;
			debug("[+] LIBC dynsym found at address %p", libc.dynsym);
			break;
		}
	}
	
	//find .dynstr table for libc
	for(int i = 0; libc.dynamic[i].d_tag != DT_NULL; i++)
	{
		if(libc.dynamic[i].d_tag == DT_STRTAB)
		{
			libc.dynstr = (char *)(libc.dynamic[i].d_un.d_val);
			debug("[+] LIBC dynstr found at address %p", libc.dynstr);
			break;			
		}
	}

	//find .gnu.hash section 
	for(int i = 0; libc.dynamic[i].d_tag != DT_NULL; i++)
	{
		if(libc.dynamic[i].d_tag == DT_GNU_HASH)
		{
			libc.gnu_hash = (char *)(libc.dynamic[i].d_un.d_val);
			debug("[+] LIBC gnu_hash found at address %p", libc.gnu_hash);
			break;			
		}
	}

	if(libc.gnu_hash == NULL)
	{
		debug("[-] Could not find GNU_HASH entry in dynamic segment");
		return -1;	
	}


	debug("[i] Resolving addresses of runtime dependencies");

	//Resolve functions needed to run
	unsigned int count = 0;
	for(int i = 0; ;i++) /* You can also calculate the number of dynsym entries by looking in HASH or GNU_HASH tables */
	{
		if(hash(libc.dynsym[i].st_name + libc.dynstr) == DLOPEN_HASH)
		{
			libc_dlopen = libc.dynsym[i].st_value + libc.baseaddr;
			debug("[+] Found dlopen at %p", libc_dlopen);
			count++;
		}
		if(hash(libc.dynsym[i].st_name + libc.dynstr) == DLCLOSE_HASH)
		{		
			libc_dlclose = libc.dynsym[i].st_value + libc.baseaddr;
			debug("[+] Found dlclose at %p", libc_dlclose);
			count++;
		}	
		if(hash(libc.dynsym[i].st_name + libc.dynstr) == DLSYM_HASH)
		{		
			libc_dlsym = libc.dynsym[i].st_value + libc.baseaddr;
			debug("[+] Found dlsym at %p", libc_dlsym);
			count++;
		}		
		if(hash(libc.dynsym[i].st_name + libc.dynstr) == CALLOC_HASH)
		{		
			libc_calloc = libc.dynsym[i].st_value + libc.baseaddr;
			debug("[+] Found calloc at %p", libc_calloc);
			count++;
		}		
		if(hash(libc.dynsym[i].st_name + libc.dynstr) == MPROTECT_HASH)
		{	
			libc_mprotect = libc.dynsym[i].st_value + libc.baseaddr;
			debug("[+] Found mprotect at %p", libc_mprotect);
			count++;
		}	
		if(count == 5)
		{
			break;
		}
	}

	/* Find dlsym using __libc_dlsym - https://infosecguerrilla.wordpress.com/2016/07/28/glibc-strange-behavior/ */

	void *libdlhandle = (*libc_dlopen)(libdl_s, RTLD_LAZY);
	debug("[+] Opened libdl with handle libdlhandle=%p", libdlhandle);
	libdl_dlsym = (*libc_dlsym)(libdlhandle, dlsym_s);
	debug("[+] Found libdl_dlsym at %p", libdl_dlsym);

	debug("[i] Finished resolving addresses of runtime dependencies");
	debug("[i] Allocating RWX memory to load shared object into and calculating program size");

	//Calculate program base address aligned to page size (0x1000 bytes)
	unsigned int size;
	size = get_program_memory_size(this.header);
	
	debug("[i] Program size is %u", size);
	//Allocate this memory
	this.baseaddr = (*libc_calloc)(1, size);
	
	if(this.baseaddr == NULL)
	{
		debug("[-] ERROR libc_calloc failed");
		return -1;
	}

	//Round process base address to page size
	this.baseaddr += (unsigned long)(0x1000 - ((unsigned long)this.baseaddr & 0x00000FFF));

	if((*libc_mprotect)(this.baseaddr, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
	{	
		debug("[-] ERROR mprotect call to create RWX memory region failed and returned with error");
		return -1;
	}

	debug("[+] Shared object baseaddr at %p", this.baseaddr);

	//Map program segments into memory 
	for(int i = 0; i < this.header->e_phnum; i++)
	{
		//Copy loadable segments into memory
		if(this.segments[i].p_type == PT_LOAD)
		{
			debug("[+] PT_LOAD Segment loaded at %p", this.segments[i].p_vaddr + this.baseaddr);
			crt_memcpy(this.baseaddr + this.segments[i].p_vaddr, (void *)this.header + this.segments[i].p_offset, this.segments[i].p_filesz);
		}

	}

	//Find SH_STRTAB
	this.SH_STRTAB = (void *)this.header + this.sections[this.header->e_shstrndx].sh_offset;

	//find this files .dynamic section
	index = find_section_by_hash(DYNAMIC_HASH, this.sections, this.SH_STRTAB, this.header->e_shnum);
	this.secdynamic = (Elf64_Shdr *)&this.sections[index];
	this.dynamic = this.secdynamic->sh_addr + this.baseaddr;

	//find this files .dynstr
	index = find_section_by_hash(DYNSTR_HASH, this.sections, this.SH_STRTAB, this.header->e_shnum);
	this.secdynstr = (Elf64_Shdr *)&this.sections[index];
	this.dynstr = this.secdynstr->sh_addr + this.baseaddr;

	//find this files .rela.plt section
	index = find_section_by_hash(RELAPLT_HASH, this.sections, this.SH_STRTAB, this.header->e_shnum);
	this.secrelaplt = (Elf64_Shdr *)&this.sections[index];
	this.relaplt = this.secrelaplt->sh_addr + this.baseaddr;

	//find this files .rela.dyn section
	index = find_section_by_hash(RELADYN_HASH, this.sections, this.SH_STRTAB, this.header->e_shnum);
	this.secreladyn = (Elf64_Shdr *)&this.sections[index];
	this.reladyn = this.secreladyn->sh_addr + this.baseaddr;

	//find this files dynsym section
	index = find_section_by_hash(DYNSYM_HASH, this.sections, this.SH_STRTAB, this.header->e_shnum);
	this.secdynsym = (Elf64_Shdr *)&this.sections[index];
	this.dynsym = this.secdynsym->sh_addr + this.baseaddr;


	//dlopen DT_NEEDED libraries
	unsigned int numNeededLibraries = 0;
	void* *libHandles = NULL;
	unsigned int z = 0;

	//Count number of DT_NEEDED entries
	for(int i = 0; this.dynamic[i].d_tag != DT_NULL; i++)
	{
		if(this.dynamic[i].d_tag == DT_NEEDED)
		{
			numNeededLibraries++;
		}
	}

	libHandles = (*libc_calloc)(sizeof(void *), numNeededLibraries);

	if(libHandles == NULL)
	{
		debug("[-] Memory allocation failed..");
		return -1;
	}

	//Open all libraries required by the shared object in order to execute
	for(int i = 0; this.dynamic[i].d_tag != DT_NULL && z < numNeededLibraries; i++)
	{
		if(this.dynamic[i].d_tag == DT_NEEDED)
		{
			debug("[i] Opening DT_NEEEDED library [%s]", this.dynamic[i].d_un.d_ptr + this.dynstr);
			libHandles[z] = (*libc_dlopen)(this.dynamic[i].d_un.d_ptr + this.dynstr, RTLD_LAZY);

			if(!libHandles[z])
			{
				return -1;
			}

			z++;
		}
	}

	//Resolve PLT references
	for(int i = 0; i < this.secrelaplt->sh_size / sizeof(Elf64_Rela); i++)
	{
		if(ELF64_R_TYPE(this.relaplt[i].r_info) == R_X86_64_JUMP_SLOT)
		{
			void *funcaddr;
			char *symName;

			//Get Index into symbol table for relocation
			index = ELF64_R_SYM(this.relaplt[i].r_info);

			symName = this.dynsym[index].st_name + this.dynstr;

			//If symbol is a local symbol write the address of it into the .got.plt
			if(ELF64_ST_TYPE(this.dynsym[index].st_info) == STT_FUNC && this.dynsym[index].st_shndx != SHN_UNDEF)
			{
				debug("[i] Symbol type is STT_FUNC AND st_shndx IS NOT STD_UNDEF for %s", symName);
				*((unsigned long *)(this.relaplt[i].r_offset + this.baseaddr)) = (unsigned long *)(this.dynsym[index].st_value + this.baseaddr);
			}

			//We need to lookup the symbol searching through DT_NEEDED libraries
			else 
			{
				for(int x = 0; x < numNeededLibraries; x++)
				{
					funcaddr = (*libdl_dlsym)(libHandles[x], symName);
					debug("[i] Looking up symbol for %s function address is %p", symName, funcaddr);
					if(funcaddr != NULL)
					{
						*((unsigned long *)(this.relaplt[i].r_offset + this.baseaddr)) = (unsigned long )((unsigned long)funcaddr);
						break;
					}									
				}
			}	
		}
	}

	//Perform relocations (.rela.dyn)
	for(int i = 0; i < this.secreladyn->sh_size / sizeof(Elf64_Rela); i++)
	{
		if(ELF64_R_TYPE(this.reladyn[i].r_info) == R_X86_64_64)
		{
			debug("[i] Processing Relocation of type R_86_64_64");			
			index = ELF64_R_SYM(this.reladyn[i].r_info);
			*((uint64_t *) (this.reladyn[i].r_offset + this.baseaddr)) = this.dynsym[index].st_value + this.reladyn[i].r_addend;
		}	
		/*
		 * Lookup address of symbol and store it in GOT entry
		 */
		else if(ELF64_R_TYPE(this.reladyn[i].r_info) == R_X86_64_GLOB_DAT)
		{
			debug("[i] Processing Relocation of type R_x86_64_GLOB_DAT %s", this.dynsym[ELF64_R_SYM(this.reladyn[i].r_info)].st_name + this.dynstr);

			//Check symbol both locally and globally (searching through DT_NEEDED entries) 
			for(int x = 0; ;x++)
			{
				if(hash(this.dynsym[x].st_name + this.dynstr) == hash(this.dynsym[ELF64_R_SYM(this.reladyn[i].r_info)].st_name + this.dynstr))
				{
					//If symbol is a local symbol write the address of it into the .got.plt
					if(this.dynsym[x].st_shndx == SHN_UNDEF)
					{						
						for(int y = 0; y < numNeededLibraries; y++)
						{
	
							void *faddr = libdl_dlsym(libHandles[y], this.dynsym[x].st_name + this.dynstr);
							debug("[i] Looking up symbol for %s function address is %p", this.dynsym[x].st_name + this.dynstr, faddr);
							if(faddr != NULL)
							{
								*((uint64_t *) (this.reladyn[i].r_offset + this.baseaddr))  = (unsigned long )((unsigned long)faddr);
								break;
							}									
						}		
						break;				
					}
				
					//write value into got entry
					*((uint64_t *)(this.reladyn[i].r_offset + this.baseaddr)) = this.dynsym[x].st_value + this.baseaddr;
					break;
				}
			}
		}
		else if(ELF64_R_TYPE(this.reladyn[i].r_info) == R_X86_64_RELATIVE)
		{
			debug("[i] Processing Relocation of type R_x86_64_RELATIVE %s", this.dynsym[ELF64_R_SYM(this.reladyn[i].r_info)].st_name + this.dynstr);
			index = ELF64_R_SYM(this.reladyn[i].r_info);
			*((uint64_t *)((unsigned long)this.reladyn[i].r_offset + (unsigned long)this.baseaddr)) = this.reladyn[i].r_addend + this.baseaddr;
		}
	}

	//Close Opened Libraries
	for(int i = 0; i < numNeededLibraries; i++)
	{
		libc_dlclose(libHandles[i]);
	}
	
	libc_dlclose(libdlhandle);

	//Call constructors of shared object
	debug("[i] Calling shared object constructors");	
	call_program_constructors(this); 

	return 1;
}

//===============================================================================================//
// Reflective ELF Loader Functions
//===============================================================================================//


/*
 * Parse backwards in memory in order to locate the ELF Header of our injected file
 */
__attribute__((always_inline)) inline Elf64_Ehdr* 
find_elf_header() 
{

	unsigned char *IP;

	__asm__("leaq (%%rip), %0;": "=r"(IP));

	//Locate the ELF Header for this file
	while(1 == 1)
	{
		if(check_elf_magic((Elf64_Ehdr *)IP))
		{
			break;
		}	
		IP--;
	}

	return (Elf64_Ehdr*)IP;
}

/*
 * Get the base address of libc by parsing /proc/self/maps (without a C library it is so annoying!)
 */
__attribute__((always_inline)) inline void* 
get_libc_base_addr() 
{

	MAPS_FILE maps;
	int fd;
	struct stat sb;
	MAPS_ENTRY e;
 
	/* Done this way to ensure relocations are not required 
	 * compiler generates a sequence of move instructions writing
	 * the string onto the stack. */

	char mapspath[16];	
	mapspath[0]  =  '/';   
	mapspath[1]  =  'p';   
	mapspath[2]  =  'r';
	mapspath[3]  =  'o';
	mapspath[4]  =  'c';
	mapspath[5]  =  '/';
	mapspath[6]  =  's';
	mapspath[7]  =  'e';
	mapspath[8]  =  'l';
	mapspath[9]  =  'f';
	mapspath[10] =  '/';
	mapspath[11] =  'm';
	mapspath[12] =  'a';
 	mapspath[13] =  'p';
	mapspath[14] =  's';
	mapspath[15] =  '\0'; 

	char libc[6];
	libc[0] = 'l';
	libc[1] = 'i';
	libc[2] = 'b';
	libc[3] = 'c';
	libc[4] = '-';
	libc[5] = '\0'; 	

	char perms[5]; 
	perms[0] = 'r';
	perms[1] = '-';
	perms[2] = 'x';
	perms[3] = 'p';
	perms[4] = '\0';

	maps.maps = crt_mmap(NULL, 0x1000 * 200, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	fd = crt_open("/proc/self/maps", 0, 0);
	maps.size = copy_in(fd, maps.maps);
	maps.pos = maps.maps;

	do
	{
		e = get_next_maps_entry(&maps);
	
		if(e.name == NULL) /* Entry does not have a name */		
			continue;

		if(crt_strcmp(e.name, &libc) > 0)
		{
			if(crt_strcmp(e.perms, &perms) > 0)
				return e.startaddr;
		}

	} while(e.startaddr != NULL);
	
	crt_munmap(maps.maps, 0x1000 * 200); //unmap maps file from memory
	crt_close(fd);
}

/*
 * Get the next maps entry in the file
 */
__attribute__((always_inline)) inline MAPS_ENTRY 
get_next_maps_entry(MAPS_FILE *maps)
{
	MAPS_ENTRY entry;
	int valid = 0;
	char *pos = maps->pos;
	char *temp;

	//Check if we have gotten to the end of the maps file
	if(*pos >= (maps->maps + maps->size)) 
		return entry;

	//Get start address
	temp = pos;
	while(*pos != '-') 
	{ 
		pos++; 
	} 
	*pos = '\0'; 
	pos++;
	entry.startaddr = convert_string_to_64bit_pointer(temp);
		

	//Get end address of memory region
	temp = pos;
	while(*pos != ' ') 
	{ 
		pos++; 
	}
	*pos = '\0'; 
	pos++;	
	entry.endaddr = convert_string_to_64bit_pointer(temp);
	
	//Get permissions
	entry.perms = pos;
		
	//Get name of memory region if it is a shared library name	
	while(*pos != '\n') { if(*pos == '/') { valid = 1; } pos++; } /* Skip over junk data */
	*pos = '\0';
	temp = pos;
	while(*pos != '/' && valid) { pos--; } pos++; /* Get name of shared object if a valid entry */
	entry.name = pos; /* Save this name */
	if(!valid) { entry.name = NULL; }
	pos = temp;

	pos++; //Skip to beginning of next entry
	maps->pos = pos; //Save this position
	return entry;
}

/*
 * Get the amount of memory which needs to be allocated in order to map our program into memory
 * plus some additional padding. 
 */
__attribute__((always_inline)) inline unsigned int
get_program_memory_size(Elf64_Ehdr *header) 
{

	unsigned int size = 0, numPages; 
	Elf64_Phdr *segments = header->e_phoff + (void *)header;

	for(int i = 0; i < header->e_phnum; i++)
	{
		if(segments[i].p_type == PT_LOAD)
		{
			if(segments[i].p_memsz > segments[i].p_align)
			{
				numPages = 1 + (segments[i].p_memsz - segments[i].p_memsz % segments[i].p_align) / segments[i].p_align;
			}			
			else
			{
				numPages = 1;
			}				
		
			size += segments[i].p_align * numPages;
		}
	}
	size += 0x2000; //padding
	return size;
}

__attribute__((always_inline)) void inline
call_program_constructors(ELF_FILE e) 
{

	int INIT_ARRAYSZ = 0;
	void* *INIT_ARRAY;
	void (*constructor)();

	//find DT_INIT_ARRAYSZ
	for(int i = 0; e.dynamic[i].d_tag != DT_NULL; i++)
	{
		if(e.dynamic[i].d_tag == DT_INIT_ARRAYSZ)
		{
			INIT_ARRAYSZ = e.dynamic[i].d_un.d_ptr;	
			break;		
		}
	}
	
	//find DT_INIT_ARRAY
	for(int i = 0; e.dynamic[i].d_tag != DT_NULL; i++)
	{
		if(e.dynamic[i].d_tag == DT_INIT_ARRAY)
		{
			INIT_ARRAY = e.dynamic[i].d_un.d_ptr + e.baseaddr;
			break;			
		}
	}

	//Call constructors in shared object
	for(int i = 1; i < INIT_ARRAYSZ; i++)
	{
		constructor = (uint64_t)INIT_ARRAY[i] + (uint64_t)e.baseaddr;
		
		if(INIT_ARRAY[i] == 0)
			break;

		debug("[i] Calling constructor %p", constructor);
		constructor();
	}
}

/* check elf header */
__attribute__((always_inline)) inline unsigned int
check_elf_magic(Elf64_Ehdr *elfHdr)
{
	if(elfHdr->e_ident[0] == 0x7f)
	{
		if(elfHdr->e_ident[1] == 0x45)
		{
			if(elfHdr->e_ident[2] == 0x4c)
			{
				if(elfHdr->e_ident[3] == 0x46)
				{
					return 1;
				}
			}
		}
	}

	return 0;
}

/* Find elf section given a name and hash */
__attribute__((always_inline)) inline unsigned int
find_section_by_hash(unsigned int sectionHash, Elf64_Shdr *sections, unsigned char *SH_STRTAB, unsigned int numSections)
{
	for(int i = 0; i < numSections; i++)
	{
		unsigned char *sectionName = SH_STRTAB + sections[i].sh_name;

		if(hash(sectionName) == sectionHash)
		{
			return i;
		}
	}

	debug("[i] ERROR could not find section");
	exit(-1);
}

//===============================================================================================//
// Standard Library Functions (x86_64)
//===============================================================================================//

__attribute__((always_inline)) inline int
crt_close(int fd)
{

	long ret;
	asm volatile ("syscall" : "=a" (ret) : "a" (__NR_close),
		      "D" (fd):
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
	if (ret < 0)
	{
		ret = -1;
	}
	return (int)ret;
}

__attribute__((always_inline)) inline int 
crt_open (const char *pathname, unsigned long flags, unsigned long mode)
{

	long ret;
	__asm__ volatile ("syscall" : "=a" (ret) : "a" (__NR_open),
		      "D" (pathname), "S" (flags), "d" (mode) :
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );

	return (int) ret;
}

__attribute__((always_inline)) inline void*
crt_mmap(void *start, unsigned long length, int prot, int flags, int fd, unsigned long offset)
{
	void *ret;
	register long r10 asm("r10") = flags;
	register long r9 asm("r9") = offset;
	register long r8 asm("r8") = fd;

	__asm__ volatile ("syscall" : "=a" (ret) : "a" (__NR_mmap),
		      "D" (start), "S" (length), "d" (prot), "r" (r8), "r" (r9), "r" (r10) : 
		      "cc", "memory", "rcx", "r11");

	return ret;
}

__attribute__((always_inline)) inline int
crt_munmap(void *start, unsigned long length)
{

	long ret;
	asm volatile ("syscall" : "=a" (ret) : "a" (__NR_munmap),
		      "D" (start), "S" (length) :
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
	if (ret < 0)
	{
		ret = -1;
	}
	return (int)ret;
}

__attribute__((always_inline)) inline int
crt_read(int fd, char *buffer, unsigned long bufferlen)
{

	long ret;
	__asm__ volatile ("syscall" : "=a" (ret) : "a" (__NR_read),
		      "D" (fd), "S" (buffer), "d" (bufferlen) :
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
	if (ret < 0)
	{
		ret = -1;
	}
	return (int)ret;
}

__attribute__((always_inline)) inline int
crt_stat(const char *path, void *buf)
{
	long ret;
	asm volatile ("syscall" :
		"=a" (ret) :
		"a" (4), "D" (path), "S" (buf) :
		"memory"
	);
	if (ret < 0)
	{
		ret = -1;
	}
	return (int)ret;
}

//===============================================================================================//
// Standard Library Functions (portable)
//===============================================================================================//

__attribute__((always_inline)) inline void *
crt_memcpy(void *dest, const void *src, unsigned long n)
{
	unsigned long i;
	unsigned char *d = (unsigned char *)dest;
	unsigned char *s = (unsigned char *)src;

	for (i = 0; i < n; ++i)
		d[i] = s[i];

	return dest;
}

__attribute__((always_inline)) inline int 
crt_strcmp(char *s1, char *s2) 
{
	int len1 = crt_strlen(s1);
	int len2 = crt_strlen(s2);
	int len = 0;
	
	if(len1 > len2)
		len = len2;
	else
		len = len1;

	for(int i = 0; i < len; i++)
	{
		if(*(s1 + i) != *(s2 + i))
		{

			return -1;
		}	
	}

	return 1;
}

__attribute__((always_inline)) inline unsigned long
crt_strlen(const char *s)
{
	unsigned long r = 0;
	for (; s && *s; ++s, ++r);
	return r;
}

/*
 * String hashing function used for string comparison
 */
__attribute__((always_inline)) inline unsigned int
hash(unsigned char *word)
{
    unsigned int hash = 0;
    for (int i = 0 ; word[i] != '\0' && word[i] != '@'; i++)
    {
        hash = 31 * hash + word[i];
    }
    return hash;
}

//===============================================================================================//
// Utility Functions
//===============================================================================================//

/*
 * Custom function to convert string to a pointer subtracts an amount to get the actual character 
 * value and then accounts for the position in the number using multiplcation to place it in
 * its correct position. 
 */
__attribute__((always_inline)) inline uint64_t 
convert_string_to_64bit_pointer(unsigned char *x)
{
	uint64_t pointer = 0;
	uint64_t z = 1;
	uint64_t temp = 0;
	unsigned int len = crt_strlen(x);

	for(int i = 0; i < len; i++)
		z *= 16;

	for(int i = 0; i < len; i++)
	{
		if(*x > 60)
		{
			temp = *x - 87;
		}
		else
		{
			temp = *x - 48;
		}


		if(z == 1)
		{
			temp = temp;
		}
		else 
		{
			z = z / 16;
			temp = temp * z;
		}

		pointer += temp;
		temp = 0;
		x++;
	}

	return pointer;
}

/*
 * Copy a file from disk into a memory buffer. WARNING Does not check size!
 */
__attribute__((always_inline)) inline unsigned int 
copy_in(int fd, void *address)
{
	int cc;
	off_t offset = 0;
	char buf[1024];

	while (0 < (cc = crt_read(fd, buf, sizeof(buf))))
	{
		crt_memcpy((address + offset), buf, cc);
		offset += cc;
	}

	return offset;
}

//===============================================================================================//
// Debug Mode Functions
//===============================================================================================//

#ifdef RSOI_DEBUG_MODE

/*
 * Used to test loading capabilities separately from the injection capabilities. We can
 * use this to figure out whether we are dealing with a problem with our ELF loader or with 
 * the injection script which is used to inject our loader into the target process. 
 */
Elf64_Ehdr* load_file_debug_mode(char *debugfile) 
{

	struct stat sb;
	unsigned int fd;
	fd = crt_open(debugfile,  0, 0);
	if(fd == -1)
	{
		debug("[-] Could not open debug file");
		exit(-1);
	}

	if (0 > crt_stat(debugfile, &sb))
	{
		return;
	}

	void *mapped = crt_mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	if(mapped == -1)
	{
		return;
	}

	copy_in(fd, mapped);
	crt_close(fd);

	if(check_elf_magic(mapped))
	{
		debug("[+] Debug File ELF Header is valid");
	}
	else
	{
		debug("[-] Debug File ELF Header is invalid ERROR!");
		exit(-1);
	}

	return (Elf64_Ehdr *)mapped;
}

#endif
