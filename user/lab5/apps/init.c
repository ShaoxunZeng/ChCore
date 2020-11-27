#include <print.h>
#include <syscall.h>
#include <launcher.h>
#include <defs.h>
#include <bug.h>
#include <fs_defs.h>
#include <ipc.h>
#include <string.h>
#include <proc.h>

#define SERVER_READY_FLAG(vaddr) (*(int *)(vaddr))
#define SERVER_EXIT_FLAG(vaddr)  (*(int *)((u64)vaddr+ 4))

extern ipc_struct_t *tmpfs_ipc_struct;
static ipc_struct_t ipc_struct;
static int tmpfs_scan_pmo_cap;
static int tmpfs_read_pmo_cap;

/* fs_server_cap in current process; can be copied to others */
int fs_server_cap;

#define BUFLEN	4096

static char *current_dir[BUFLEN];

static int is_begin_with(char *src, char *suffix){
	if(strlen(suffix) > strlen(src))
		return 0;
	for(int i = 0; i < strlen(suffix); i++){
		if(src[i] != suffix[i])
			return 0;
	}
	return 1;
}

static int do_complement(char *buf, char *complement, int complement_time)
{
#ifdef LOG	
	printf("[Debug] do_complement buf: %s\n", buf);
	printf("[Debug] do_complement complement: %s\n", complement);
	printf("[Debug] do_complement complement_time: %d\n", complement_time);
#endif	
	// TODO: your code here
	int last_slash = -1;
	int path_start = strlen(complement) - 1;
	while(path_start != 0 && complement[path_start] != ' '){
		if(complement[path_start] == '/' && last_slash == -1)
			last_slash = path_start;
		path_start--;
	}
	if(complement[path_start] == ' '){
		path_start++;
	}
	if(last_slash == -1){
		last_slash = path_start - 1;
	}
	
#ifdef LOG
	printf("[Debug] path_start %d\n", path_start);
	printf("[Debug] last_slash %d\n", last_slash);

	printf("[Debug] complement[last_slash + 1] is %s\n", complement + last_slash + 1);
#endif

	char f_dirname[BUFLEN];
	f_dirname[0] = '/';
	f_dirname[1] = '\0';
	int i = 1;
	int j = complement[path_start] == '/' ? path_start + 1 : path_start;

	for(; j < last_slash; i++, j++){
		f_dirname[i] = complement[j];
	}

	// for now, support 32 file names, each shorter than 64
	ipc_msg_t *ipc_msg;
	int start = 0;
	int ret = 0;
	struct fs_request fr;
	int flag = 0;

	ipc_msg = ipc_create_msg(tmpfs_ipc_struct,
				 sizeof(struct fs_request), 1);
	fr.req = FS_REQ_SCAN;
	strcpy((void *)fr.path, f_dirname);

	do {
		fr.offset = start;
		fr.buff = (char *)TMPFS_SCAN_BUF_VADDR;
		fr.count = PAGE_SIZE;

		// notice in the boot_fs, we already map this pmo to vmr
		ipc_set_msg_cap(ipc_msg, 0, tmpfs_scan_pmo_cap);
		ipc_set_msg_data(ipc_msg, (char *)&fr, 0, sizeof(struct fs_request));
		ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
#ifdef LOG	
		printf("[Debug][Shell] ipc ret: %d\n", ret);
#endif
		
		char *vp = (char *)TMPFS_SCAN_BUF_VADDR;
		start += ret;
		for (int i = 0; i < ret; i++) {
			struct dirent* p = vp;
#ifdef LOG	
			printf("[Debug] p->d_name is: %s\n", p->d_name);
#endif
			if(is_begin_with(p->d_name, complement + last_slash + 1)){
				complement_time--;
				if(complement_time == 0){
					j = last_slash + 1;
					for(i = 0; i < strlen(p->d_name); i++, j++){
						buf[j] = p->d_name[i];
					}
					buf[j] = '\0';
#ifdef LOG	
					printf("[Debug] complemented buf now is: %s\n", buf);
#endif
					flag = 1;
					goto found;
				}
			}
			vp += p->d_reclen;
		}

	} while (ret != 0);
	// notice here we don't round back, if there are too many tabs, it wouldn't be complemented
found:
	if(!flag){
		printf("[Shell] couldn't complement!!!\n");
	}

	ipc_destroy_msg(ipc_msg);
	
	return 0;
}

extern char getch();

// read a command from stdin leading by `prompt`
// put the commond in `buf` and return `buf`
// What you typed should be displayed on the screen
char *readline(const char *prompt)
{
	static char buf[BUFLEN];

	int i = 0, j = 0;
	unsigned char c = 0;
	int ret = 0;
	char complement[BUFLEN];
	int complement_time = 0;
	int complement_continue = 0;

	if (prompt != NULL) {
		printf("%s", prompt);
	}

	while (1) {
		c = getch();
		if (c < 0)
			return NULL;
		// TODO: your code here
		if(c == '\t'){
			buf[i] = '\0';
			if(complement_continue){
				complement_time++;
			} else {
				complement_time = 1;
				complement_continue = 1;
				strcpy(complement, buf);
			}
			int origin_len = strlen(prompt) + strlen(buf);
			do_complement(buf, complement, complement_time);
			// overwrite the origin 
			usys_putc('\r');
			for(int i = 0; i < origin_len; i++){
				usys_putc(' ');
			}
			usys_putc('\r');

			printf("%s", prompt);
			printf("%s", buf);
			i = strlen(buf);
			continue;
		}
		complement_continue = 0;
		if(c == '\r')
			usys_putc('\n');
		else
			usys_putc(c);

		if(i == BUFLEN-1){
			printf("\n%s", prompt);
			printf(" buf overflow!!!\n");
			return NULL;
		}

		if(c == '\n' || c == '\r'){
			buf[i] = '\0';
			return buf;
		}

		buf[i++] = c;
	}
}

int do_cd(char *cmdline)
{
#ifdef LOG
	printf("[Debug] begin command do_cd...\n");
#endif	
	cmdline += 2;
	while (*cmdline == ' ')
		cmdline++;
	if (*cmdline == '\0')
		return 0;

	// for now, cd only support the absolute path starts from the root
	if (*cmdline == '/') {
		if(strlen(cmdline) >= BUFLEN){
			printf("[Debug] path is too long, cd failed!!!\n", cmdline);
			return 0;
		}
		strcpy(current_dir, cmdline);
		printf("[Debug] change dir to: %s\n", current_dir);
	}
	else {
		printf("[Shell] cd dosen't support this kind of path for now: %s\b", cmdline);
	}

	return 0;
}

int do_top()
{
	// TODO: your code here
	usys_top();
	return 0;
}

void fs_scan(char *path)
{
	// TODO: your code here
	ipc_msg_t *ipc_msg;
	int start = 0;
	int ret = 0;
	struct fs_request fr;
	char *str = malloc(256);
	int path_names_index = 0;

	ipc_msg = ipc_create_msg(tmpfs_ipc_struct,
				 sizeof(struct fs_request), 1);
	fr.req = FS_REQ_SCAN;
	strcpy((void *)fr.path, path);

	do {
		fr.offset = start;
		fr.buff = (char *)TMPFS_SCAN_BUF_VADDR;
		fr.count = PAGE_SIZE;

		// notice in the boot_fs, we already map this pmo to vmr
		ipc_set_msg_cap(ipc_msg, 0, tmpfs_scan_pmo_cap);
		ipc_set_msg_data(ipc_msg, (char *)&fr, 0, sizeof(struct fs_request));
		ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
		
		char *vp = (char *)TMPFS_SCAN_BUF_VADDR;
		start += ret;
		for (int i = 0; i < ret; i++) {
			struct dirent* p = vp;
			strcpy(str, p->d_name);
			printf("%s\n", str);
			vp += p->d_reclen;
		}

	} while (ret != 0);

	ipc_destroy_msg(ipc_msg);
	free(str);
	
	return;
}

int do_ls(char *cmdline)
{
	char pathbuf[BUFLEN];

	pathbuf[0] = '\0';
	cmdline += 2;
	while (*cmdline == ' ')
		cmdline++;

	// make sure the path is begin with '/'
	if(*cmdline != '/'){
		pathbuf[0] = '/';
		pathbuf[1] = '\0';
	}
	strcat(pathbuf, cmdline);

	fs_scan(pathbuf);
	return 0;
}


void fs_read(char *path)
{
	// TODO: your code here
	ipc_msg_t *ipc_msg;
	int start = 0;
	int ret = 0;
	struct fs_request fr;
	int total_size = 0;

	ipc_msg = ipc_create_msg(tmpfs_ipc_struct,
				 sizeof(struct fs_request), 1);

	strcpy((void *)fr.path, path);

	fr.req = FS_REQ_GET_SIZE;

	ipc_set_msg_data(ipc_msg, (char *)&fr, 0, sizeof(struct fs_request));
	ret = ipc_call(tmpfs_ipc_struct, ipc_msg);

#ifdef LOG
	printf("[Debug][Shell] get size ipc ret: %d\n", ret);
#endif

	total_size = ret;

	fr.req = FS_REQ_READ;

	do {
		fr.offset = start;
		fr.buff = (char *)TMPFS_READ_BUF_VADDR;
		// left one for the '\0'
		fr.count = total_size < (PAGE_SIZE - 1) ? total_size : (PAGE_SIZE - 1);

		// notice in the boot_fs, we already map this pmo to vmr
		ipc_set_msg_cap(ipc_msg, 0, tmpfs_read_pmo_cap);
		ipc_set_msg_data(ipc_msg, (char *)&fr, 0, sizeof(struct fs_request));
		ret = ipc_call(tmpfs_ipc_struct, ipc_msg);

#ifdef LOG
		printf("[Debug][Shell] ipc ret: %d\n", ret);
#endif

		*((char *)TMPFS_READ_BUF_VADDR + ret) = '\0';
		
		start += ret;
		total_size -= ret;

		char *str = (char *)TMPFS_READ_BUF_VADDR;
		printf("%s\n", str);

	} while (total_size != 0);

	ipc_destroy_msg(ipc_msg);
	
	return;
}

int do_cat(char *cmdline)
{
	char pathbuf[BUFLEN];

	pathbuf[0] = '\0';
	cmdline += 3;
	while (*cmdline == ' ')
		cmdline++;

	// make sure the path is begin with '/'
	if(*cmdline != '/'){
		pathbuf[0] = '/';
		pathbuf[1] = '\0';
	}
	strcat(pathbuf, cmdline);

	fs_read(pathbuf);
	return 0;
}

int do_echo(char *cmdline)
{
	cmdline += 4;
	while (*cmdline == ' ')
		cmdline++;
	printf("%s\n", cmdline);
	return 0;
}

void do_clear(void)
{
	usys_putc(12);
	usys_putc(27);
	usys_putc('[');
	usys_putc('2');
	usys_putc('J');
}

int builtin_cmd(char *cmdline)
{
	int ret, i;
	char cmd[BUFLEN];
	for (i = 0; cmdline[i] != ' ' && cmdline[i] != '\0'; i++)
		cmd[i] = cmdline[i];
	cmd[i] = '\0';
	if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit"))
		usys_exit(0);
	if (!strcmp(cmd, "cd")) {
		ret = do_cd(cmdline);
		return !ret ? 1 : -1;
	}
	if (!strcmp(cmd, "ls")) {
		ret = do_ls(cmdline);
		return !ret ? 1 : -1;
	}
	if (!strcmp(cmd, "echo")) {
		ret = do_echo(cmdline);
		return !ret ? 1 : -1;
	}
	if (!strcmp(cmd, "cat")) {
		ret = do_cat(cmdline);
		return !ret ? 1 : -1;
	}
	if (!strcmp(cmd, "clear")) {
		do_clear();
		return 1;
	}
	if (!strcmp(cmd, "top")) {
		ret = do_top();
		return !ret ? 1 : -1;
	}
	return 0;
}

int run_cmd(char *cmdline)
{
	char pathbuf[BUFLEN];
	struct user_elf user_elf;
	int ret;
	int caps[1];

	pathbuf[0] = '\0';
	while (*cmdline == ' ')
		cmdline++;
	if (*cmdline == '\0') {
		return -1;
	} else if (*cmdline != '/') {
		strcpy(pathbuf, "/");
	}
	strcat(pathbuf, cmdline);

	ret = readelf_from_fs(pathbuf, &user_elf);
	if (ret < 0) {
		printf("[Shell] No such binary\n");
		return ret;
	}

	caps[0] = fs_server_cap;
	int child_process_cap = -1;
	int child_main_thread_cap = -1;
	ret = launch_process_with_pmos_caps(&user_elf, &child_process_cap, &child_main_thread_cap,
					     NULL, 0, caps, 1, 0);
	fail_cond(ret != 0, "create_process returns %d\n", ret);
	
	// just because there is time limit in the test case
	// so we should schedule quickly
	usys_yield();
	while(!sys_is_thread_finished(child_main_thread_cap)){

	}
	
	return ret;
}

static int
run_cmd_from_kernel_cpio(const char *filename, int *new_thread_cap,
			 struct pmo_map_request *pmo_map_reqs,
			 int nr_pmo_map_reqs)
{
	struct user_elf user_elf;
	int ret;

	ret = readelf_from_kernel_cpio(filename, &user_elf);
	if (ret < 0) {
		printf("[Shell] No such binary in kernel cpio\n");
		return ret;
	}
	return launch_process_with_pmos_caps(&user_elf, NULL, new_thread_cap,
					     pmo_map_reqs, nr_pmo_map_reqs,
					     NULL, 0, 0);
}

void boot_fs(void)
{
	int ret = 0;
	int info_pmo_cap;
	int tmpfs_main_thread_cap;
	struct pmo_map_request pmo_map_requests[1];

	/* create a new process */
	printf("Booting fs...\n");
	/* prepare the info_page (transfer init info) for the new process */
	info_pmo_cap = usys_create_pmo(PAGE_SIZE, PMO_DATA);
	fail_cond(info_pmo_cap < 0, "usys_create_ret ret %d\n", info_pmo_cap);

	ret = usys_map_pmo(SELF_CAP,
			   info_pmo_cap, TMPFS_INFO_VADDR, VM_READ | VM_WRITE);
	fail_cond(ret < 0, "usys_map_pmo ret %d\n", ret);

	SERVER_READY_FLAG(TMPFS_INFO_VADDR) = 0;
	SERVER_EXIT_FLAG(TMPFS_INFO_VADDR) = 0;

	/* We also pass the info page to the new process  */
	pmo_map_requests[0].pmo_cap = info_pmo_cap;
	pmo_map_requests[0].addr = TMPFS_INFO_VADDR;
	pmo_map_requests[0].perm = VM_READ | VM_WRITE;
	ret = run_cmd_from_kernel_cpio("/tmpfs.srv", &tmpfs_main_thread_cap,
				       pmo_map_requests, 1);
	fail_cond(ret != 0, "create_process returns %d\n", ret);

	fs_server_cap = tmpfs_main_thread_cap;

	while (SERVER_READY_FLAG(TMPFS_INFO_VADDR) != 1)
		usys_yield();

	/* register IPC client */
	tmpfs_ipc_struct = &ipc_struct;
	ret = ipc_register_client(tmpfs_main_thread_cap, tmpfs_ipc_struct);
	fail_cond(ret < 0, "ipc_register_client failed\n");

	/* create pmo for scan and map to vmr */
	tmpfs_scan_pmo_cap = usys_create_pmo(PAGE_SIZE, PMO_DATA);
	fail_cond(tmpfs_scan_pmo_cap < 0, "usys create_ret ret %d\n",
		  tmpfs_scan_pmo_cap);

	ret = usys_map_pmo(SELF_CAP,
			   tmpfs_scan_pmo_cap,
			   TMPFS_SCAN_BUF_VADDR, VM_READ | VM_WRITE);
	fail_cond(ret < 0, "usys_map_pmo ret %d\n", ret);

	/* create pmo for read and map to vmr */
	tmpfs_read_pmo_cap = usys_create_pmo(PAGE_SIZE, PMO_DATA);
	fail_cond(tmpfs_read_pmo_cap < 0, "usys create_ret ret %d\n",
		  tmpfs_read_pmo_cap);

	ret = usys_map_pmo(SELF_CAP,
			   tmpfs_read_pmo_cap,
			   TMPFS_READ_BUF_VADDR, VM_READ | VM_WRITE);
	fail_cond(ret < 0, "usys_map_pmo ret %d\n", ret);

	printf("fs is UP.\n");

	current_dir[0] = '/';
	current_dir[1] = '\0';
}
