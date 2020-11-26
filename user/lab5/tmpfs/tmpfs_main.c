#include <syscall.h>
#include <launcher.h>
#include "tmpfs_server.h"

#define server_ready_flag_offset 0x0
#define server_exit_flag_offset  0x4

// prepare the augument for fs_server_scan
static int do_scan(struct fs_request *fr, ipc_msg_t * ipc_msg){
	int ret = 0;
	int err = 0;

	int cap = ipc_get_msg_cap(ipc_msg, 0);
#ifdef LOG	
	printf("[Debug][Server] do_scan cap: %d\n", cap);
	printf("[Debug][Server] do_scan path: %s\n", fr->path);
	printf("[Debug][Server] do_scan offset/start: %d\n", fr->offset);
	printf("[Debug][Server] do_scan count: %d\n", fr->count);
#endif
	/* map copied pmo to another va */
	err = usys_map_pmo(SELF_CAP, cap, TMPFS_SCAN_BUF_VADDR,
			VM_READ | VM_WRITE);
	fail_cond(err < 0, "usys_map_pmo on copied pmo ret %d\n", err);

	ret = fs_server_scan(fr->path, fr->offset, (void *)TMPFS_SCAN_BUF_VADDR, fr->count);
	fail_cond(ret < 0, "fs_server_scan ret %d\n", ret);

	/* unmap copied pmo */
	err = usys_unmap_pmo(SELF_CAP, cap, TMPFS_SCAN_BUF_VADDR);
	fail_cond(err < 0, "usys_unmap_pmo on copied pmo ret %d\n", err);

#ifdef LOG	
	printf("[Debug][Server] fs_server_scan success ret: %d\n", ret);
#endif
	return ret;
}


// prepare the augument for fs_server_read
static int do_read(struct fs_request *fr, ipc_msg_t * ipc_msg){
	int ret = 0;
	int err = 0;

	int cap = ipc_get_msg_cap(ipc_msg, 0);
#define LOG
#ifdef LOG	
	printf("[Debug][Server] do_read cap: %d\n", cap);
	printf("[Debug][Server] do_read path: %s\n", fr->path);
	printf("[Debug][Server] do_read offset/start: %d\n", fr->offset);
	printf("[Debug][Server] do_read count: %d\n", fr->count);
#endif
	/* map copied pmo to another va */
	err = usys_map_pmo(SELF_CAP, cap, TMPFS_READ_BUF_VADDR,
			VM_READ | VM_WRITE);
	fail_cond(err < 0, "usys_map_pmo on copied pmo ret %d\n", err);

	ret = fs_server_read(fr->path, fr->offset, (void *)TMPFS_READ_BUF_VADDR, fr->count);
	fail_cond(ret < 0, "do_read ret %d\n", ret);

	/* unmap copied pmo */
	err = usys_unmap_pmo(SELF_CAP, cap, TMPFS_READ_BUF_VADDR);
	fail_cond(err < 0, "usys_unmap_pmo on copied pmo ret %d\n", err);

#ifdef LOG	
	printf("[Debug][Server] do_read success ret: %d\n", ret);
#endif
	return ret;
}

static void fs_dispatch(ipc_msg_t * ipc_msg)
{
	int ret = 0;

	if (ipc_msg->data_len >= 4) {
		struct fs_request *fr = (struct fs_request *)
		    ipc_get_msg_data(ipc_msg);
		switch (fr->req) {
		case FS_REQ_SCAN:
				// TODO: you code here
			ret = do_scan(fr, ipc_msg);
			break;
		case FS_REQ_MKDIR:
			ret = fs_server_mkdir(fr->path);
			break;
		case FS_REQ_RMDIR:
			ret = fs_server_rmdir(fr->path);
			break;
		case FS_REQ_CREAT:
			ret = fs_server_creat(fr->path);
			break;
		case FS_REQ_UNLINK:
			ret = fs_server_unlink(fr->path);
			break;
		case FS_REQ_OPEN:
			error("%s: %d Not impelemented yet\n", __func__,
			      ((int *)ipc_get_msg_data(ipc_msg))[0]);
			usys_exit(-1);
			break;
		case FS_REQ_CLOSE:
			error("%s: %d Not impelemented yet\n", __func__,
			      ((int *)ipc_get_msg_data(ipc_msg))[0]);
			usys_exit(-1);
			break;
		case FS_REQ_WRITE:
				// TODO: you code here
			error("%s: %d Not impelemented yet\n", __func__,
			      ((int *)ipc_get_msg_data(ipc_msg))[0]);
			usys_exit(-1);
			break;
		case FS_REQ_READ:
				// TODO: you code here
			ret = do_read(fr, ipc_msg);
			break;
		case FS_REQ_GET_SIZE:{
				ret = fs_server_get_size(fr->path);
				break;

			}
		default:
			error("%s: %d Not impelemented yet\n", __func__,
			      ((int *)ipc_get_msg_data(ipc_msg))[0]);
			usys_exit(-1);
			break;
		}
	} else {
		printf("TMPFS: no operation num\n");
		usys_exit(-1);
	}

	usys_ipc_return(ret);
}

int main(int argc, char *argv[], char *envp[])
{
	void *info_page_addr = (void *)(long)TMPFS_INFO_VADDR;
	// void *info_page_addr = (void *) (envp[0]);
	int *server_ready_flag;
	int *server_exit_flag;

	printf("info_page_addr: 0x%lx\n", info_page_addr);

	if (info_page_addr == NULL) {
		error("[tmpfs] no info received. Bye!\n");
		usys_exit(-1);
	}

	fs_server_init(CPIO_BIN);
	info("register server value = %u\n", ipc_register_server(fs_dispatch));

	server_ready_flag = info_page_addr + server_ready_flag_offset;
	*server_ready_flag = 1;

	server_exit_flag = info_page_addr + server_exit_flag_offset;
	while (*server_exit_flag != 1) {
		usys_yield();
	}

	info("exit now. Bye!\n");
	return 0;
}
