#ifndef __FS_WATCHER_H
#define __FS_WATCHER_H

/*open*/
#define path_size 256
#define TASK_COMM_LEN 16

struct event_open {
	int pid_;
	char path_name_[path_size];
	int n_;
    char comm[TASK_COMM_LEN];
};

/*read*/

struct event_read {
	int pid;
    unsigned long long duration_ns;
};

/*write*/
struct fs_t {
   unsigned long inode_number;
    pid_t pid;
    size_t real_count;
    size_t count;
};


#endif /* __MEM_WATCHER_H */