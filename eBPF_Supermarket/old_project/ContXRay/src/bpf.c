/********************************************************************************
* @File name: bpf.c
* @Author: XUPT barryX DONG XU
* @Version: 1.1
* @Date: 2022/5/29
* @Description: Kernel BPF program
********************************************************************************/

#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/cgroup-defs.h>
#include <linux/kernfs.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/tcp.h>

#define CONTAINER_ID_LEN 32
#define FILENAME_LEN 64
#define FSNAME_LEN 64
#define TASK_COMM_LEN 16
#define ARGV_LEN 64
#define CONTAINER_ID_USE_LEN 12
#define FLAGCOUNT 8

struct syscall_key_t{
    u32 argsid;
    char cid[CONTAINER_ID_USE_LEN];
};

struct fileopen_info {
    u32 pid;
    char filename[FILENAME_LEN];
    char fsname[FSNAME_LEN];
    char comm[TASK_COMM_LEN];
    char cid[CONTAINER_ID_USE_LEN];
};

struct visit_key_t {
    u32 seq;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};
struct visit_value {
    char cid[CONTAINER_ID_USE_LEN];
    char comm[TASK_COMM_LEN];
    u8 sc_flag;
};
struct visit_info {
    char scid[CONTAINER_ID_USE_LEN];
    char dcid[CONTAINER_ID_USE_LEN];
    char sccomm[TASK_COMM_LEN];
    char dccomm[TASK_COMM_LEN];
    u16 sport;
    u16 dport;
    u8 flag;
};

struct exec_info {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
    char argv[ARGV_LEN];
    char cid[CONTAINER_ID_USE_LEN];
};


// union tcp_hdr_word { 
// 	struct tcphdr hdr;
// 	u32     words[10];
// }; 

// struct access_bitfield_flag {
//     u8 pad0[offsetof(struct tcphdr,window)-1];
//     u16 flags;
// };


BPF_HASH(syscalls,struct syscall_key_t,u32);
BPF_HASH(visit,struct visit_key_t,struct visit_value);
BPF_HASH(socktable,void *,struct task_struct *);

BPF_PERF_OUTPUT(fileopen_event);
BPF_PERF_OUTPUT(exec_event);
BPF_PERF_OUTPUT(cv_event);

/**
 * @description: Compare string
 * @param {char} *s1 string 1
 * @param {char} *s2 string 2
 * @return {*} Return 0 when s1==s2
 */
static int strcmp_64(char *s1, char *s2){
    int i;
    #pragma clang loop unroll(full)
    for(i=63;i>0;i--){
        if(s1[i] != s2[i])
            break;
    }
    return i;
}

/**
 * @description: Calculate the length of the string
 * @param {char} *str The string to be caculated
 * @return {*} The length of the string
 */
static int strlen_64(char *str){
    int i;
    #pragma clang loop unroll(full)
    for(i=0;i<FILENAME_LEN;i++){
        if(str[i] == 0)
            break;
    }
    return i;
}

/**
 * @description: Concatenate string 1 and string 2
 * @param {char} *s1 string1
 * @param {char} *s2 string2
 * @param {char} *result Concatenate result
 * @return {*} The length of the string1
 */
static int strcat_64(char *s1,char *s2,char *result){ //return s1+s2
    int i;
    i = strlen_64(s1);
    if(i < 1)
        return i;
    bpf_probe_read_kernel_str(result,FILENAME_LEN,s1);
    char * _result = &result[i];
    bpf_probe_read_kernel_str(_result,FILENAME_LEN-i,s2);
    return i;
}

/**
 * @description: Get the level of the task
 * @param {struct task_struct} *task 
 * @return {*} The level of the task
 */
static int get_level(struct task_struct *task){
    return(task->nsproxy->pid_ns_for_children->level);
}

/**
 * @description: Get the container id of the task from cgroup
 * @param {struct task_struct} *task 
 * @param {char} *cid Save the container id
 * @return {*} The length of the string cid
 */
static int get_cont_id(struct task_struct *task, char *cid){
    struct css_set *css;
    struct cgroup_subsys_state *sbs;
    struct cgroup *cg;
    struct kernfs_node *knode, *pknode;
    char tmp_cid[CONTAINER_ID_LEN];
    char *_cid;
    css = task->cgroups;
    bpf_probe_read(&sbs, sizeof(void *), &css->subsys[0]);
        bpf_probe_read(&cg,  sizeof(void *), &sbs->cgroup);
        bpf_probe_read(&knode, sizeof(void *), &cg->kn);
        bpf_probe_read(&pknode, sizeof(void *), &knode->parent);
        if(pknode != NULL) {
            char *aus;
            bpf_probe_read(&aus, sizeof(void *), &knode->name);
            bpf_probe_read_str(&tmp_cid, CONTAINER_ID_LEN, aus);
            if(tmp_cid[6] == '-')
                _cid = &tmp_cid[7];
            else
                _cid = (char *)&tmp_cid;
            bpf_probe_read_str(cid,CONTAINER_ID_USE_LEN,_cid);
        }
    return sizeof(cid);
}

/**
 * @description: Add "/" to the head of string
 * @param {char *} str
 * @return {*} return 1 when success
 */
static int add_head_slash(char * str){
    if(str[0] == '/' && str[1] == 0){
        char empty_str[FILENAME_LEN] = "";
        bpf_probe_read_kernel_str(str,FILENAME_LEN,empty_str);
        return -1;
    }
    char tmp[FILENAME_LEN];
    bpf_probe_read_kernel_str(tmp,FILENAME_LEN,str);
    char * _str = &str[1];
    bpf_probe_read_kernel_str(_str,FILENAME_LEN-1,tmp);
    str[0] = '/';
    return 1;
}

/**
 * @description: Get the name of the dentry
 * @param {dentry} *den
 * @param {char *} name
 * @return {*}
 */
static void get_dentry_name(struct dentry *den,char * name){
    bpf_probe_read_kernel_str(name,FILENAME_LEN,den->d_name.name);
    add_head_slash(name);
}

/**
 * @description: Traverse the parent field of dentry to get the full file name
 * @param {dentry} *den
 * @param {char *} filename
 * @return {*}
 */
static int get_full_filename(struct dentry *den,char * filename){
    int i;
    char p_name[FILENAME_LEN],tmp[FILENAME_LEN];
    struct dentry *cur_den = den;
    get_dentry_name(cur_den,filename);
    #pragma clang loop unroll(full)
    for(i=0;i<64;i++){
        if(cur_den->d_parent == 0)
            break;
        cur_den = cur_den->d_parent;
        get_dentry_name(cur_den,p_name);
        strcat_64(p_name,filename,tmp);
        bpf_probe_read_kernel_str(filename,FILENAME_LEN,tmp);
    }
    return i;
}
/**
 * @description: 
 * @param {sock} *sk
 * @param {struct task_struct} *task 
 * @return {*}
 */
static void get_socked_task(struct sock *sk,struct task_struct *task){
    struct socket *sock;
    struct task_struct **ptask;
    bpf_probe_read_kernel(&sock,sizeof(void *),&sk->sk_socket);
    ptask = socktable.lookup((void *)&sock);
    bpf_trace_printk("---look-before--------");
    if(ptask == NULL){
        return;
    }
    bpf_trace_printk("get_socked_task:task %s",(*ptask)->comm);

    return;
}

/**
 * @description: 
 */ 
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct task_struct *curr_task = (struct task_struct *)bpf_get_current_task();
    if(get_level(curr_task)){
        struct syscall_key_t k = {.argsid = args->id};
        get_cont_id(curr_task,k.cid);
        syscalls.increment(k,1);
    }
    return 0;
}

/**
 * @description: 
 * @param {pt_regs} *ctx
 * @return {*}
 */
int trace_fileopen(struct pt_regs *ctx){
    struct task_struct *curr_task = (struct task_struct *)bpf_get_current_task();
    if(get_level(curr_task)){
        struct fileopen_info info = {.pid = (u32)curr_task->pid};
        struct file * fi = (struct file *)PT_REGS_RC(ctx);
        get_cont_id(curr_task,info.cid);
        bpf_probe_read_kernel_str(info.fsname,FSNAME_LEN,fi->f_inode->i_sb->s_type->name);
        get_full_filename(fi->f_path.dentry,info.filename);
        bpf_probe_read_kernel_str(info.comm,TASK_COMM_LEN,curr_task->comm);
        char overlay_s[FSNAME_LEN] = "overlay";
        if(strcmp_64(info.fsname,overlay_s) && strlen_64(info.filename)>0 && strlen_64(info.fsname)>0 ){
            fileopen_event.perf_submit(ctx, &info, sizeof(info));
        }
    }
    return 0;
}

/**
 * @description: 
 * @param {pt_regs} *ctx
 * @return {*}
 */
int trace_sock_alloc(struct pt_regs *ctx){
    struct task_struct *curr_task = (struct task_struct *)bpf_get_current_task();
    if(get_level(curr_task)){
        struct socket * sock = (struct socket *)PT_REGS_RC(ctx);
        // bpf_trace_printk("----------test sock_task function :%s---test sock:%d------",curr_task->comm,sock->state);
        socktable.update((void *)&sock,&curr_task);
    }
    return 0;
}

/**
 * @description: 
 * @param {pt_regs} *ctx
 * @return {*}
 */
int trace_tcp_visit(struct pt_regs *ctx){
    struct task_struct *sock_task;
    struct task_struct **psock_task;
    struct socket *sock;
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    bpf_probe_read_kernel(&sock,sizeof(void *),&sk->sk_socket);
    psock_task = socktable.lookup((void *)&sock);
    if(psock_task){
        sock_task = *psock_task;
    }
    if(get_level(sock_task)){
        struct visit_value value = {};
        get_cont_id(sock_task,value.cid);
        bpf_probe_read_kernel_str(value.comm,TASK_COMM_LEN,sock_task->comm);
        struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
        struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
        const struct tcphdr *th;
        const struct iphdr *iph;
        u32 seq = tcb->seq;//data 1
        u8 flags = tcb->tcp_flags;
        flags &= 0x00ff;
        bpf_probe_read_kernel(&value.sc_flag,sizeof(u8),&flags);
        bpf_trace_printk("ack test:%d",flags);
        struct visit_key_t visit_key = {.seq = seq};
         bpf_probe_read_kernel(&visit_key.saddr,sizeof(u32),&sk->__sk_common.skc_rcv_saddr); //data 2
         bpf_probe_read_kernel(&visit_key.sport,sizeof(u16),&sk->__sk_common.skc_num);       //data 3
         bpf_probe_read_kernel(&visit_key.daddr,sizeof(u32),&sk->__sk_common.skc_daddr);     //data 4
         bpf_probe_read_kernel(&visit_key.dport,sizeof(u16),&sk->__sk_common.skc_dport);     //data 5
         visit_key.dport = ntohs(visit_key.dport);
         visit.update(&visit_key,&value);   //save_info:cid -> other cid
    }
    return 0;
}

/**
 * @description: 
 * @param {pt_regs} *ctx
 * @return {*}
 */
int trace_tcp_visted(struct pt_regs *ctx){
    struct task_struct *sock_task;
    struct task_struct **psock_task;
    struct socket *sock;
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    bpf_probe_read_kernel(&sock,sizeof(void *),&sk->sk_socket);
    psock_task = socktable.lookup((void *)&sock);
    if(psock_task){
        sock_task = *psock_task;
    }
    if(get_level(sock_task)){
        struct task_struct *test;
        get_socked_task(sk,test);
        struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
        struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
        char scid[CONTAINER_ID_USE_LEN];
        char dcid[CONTAINER_ID_USE_LEN];
        const struct tcphdr *th;
        const struct iphdr *iph;
        th = ( const struct tcphdr *)skb->data;
        iph = (const struct iphdr *)(skb->head + skb->network_header);
        struct visit_key_t visit_key = {};
        struct visit_value *ret;
        // u16 flags = (*(&(th->window)-1));
        // u16 _flags = (flags >>6)<<9; 
        // struct access_bitfield_flag *accessor = (struct tcphdr *)th;
        // u8 flag = accessor->flags;
        // flag &= 0x10;
        #if defined(__LITTLE_ENDIAN_BITFIELD)
        bpf_trace_printk("LITTLE");
        #elif defined(__BIG_ENDIAN_BITFIELD)
        bpf_trace_printk("BIG");
        #else
        #endif	
        u32 saddr = iph->saddr;   //data 1
        u32 daddr = iph->daddr;   //data 2
        u16 sport = th->source;   //data 3
        u16 dport = th->dest;     //data 4
        u32 seq = tcb->seq;       //data 5

        //reverse data1~data4 and assigned to the key
        visit_key.sport = ntohs(sport); 
        visit_key.dport = ntohs(dport);
        visit_key.saddr = saddr;
        visit_key.daddr = daddr;
        //record the seq
        visit_key.seq = seq;
        ret = visit.lookup(&visit_key);
        if(ret){
        visit.delete((struct visit_key_t *)&ret);
        struct visit_info vinfo = {};
        get_cont_id(sock_task,dcid);
        bpf_probe_read_str(scid, CONTAINER_ID_USE_LEN, ret->cid);    
        bpf_probe_read_str(vinfo.scid,CONTAINER_ID_USE_LEN,scid);    //value1: scid
        bpf_probe_read_str(vinfo.dcid,CONTAINER_ID_USE_LEN,dcid);    //value2: dcid
        bpf_probe_read_kernel(&vinfo.sport,sizeof(u16),&visit_key.sport); //value3 :sport
        bpf_probe_read_kernel(&vinfo.dport,sizeof(u16),&visit_key.dport); //value4 :dpoer
        bpf_probe_read_kernel_str(vinfo.sccomm,TASK_COMM_LEN,ret->comm); //value5: sccomm
        bpf_probe_read_kernel_str(vinfo.dccomm,TASK_COMM_LEN,sock_task->comm); //value6 :dccomm
        bpf_probe_read_kernel(&vinfo.flag,sizeof(u8),&ret->sc_flag);    //value7 :tcp_flag
        // bpf_trace_printk("%s->%s",vinfo.scid,vinfo.dcid);
        cv_event.perf_submit(ctx, &vinfo, sizeof(vinfo));
        }           
    }
     return 0;
}

/**
 * @description: Get the syscall exec param
 * @param {pt_regs} *ctx
 * @param {char __user} *filename
 * @param {char __user *__user} *__argv
 * @return {*}
 */
int syscall__execve(struct pt_regs *ctx,const char __user *filename,const char __user *const __user *__argv){
    struct task_struct *curr_task = (struct task_struct *)bpf_get_current_task();
    if(get_level(curr_task)){
        struct exec_info info = {.pid = (u32)curr_task->pid};
        const char * _argv;
        bpf_probe_read_kernel_str(info.comm,TASK_COMM_LEN,curr_task->comm);
        bpf_probe_read_user_str(info.filename,FILENAME_LEN,filename);
        bpf_probe_read_user(&_argv,sizeof(void *),&__argv[1]);
        bpf_probe_read_user_str(info.argv,ARGV_LEN,_argv);
        get_cont_id(curr_task,info.cid);
        exec_event.perf_submit(ctx, &info, sizeof(info));
     }
     return 0;
}
