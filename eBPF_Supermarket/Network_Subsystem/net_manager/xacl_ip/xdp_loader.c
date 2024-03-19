/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF program --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "common_kern_user.h"

static const char *default_filename = "xdp_prog_kern.o";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_stats_map";
char pin_dir[PATH_MAX];
char map_filename[PATH_MAX];

int unpin_maps(struct bpf_object *bpf_obj)
{
	int err;
	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	return 0;
}

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj)
{
	int err;
	unpin_maps(bpf_obj);
	if (verbose)
		printf(" - Pinning maps in %s/\n", pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, pin_dir);
	if (err)
		return EXIT_FAIL_BPF;

	return 0;
}

int main(int argc, char **argv)
{
	struct xdp_program *program;  // XDP程序对象指针
	int err;  // 错误码
	int len;  // 字符串长度
	char errmsg[1024];  // 错误消息字符串


	// 配置结构体，包括XDP模式、接口索引、是否卸载程序以及程序名称等信息
	struct config cfg = {
		.attach_mode = XDP_MODE_NATIVE,
		.ifindex     = -1,
		.do_unload   = false,
		.progname = "xdp_entry"
	};
	/* Set default BPF-ELF object file and BPF program name */
	// 设置默认的BPF ELF对象文件名和BPF程序名称
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	/* Cmdline options can change progname */
	// 解析命令行参数，可能会修改程序名称等配置信息
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	// 检查是否提供了必需的选项
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	/* Generate pin_dir & map_filename string */
	// 生成pin目录和映射文件名字符串
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}
	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
		       pin_basedir, cfg.ifname, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}

	// 加载BPF程序并将其附加到XDP
	program = load_bpf_and_xdp_attach(&cfg);
	if (!program)
		return EXIT_FAIL_BPF;   // 如果加载失败，则返回BPF错误退出码

	/* do unload */
	// 如果指定了卸载选项，则执行卸载操作
	if (cfg.do_unload) {
		unpin_maps(xdp_program__bpf_obj(program));  // 解除BPF程序固定的映射
		err = do_unload(&cfg);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't unload XDP program %s: %s\n",
				cfg.progname, errmsg);  // 打印卸载错误消息
			return err;
		}

		printf("Success: Unloading XDP prog name: %s\n", cfg.progname);
		return EXIT_OK;; 
	}

	// 如果启用了详细模式，则打印加载的BPF对象文件和程序名称，以及附加的XDP程序的设备信息
	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used program(%s)\n",
		       cfg.filename, cfg.progname);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	// 使用--dev名称作为子目录来导出/固定映射
	err = pin_maps_in_bpf_object(xdp_program__bpf_obj(program));
	if (err) {
		fprintf(stderr, "ERR: pinning maps\n");
		return err;
	}

	return EXIT_OK;
}
