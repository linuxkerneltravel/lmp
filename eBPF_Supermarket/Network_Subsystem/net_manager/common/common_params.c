#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

#include <net/if.h>
#include <linux/if_link.h> /* XDP_FLAGS_* depend on kernel-headers installed */
#include <linux/if_xdp.h>

#include "common_params.h"

int verbose = 1;

#define BUFSIZE 30

/**
 * @brief 打印选项的帮助信息
 * 
 * @param long_options 包含所有长选项的结构体数组
 * @param required 标志位，用于指示是否打印必需的选项
 */
void _print_options(const struct option_wrapper *long_options, bool required)
{
    int i, pos;
    char buf[BUFSIZE];

    // 遍历所有的长选项
    for (i = 0; long_options[i].option.name != 0; i++) {
        // 如果选项的必需性与参数不符，则跳过
        if (long_options[i].required != required)
            continue;

        // 如果选项的短名称为大写字母，打印其短名称
        if (long_options[i].option.val > 64) /* ord('A') = 65 */
            printf(" -%c,", long_options[i].option.val);
        else
            // 否则不打印短名称，保留空白对齐
            printf("    ");

        // 将选项的长名称及其元变量（如果有）格式化到 buf 中
        pos = snprintf(buf, BUFSIZE, " --%s", long_options[i].option.name);
        if (long_options[i].metavar)
            snprintf(&buf[pos], BUFSIZE-pos, " %s", long_options[i].metavar);

        // 打印格式化后的选项名称和帮助信息
        printf("%-22s", buf);
        printf("  %s", long_options[i].help);
        printf("\n");
    }
}


/**
 * @brief 打印程序的用法信息
 * 
 * @param prog_name 程序名
 * @param doc 程序的文档说明
 * @param long_options 包含所有长选项的结构体数组
 * @param full 标志位，是否打印完整的帮助信息
 */
void usage(const char *prog_name, const char *doc,
           const struct option_wrapper *long_options, bool full)
{
    // 打印用法信息的基本格式
    printf("Usage: %s [options]\n", prog_name);

    // 如果不需要打印完整的帮助信息
    if (!full) {
        // 提示用户使用 --help 或 -h 查看完整的选项列表
        printf("Use --help (or -h) to see full option list.\n");
        return;
    }

    // 打印文档说明
    printf("\nDOCUMENTATION:\n %s\n", doc);

    // 打印必需选项
    printf("Required options:\n");
    _print_options(long_options, true);
    printf("\n");

    // 打印其他选项
    printf("Other options:\n");
    _print_options(long_options, false);
    printf("\n");
}


/**
 * @brief 将 option_wrapper 结构体数组转换为标准的 option 结构体数组
 * 
 * @param wrapper 包含所有长选项的结构体数组
 * @param options 输出参数，用于存储转换后的 option 结构体数组
 * @return int 成功返回0，失败返回-1
 */
int option_wrappers_to_options(const struct option_wrapper *wrapper,
				struct option **options)
{
	int i, num;
	struct option *new_options;

	// 计算 wrapper 数组中的选项数量
	for (i = 0; wrapper[i].option.name != 0; i++) {}
	num = i;

	// 分配新的 option 数组内存
	new_options = malloc(sizeof(struct option) * num);
	if (!new_options)
		// 如果内存分配失败，返回 -1
		return -1;

	// 将 wrapper 数组中的每个 option 复制到新的 option 数组中
	for (i = 0; i < num; i++) {
		memcpy(&new_options[i], &wrapper[i], sizeof(struct option));
	}

	// 将新分配并填充的 option 数组赋值给输出参数 *options
	*options = new_options;

	// 成功返回 0
	return 0;
}


/**
 * @brief 解析命令行参数
 * 
 * @param argc 参数个数
 * @param argv 参数值数组
 * @param options_wrapper 包含所有长选项的结构体数组
 * @param cfg 配置结构体，用于存储解析结果
 * @param doc 程序的文档说明
 */
void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *options_wrapper,
                        struct config *cfg, const char *doc)
{
	struct option *long_options;
	bool full_help = false;
	int longindex = 0;
	char *dest;
	int opt;

	// 将 option_wrapper 结构体数组转换为标准的 option 结构体数组
	if (option_wrappers_to_options(options_wrapper, &long_options)) {
		fprintf(stderr, "Unable to malloc()\n");
		exit(EXIT_FAIL_OPTION);
	}

	/* 解析命令行参数 */
	while ((opt = getopt_long(argc, argv, "hd:r:L:R:ASNFUMQ:czpq:i:m:k:g:n:tTf",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'd':
			// 检查设备名称长度是否超出限制
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			// 设置设备名称
			cfg->ifname = (char *)&cfg->ifname_buf;
			strncpy(cfg->ifname, optarg, IF_NAMESIZE);
			// 获取设备索引
			cfg->ifindex = if_nametoindex(cfg->ifname);
			if (cfg->ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'r':
			// 检查重定向设备名称长度是否超出限制
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --redirect-dev name too long\n");
				goto error;
			}
			// 设置重定向设备名称
			cfg->redirect_ifname = (char *)&cfg->redirect_ifname_buf;
			strncpy(cfg->redirect_ifname, optarg, IF_NAMESIZE);
			// 获取重定向设备索引
			cfg->redirect_ifindex = if_nametoindex(cfg->redirect_ifname);
			if (cfg->redirect_ifindex == 0) {
				fprintf(stderr,
						"ERR: --redirect-dev name unknown err(%d):%s\n",
						errno, strerror(errno));
				goto error;
			}
			break;
		case 't':
			cfg->show_stats = true;
			break;
		case 'i':
			cfg->ip_filter = true;
			// 检查文件路径长度是否超出限制
			if (strlen(optarg) >= FILE_MAXSIZE) {
				fprintf(stderr, "ERR: --ip_filter_file name too long\n");
				goto error;
			}
			// 设置文件路径
			cfg->ip_filter_file = (char *)&cfg->ip_filter_file_buf; //初始化ip_filter_file
			strncpy(cfg->ip_filter_file, optarg, FILE_MAXSIZE);
			//printf("%s %s\n",optarg,cfg->ip_filter_file);
			break;
		case 'm':
			cfg->mac_filter = true;
			// 检查文件路径长度是否超出限制
			if (strlen(optarg) >= FILE_MAXSIZE) {
				fprintf(stderr, "ERR: --mac_filter_file name too long\n");
				goto error;
			}
			// 设置文件路径
			cfg->mac_filter_file = (char *)&cfg->mac_filter_file_buf; //初始化mac_filter_file
			strncpy(cfg->mac_filter_file, optarg, FILE_MAXSIZE);
			break;
		case 'k':
			cfg->router = true;
			// 检查文件路径长度是否超出限制
			if (strlen(optarg) >= FILE_MAXSIZE) {
				fprintf(stderr, "ERR: --router_file name too long\n");
				goto error;
			}
			// 设置文件路径
			cfg->router_file = (char *)&cfg->router_file_buf; //初始化router_file
			strncpy(cfg->router_file, optarg, FILE_MAXSIZE);
			break;
		case 'g':
			cfg->state = true;
			break;
		case 'n':
			cfg->clear = true;
			break;	
		case 'A':
			// 设置附加模式为未指定模式
			cfg->attach_mode = XDP_MODE_UNSPEC;
			break;
		case 'S':
			// 设置附加模式为 SKB 模式
			cfg->attach_mode = XDP_MODE_SKB;
			cfg->xsk_bind_flags &= ~XDP_ZEROCOPY;
			cfg->xsk_bind_flags |= XDP_COPY;
			break;
		case 'N':
			// 设置附加模式为原生模式
			cfg->attach_mode = XDP_MODE_NATIVE;
			break;
		case 3: /* --offload-mode */
			// 设置附加模式为硬件模式
			cfg->attach_mode = XDP_MODE_HW;
			break;
		case 'M':
			// 启用重用地图
			cfg->reuse_maps = true;
			break;
		case 'U':
			// 设置卸载标志
			cfg->do_unload = true;
			cfg->unload_all = true;
			// cfg->prog_id = atoi(optarg);
			break;
		case 'p':
			// 启用轮询模式
			cfg->xsk_poll_mode = true;
			break;
		case 'q':
			// 设置为非详细模式
			verbose = false;
			break;
		case 'Q':
			// 设置接口队列
			cfg->xsk_if_queue = atoi(optarg);
			break;
		case 1: /* --filename */
			// 设置文件名
			dest  = (char *)&cfg->filename;
			strncpy(dest, optarg, sizeof(cfg->filename));
			break;
		case 2: /* --progname */
			// 设置程序名称
			dest  = (char *)&cfg->progname;
			strncpy(dest, optarg, sizeof(cfg->progname));
			break;
		case 'L': /* --src-mac */
			// 设置源 MAC 地址
			dest  = (char *)&cfg->src_mac;
			strncpy(dest, optarg, sizeof(cfg->src_mac));
			break;
		case 'R': /* --dest-mac */
			// 设置目的 MAC 地址
			dest  = (char *)&cfg->dest_mac;
			strncpy(dest, optarg, sizeof(cfg->dest_mac));
			break;
		case 'c':
			// 设置绑定标志为复制模式
			cfg->xsk_bind_flags &= ~XDP_ZEROCOPY;
			cfg->xsk_bind_flags |= XDP_COPY;
			break;
		case 'z':
			// 设置绑定标志为零拷贝模式
			cfg->xsk_bind_flags &= ~XDP_COPY;
			cfg->xsk_bind_flags |= XDP_ZEROCOPY;
			break;
		case 4: /* --unload-all */
			// 设置卸载所有标志
			cfg->unload_all = true;
			break;
		case 'h':
			// 设置显示完整帮助信息的标志
			full_help = true;
			/* fall-through */
			break;
		case 'T':
			// 设置打印的标志
			cfg->print_info = true;
			break;
		case 'f':
			// 设置打印的标志
			cfg->socketmap_flag = true;
			break;
		error:
		default:
			// 打印使用信息并退出
			usage(argv[0], doc, options_wrapper, full_help);
			free(long_options);
			exit(EXIT_FAIL_OPTION);
		}
	}
	// 释放分配的内存
	free(long_options);
}
