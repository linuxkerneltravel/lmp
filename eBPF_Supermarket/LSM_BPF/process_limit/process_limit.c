#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <argp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "process_limit.skel.h"
#include "process_limit.h"

static struct env {
	bool verbose;
} env = {
	.verbose = false,
};

const char *argp_program_version = "bpf loggin example";
const char argp_program_doc[] = 
"An example BPF CO-RE application that demonstrates a libbpf maps set up\n";
static const struct argp_option opts[] = {
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{"verbose", 'v', NULL, 0, "verbose debug output"},
	{},
};

int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose) {
		return 0;
	}

	return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;

	}

	return 0;
}

static int print_execs(int fd)
{
	int err;
	struct event ev;
	pid_t lookup_key = 0, next_key;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &ev);
		if (err < 0) {
			fprintf(stderr, "failed to lookup exec: %d\n", err);
			return -1;
		}
		printf("\nProcess Name = %s, uid = %u, pid = %u\n", ev.comm, ev.uid, ev.pid);
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup execs : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

int main(int argc, char **argv) {
	struct process_limit_bpf *obj;
	int err = 0;
	struct rlimit rlim = {
		.rlim_cur = 512UL << 20,
		.rlim_max = 512UL << 20,
	};
	const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	int fd;

	err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err) {
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
		fprintf(stderr, "failed to parse command line arguments\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	
	obj = process_limit_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = process_limit_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object %d\n", err);
		goto cleanup;
	}

	err = process_limit_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	fd = bpf_map__fd(obj->maps.execs);

	printf("printing executed commands\n");

	while (1) {
		print_execs(fd);
		fd = bpf_map__fd(obj->maps.execs);
	}

cleanup:
	process_limit_bpf__destroy(obj);
	return err != 0;
}
