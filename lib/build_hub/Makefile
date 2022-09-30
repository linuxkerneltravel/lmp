TEST_EXAMPLE_DIR ?= ../../eBPF_Hub/
TEST_TIME ?= 4
ECLI_DIR ?= ../../ecli/

# TODO: maybe use the compile docker to test?
.PHONY:test test_project clone_and_install_deps clean
all: test

install-deps: ## install deps
	apt update
	apt-get install libcurl4-openssl-dev libelf-dev clang llvm ## libgtest-dev

clone_and_install_deps:
	rm -rf ./eunomia-cc ./ecli
	git clone https://github.com/eunomia-bpf/eunomia-cc --recursive --depth=1	# checkout the newest toolchain
	make -C eunomia-cc
	wget https://aka.pw/bpf-ecli -O ./ecli && chmod +x ./ecli

# test with the files in eunomia-bpf
TEST_CASES_DIRS=$(shell ls -l ../../eBPF_Hub/ | grep ^d | awk '{print $$9}')
test: $(TEST_CASES_DIRS)

.PHONY:$(TEST_CASES_DIRS)
# build the test cases
$(TEST_CASES_DIRS):
	SOURCE_DIR=../../../eBPF_Hub/$@/ make -C eunomia-cc build ; true
	# sudo timeout --preserve-status -s 2 $(TEST_TIME) ./ecli run ../../eBPF_Hub/$@/package.json

clean:
	@make -C client clean
