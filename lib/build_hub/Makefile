TEST_EXAMPLE_DIR ?= ../../eBPF_Hub/
TEST_TIME ?= 4
ECLI_DIR ?= ../../ecli/

# TODO: maybe use the compile docker to test?
.PHONY:test test_project clone_and_install_deps clean
all: test

install-deps: ## install deps
	sudo apt update
	sudo apt-get install libcurl4-openssl-dev libelf-dev clang llvm ## libgtest-dev

ecli:
	wget https://aka.pw/bpf-ecli -O ./ecli && chmod +x ./ecli

ecc:
	wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc

clone_and_install_deps: ecli ecc

# test with the files in eunomia-bpf
TEST_CASES_DIRS=$(shell ls -l ../../eBPF_Hub/ | grep ^d | awk '{print $$9}')
test: $(TEST_CASES_DIRS) ecli ecc

TEST_TIME ?= 2
ECC_BIN ?= ./ecc

.PHONY:$(TEST_CASES_DIRS)
# build the test cases
$(TEST_CASES_DIRS):
	ls $(TEST_EXAMPLE_DIR)$@/$@.h && $(ECC_BIN) $(TEST_EXAMPLE_DIR)$@/$@.bpf.c $(TEST_EXAMPLE_DIR)$@/$@.h \
	|| $(ECC_BIN) $(TEST_EXAMPLE_DIR)$@/$@.bpf.c
	sudo timeout --preserve-status -s 2 $(TEST_TIME) ./ecli run $(TEST_EXAMPLE_DIR)$@/package.json

clean:
	@make -C client clean
