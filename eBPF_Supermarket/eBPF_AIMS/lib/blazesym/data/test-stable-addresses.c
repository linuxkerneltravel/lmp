/* The sample program is used to generate test-stable-addresses*.
 *
 * Chosen functions are placed in dedicated sections to allow for control placement.
 */
extern void foo(void);

__attribute__((section(".text.factorial"))) unsigned int
factorial(unsigned int n) {
  if (n == 0)
    return 1;
  return factorial(n - 1) * n;
}

__attribute__((noinline)) static void
factorial_wrapper() {
  factorial(5);
}

__attribute__((always_inline)) static void
factorial_2nd_layer_inline_wrapper() {
  factorial(6);
}

__attribute__((always_inline)) static void
factorial_inline_wrapper() {
  factorial_2nd_layer_inline_wrapper();
}

__attribute__((section(".text.inline")))
__attribute__((noinline)) static void
factorial_inline_test() {
  factorial_inline_wrapper();
}

// A dummy function that should not actually be called. It just contains a bunch
// of signature bytes that we use for offset verification later on.
asm(
  ".globl dummy\n"
  ".type dummy, @function\n"
  "dummy:\n"
  ".byte 0xde\n"
  ".byte 0xad\n"
  ".byte 0xbe\n"
  ".byte 0xef\n"
);

extern void dummy(void);

__attribute__((section(".text.main"))) int
main(int argc, const char *argv[]) {
  factorial_wrapper();
  factorial_inline_test();
  foo();
  dummy();
  return 0;
}
