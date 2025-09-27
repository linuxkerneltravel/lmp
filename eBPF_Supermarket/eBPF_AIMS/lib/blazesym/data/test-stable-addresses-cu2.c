extern unsigned int factorial(unsigned int n);

__attribute__((noinline)) static void
factorial_wrapper() {
	factorial(5);
}

void foo(void) {
	factorial_wrapper();
}
