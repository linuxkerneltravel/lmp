#![no_std]
#![no_main]

use core::hint::black_box;


#[inline(never)]
fn uninlined_call() -> usize {
    let x = 1337;
    x + 42
}

#[inline(always)]
fn inlined_call() -> usize {
    uninlined_call()
}

#[inline(never)]
// We export the function with a *fixed* mangled form here. That is
// necessary because we rely on lookup by name, but rustc does *not*
// guarantee stable mangled symbols. Specifically, the disambiguator [0]
// can basically flip at random every time we recompile. So we just pick
// one such symbol and fix it.
// [0] https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html#free-standing-functions-and-statics
#[export_name = "_RNvCs69hjMPjVIJK_4test13test_function"]
fn test_function() -> usize {
    let x = inlined_call();
    x
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let _x = black_box(test_function());
    loop {}
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
