[![pipeline](https://github.com/libbpf/blazesym/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/libbpf/blazesym/actions/workflows/test.yml)
[![rustc](https://img.shields.io/badge/rustc-1.64+-blue.svg)](https://blog.rust-lang.org/2022/09/22/Rust-1.64.0.html)

blazecli
========

**blazecli** is a command line interface for the
[**blazesym**][blazesym] library. It aims to closely mirror the
structure of the library in its command and sub-command structure.


Usage
-----
As mentioned above, the program's sub-command aim to mirror the
library's public API structure. Hence, to symbolize an address in an ELF
file -- which **blazesym** allows via the
[`symbolize::Symbolizer`][blazesym-sym] type in conjunction with the
[`Elf` source][blazesym-elf-src] -- is possible via the `symbolize elf`
sub-command:

```sh
# Just an example to illustrate symbolization on live data.
$ readelf --syms /lib64/libc.so.6 --wide | grep readdir64_r
>   2253: 00000000000caee0   228 FUNC    WEAK   DEFAULT   12 readdir64_r@@GLIBC_2.2.5

$ blazecli symbolize elf --path /lib64/libc.so.6 00000000000caee0
> 0xcaee0: readdir_r@0xcaee0+0 :0
```

To run the program from within a checkout (without any kind of
installation), you would use:
```sh
$ cargo run -p blazecli -- symbolize elf --path /lib64/libc.so.6 00000000000caee0
```

Similarly, to symbolize an address inside a process the `symbolize
process` sub-command can be used. Please refer to the program's help
text for additional details.


### Shell Completion
**blazecli** comes with shell completion support (for various shells). A
completion script can be generated via the `shell-complete` utility
program and then only needs to be sourced to make the current shell
provide context-sensitive tab completion support. E.g.,
```bash
$ cargo run --bin=shell-complete --features="clap_complete" -- bash > blazecli.bash
$ source blazecli.bash
```

The generated completion script can be installed system-wide and sourced
through initialization files, such as `~/.bashrc`.

Completion scripts for other shells work in a similar manner. Please
refer to the help text (`--help`) of the `shell-complete` program for
the list of supported shells.

[blazesym]: https://crates.io/crates/blazesym
[blazesym-sym]: https://docs.rs/blazesym/0.2.0-alpha.7/blazesym/symbolize/struct.Symbolizer.html
[blazesym-elf-src]: https://docs.rs/blazesym/0.2.0-alpha.7/blazesym/symbolize/enum.Source.html#variant.Elf
