# ARM64平台交叉编译工具链

## How to install aarch64-linux-gnu- compilation tools for cross-compilation？

1. install the Ubuntu toolchain gcc-aarch64-linux-gnu GNU C compiler for the arm64 architecture

``` sudo apt-get install gcc-aarch64-linux-gnu ```



2. export the environment variable ARCH and CROSS_COMPILE

``` export ARCH=arm64 && export CROSS_COMPILE=/usr/bin/aarch64-linux-gnu- ```



3. After done before installation, cmake will automatically detect the cross-compilation tools.




## What is the arm64_linux_setup.cmake？

This file is a cmake module used to set the arm64 cross-compilation environment in the cmake project.




## What is the dependency directory?

The dependency directory is used to store the dependent libraries for arm64 cross-compilation.
