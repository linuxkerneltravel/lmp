# Copyright 2023 The LMP Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: jinyufeng2000@gmail.com
#
# Test script

#!/bin/bash

set -e

TEST_DIR="$(dirname $(readlink -f $0))"
UTRACE="$TEST_DIR/../build/utrace"

for file in $TEST_DIR/*; do
  lib=""
  if [[ $file == *thread* ]]; then
    lib=" -pthread"
  fi
  if [[ $file == *.c ]]; then
    gcc $file $lib
    echo "test $file using gcc"
    sudo $UTRACE -c a.out
    clang $file $lib
    echo "test $file using clang"
    sudo $UTRACE -c a.out
  elif [[ $file == *.cpp ]]; then
    g++ $file
    echo "test $file using g++"
    sudo $UTRACE -c a.out -o /dev/null
    clang++ $file
    echo "test $file using clang++"
    sudo $UTRACE -c a.out -o /dev/null
  fi
  break
done

rm -f a.out
