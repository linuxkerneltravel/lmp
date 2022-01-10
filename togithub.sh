#!/bin/sh
# Author: Zhwen Xu<HelightXu@gmail.com>
# Created: 2022-01-05
# Description:
#

# git clone https://gitee.com/linuxkerneltravel/lmp
# git remote add github https://github.com/linuxkerneltravel/lmp
# git remote rename origin gitee

git pull gitee master
git push github master

# github to gitee
#
# git fetch github
# git merge github/master
# git push
#
