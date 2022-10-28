#!/usr/bin/python
# fs monitoring menu

import argparse
import os

version='%(prog)s version : v0.01 '

# usage = """
# Usage: 
#     fs.py [-h] [-o] [-r] [-w] [-v] [-p] [-d]
# """

parser = argparse.ArgumentParser(
    description = "Filesystem monitoring tools",
    formatter_class = argparse.RawDescriptionHelpFormatter,
    epilog = version)

parser.add_argument("-O", "--open", action="store_true",
    help="Print all open syscall")

parser.add_argument("-R", "--read", action="store_true",
    help="Print all read syscall")

parser.add_argument("-W", "--write", action="store_true",
    help="Print all write syscall")

parser.add_argument("-V", "--vfs_func", action="store_true",
    help="Print all vfs method and counts")

parser.add_argument("-P", "--pcache", action="store_true",
    help="Print failed page cache lookups and hitting accuracy")

parser.add_argument("-D", "--dcache", action="store_true",
    help="Print failed dentry cache hitting accuracy")

parser.add_argument("-A", "--ahead", action="store_true",
    help="Print readahead information")

args = parser.parse_args()

if args.open:
    print("Tracing open syscall...")
    os.system("sudo ./tools/open.py")

if args.read:
    print("Tracing read syscall...")
    os.system("sudo ./tools/read.py")
    
if args.write:
    print("Tracing write syscall...")
    os.system("sudo ./tools/write.py")
    
if args.vfs_func:
    print("Tracing vfs functions...")
    os.system("sudo ./tools/vfs.py")
    
if args.pcache:
    print("Tracing page cache stat...")
    os.system("sudo ./tools/pcache.py")

if args.dcache:
    print("Tracing dentry cache stat...")
    os.system("sudo ./tools/dcache.py")

if args.ahead:
    print("Tracing readahead info...")
    os.system("sudo ./tools/ahead.py")

else:
    print("-h to show more")