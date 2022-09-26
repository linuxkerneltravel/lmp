#!/bin/python3
import sys
import os

def usage():
    print("usage: {} [-h] [observer_type]".format(sys.argv[0]))
    print()
    print("SubSystem Observability Utility")
    print()
    print("optional arguments")
    print("  %-22s show this help message and exit" % ("-h, --help", ))
    print("  %-22s run cpu observability utility" % ("cpu [options]", ))
    print("  %-22s run memory observability utility" % ("memory [options]", ))
    print("  %-22s run filesystem observability utility" % ("fs [options]", ))
    pass

if __name__ == "__main__":
    subprogramMap = {
        "cpu":      "cpu/BCC_sar/src/sar/sar.py",
        "memory":   "memory/stat.py",
        "fs":       "filesystem/fs.py"
    }
    if len(sys.argv) <= 1 or sys.argv[1] in ["-h", "--help"]:
        usage()
    else:
        if sys.argv[1] in subprogramMap:
            path = subprogramMap[sys.argv[1]]

            other_args = " "
            for i in range(2, len(sys.argv)):
                other_args = other_args + sys.argv[i]

            os.chdir(os.path.dirname(path))
            path = path.split("/")[-1]
            os.system("python3 " + path + other_args)
        else:
            print("You choose an invalid observer utility!")