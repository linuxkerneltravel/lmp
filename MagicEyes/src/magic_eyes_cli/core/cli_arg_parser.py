"""
    for argc parse
"""
import argparse
import argcomplete
import os
import sys
import subprocess
import multiprocessing
from core.filesystem import get_all_tools
from core.filesystem import print_all_tools

class CliArgParser:
    """
    class of commandline argc praser
    """
    def __init__(self) -> None:
        """Initialize the parser """
        self._arg_parser = argparse.ArgumentParser(
            description=''' magic_eyes_cli: command tools for Linux kernel diagnosis and optimization ''',
            add_help=True,
            epilog='''eg: magic_eyes_cli -l''')
        self._parsed_args = None
        self._setup_args()
        argcomplete.autocomplete(self._arg_parser)

    def parse_args(self, args):
        """ Parse the given arguments and return them """
        self._parsed_args = self._arg_parser.parse_args(args[:2])  # 只解析到 net net_watcher
        if self._parsed_args.list:
            print_all_tools()
        elif self._parsed_args.check:
            print("will to do in future")
        elif hasattr(self._parsed_args, 'func'):
            self._parsed_args.func(args)
        else:
            self._arg_parser.print_help()
    
    def handle_args(self, args):
        backend_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 
                                    '..', '..', 'backend')
        tool_path = os.path.join(backend_path, args[0], args[1], 'bin', args[1])
        if not os.path.exists(tool_path):
            print(f"Error: Tool {args[1]} not found in {args[0]}")
        # [tool] 后面的参数
        tool_args = args[2:]
        if (len(tool_args) == 1) and (tool_args[0] == '-h' or tool_args[0] == '--help'):
            cmd = [tool_path] + tool_args               # -h 不需要超级权限
        else:
            cmd = ['sudo'] + [tool_path] + tool_args
        try:
            subprocess.run(cmd, check=True)
        except KeyboardInterrupt:
            print("Operation was cancelled by the user.")
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            sys.exit(1)
        
    def _setup_args(self):
        # 通用参数部分，组内选项是互斥的  
        common_opts_group = self._arg_parser.add_argument_group("all of common options")
        comm_opts = common_opts_group.add_mutually_exclusive_group()
        comm_opts.add_argument(
            "-l", action='store_true', dest='list',
            help=" list all avaliable tools ")
        comm_opts.add_argument(
            "-c", action='store_true', dest='check',
            help="check all tools dependency, and whether it can be run in current platform"
        )
        subparser = self._arg_parser.add_subparsers(dest='command')
        # 获取subsystem以及下属的工具清单
        tools_lists = get_all_tools()
        for subsystem, tools in tools_lists:
            subsystem_parser = "subsystem_" + str({subsystem})
            subsystem_parser = subparser.add_parser(
                f'{subsystem}',
                help=f"tool for Linux {subsystem} subsystem"
            )
            subtool_parser = subsystem_parser.add_subparsers(dest='tools')
            for tool in tools:
                tool_parser = "tool_" + str({tool})
                tool_parser = subtool_parser.add_parser(
                    f'{tool}',
                    add_help=True,
                    help=f"tool within {subsystem}"
                )
                #tool_parser.add_argument(
                #    'tool_args', 
                #    nargs='*',
                #    help="tool all args"
                #)
                tool_parser.set_defaults(func=self.handle_args)

    def exit(self, status=os.EX_OK, message=None):
        self._arg_parser.exit(status=status, message=message)


def cpu_num():
    try:
        num = multiprocessing.cpu_count()
    except BaseException:
        num = 1
    return int(num)