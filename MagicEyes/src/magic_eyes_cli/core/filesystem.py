"""part of file system handle like files, directories and paths """

import logging
import os
import shutil


LOGGER = logging.getLogger(__name__)


def delete_file_or_directory(path, ignore_errors=False, log_function=LOGGER.debug):
    """
    Used as a universal delete function. Also deletes non-empty directories recursively.

    Args:
        path (str): Path to the file or directory to be deleted

    Keyword Args:
        ignore_errors (bool): Catches and ignores the exceptions if True
        log_function (Callable): Log messages will be passed to this callable

    Returns:
        bool: True if file or directory is removed
              False if an exception occurred during deletion or the file/directory does not exist
    """
    logger = log_function or (lambda *x: None)
    result = False

    try:
        if os.path.isfile(path):
            logger("Deleting file %s", path)
            os.remove(path)
            result = True
        elif os.path.isdir(path):
            logger("Deleting directory %s", path)
            shutil.rmtree(path)
            result = True
        else:
            logger("The path %s does not exist", path)
    except BaseException:
        if not ignore_errors:
            logger("Error during deletion of %s", path)
            raise

    return result


def write_to_file(filepath, file_content):
    """
    Writes file_content to the file in filepath. Creates directories for filepath if they do not already exist.
    Overwrites the file in filepath if it already exists.

    Args:
        filepath (str): Path to the file
        file_content (str | list): If it is of str type, it is directly written to the file,
            if it is of list type, each element is converted to str and written to the file separeted by a newline
    """
    file_directory = os.path.dirname(filepath)
    if file_directory and not os.path.isdir(file_directory):
        os.makedirs(file_directory)

    with open(filepath, 'w') as file_:
        if isinstance(file_content, list):
            file_.write("\n".join(file_content))
        else:
            file_.write(str(file_content))


# 列出所有子系统以及子系统下属的所有工具
def get_all_tools():
    backend_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 
                                '..', '..' ,'backend')
    if not os.path.isdir(backend_path):
        print("invalid path")
        return []
    tools_lists = []
    # 遍历backend目录下的所有文件和文件夹
    for item in os.listdir(backend_path):
        item_path = os.path.join(backend_path, item)
        if os.path.isdir(item_path):
            # 添加子系统
            tools_lists.append([item, []])
            # 添加子系统下的工具
            for sub_item in os.listdir(item_path):
                sub_item_path = os.path.join(item_path, sub_item)
                if os.path.isdir(sub_item_path):
                    tools_lists[-1][1].append(sub_item)
    return tools_lists


def print_all_tools():
    print("list all avaliable tools:")
    tools_lists = get_all_tools()
    for subsystem, tools in tools_lists:
        print(f"{' '.ljust(2)}[{subsystem}]")
        for tool in tools:
            print(f"{' '.ljust(8)}{tool}")
        print()

