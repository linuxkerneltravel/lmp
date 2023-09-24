'''
Copyright 2023 The LMP Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

author: luiyanbing@foxmail.com

数据对象定义
'''

from json import dumps, JSONEncoder

class psid_t:
    def __init__(self, psid) -> None:
        self.pid = psid.pid
        self.ksid = psid.ksid
        self.usid = psid.usid

    def __hash__(self) -> int:
        return hash(str(self.pid)+str(self.ksid)+str(self.usid))

    def __eq__(self, other) -> bool:
        return self.pid == other.pid and self.ksid == other.ksid and self.usid == other.usid

    def __str__(self) -> str:
        return ' '.join([str(self.pid), str(self.ksid), str(self.usid)])


class MyEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, int):
            return obj.value
        else:
            return super(MyEncoder, self).default(obj)
