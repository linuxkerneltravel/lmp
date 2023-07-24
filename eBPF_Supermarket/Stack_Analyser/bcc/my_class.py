
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
