# b = BPF(src_file="*.c")
def read_c_program(filepath):
    ret = ''
    with open(filepath, encoding='utf-8', mode='r') as f:
        ret = f.read()
    # 验证格式
    assert len(ret) != 0
    return ret
