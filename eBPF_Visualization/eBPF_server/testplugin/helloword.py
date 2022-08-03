import time
def hello():
    time.sleep(1)
    print("TIME|TEXT   READ_s|INTEGER WRITE_s|INTEGER FSYNC_s|INTEGER OPEN_s|INTEGER CREATE_s|INTEGER")
    for i in range(10):
        time.sleep(1)
        print("16:49:44:      1301       14        0       14        0")
hello()
