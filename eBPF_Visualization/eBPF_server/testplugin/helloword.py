import time
def hello():
    time.sleep(1)
    print("Hello,World")
    for i in range(10):
        time.sleep(1)
        print("test -",i)
hello()
