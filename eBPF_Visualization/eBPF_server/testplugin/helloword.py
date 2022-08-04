import time
def hello():
    time.sleep(1)
    print("TIME(s)|TEXT        PID|INTEGER          MS|FLOAT QUERY|TEXT")
    for i in range(10):
        time.sleep(1)
        print("1.421264       25776  2002.183 call_getproduct(97)")
hello()
