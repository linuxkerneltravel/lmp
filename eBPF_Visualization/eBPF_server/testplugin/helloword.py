import time
def hello():
    time.sleep(1)
    print("TIME(s)        PID         MS QUERY")
    for i in range(10):
        time.sleep(1)
        print("1.421264%d       25776  2002.183 call_getproduct(97)"%i)
hello()
