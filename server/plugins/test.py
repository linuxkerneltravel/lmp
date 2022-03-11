import threading,time

global t


def sayHello():
    print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
    time.sleep(1)

while True:
    sayHello()
# t=threading.Timer(1.0, sayHello)
# t.start()