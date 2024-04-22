import time
import os

if __name__ == "__main__":
    print(os.getpid())
    while True:
        time.sleep(0.3)
        for i in range(1000000):
            pass