from prometheus_client import start_http_server, Summary
from prometheus_client import Counter, Histogram, Enum, Info
import random
import time
# 此程序用于暴露数据接口，以供Prometheus定时抓取数据。
# 数据的形式可以自定义，有直方图、Counter、Enum、Info等记录方式
# 详情请查看https://github.com/prometheus/client_python (prometheus Python客户端的ReadME页面)

# Create a metric to track time spent and requests made.
REQUEST_TIME = Histogram('request_processing_seconds', 'Time spent processing request')
c = Counter('my_failures', 'Description of counter')
c.inc()     # Increment by 1
c.inc(1.6)  # Increment by given value

e = Enum('my_task_state', 'Description of enum',
        states=['starting', 'running', 'stopped'])
# e.state('running')

i = Info('DNSCache', 'DNS Cache Content')
i.info({'Cache': str(["baidu", "google"])})

# Decorate function with metric.
def process_request(t):
    e.state("running")
    i.info({'Cache': str(["baidu", "google", "bing"])})
    """A dummy function that takes some time."""
    time.sleep(t)
    label = "little"
    if t > 0.5:
        label = "big"
    REQUEST_TIME.observe(t, {'trace_id': label})
    i.info({'Cache': str(["baidu", "google", "aliyun"])})
    e.state("stopped")

if __name__ == '__main__':
    # Start up the server to expose the metrics. Set port here.
    start_http_server(8000)
    # Generate some requests.
    while True:
        process_request(random.random())
        time.sleep(1)