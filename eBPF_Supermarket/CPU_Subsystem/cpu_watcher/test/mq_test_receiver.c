#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

#define QUEUE_NAME "/test_queue"
#define MSG_SIZE 50

int main() {
    mqd_t mq;
    char msg_buffer[MSG_SIZE];
    unsigned int priority;

    // 打开消息队列
    mq = mq_open(QUEUE_NAME, O_RDONLY);
    if (mq == (mqd_t)-1) {
        perror("mq_open");
        exit(1);
    }

    // 接收消息
    while (1) {
        if (mq_receive(mq, msg_buffer, MSG_SIZE, &priority) == -1) {
            perror("mq_receive");
            break;
        }
        printf("Received: %s\n", msg_buffer);
    }

    // 关闭消息队列
    mq_close(mq);

    return 0;
}
