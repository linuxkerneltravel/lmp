#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

#define QUEUE_NAME "/test_queue"
#define MSG_SIZE 50
#define MAX_MSGS 10

int main() {
    mqd_t mq;
    struct mq_attr attr;
    char msg_buffer[MSG_SIZE];
    unsigned int priority = 1;
    int i;

    // 设置消息队列属性
    attr.mq_flags = 0;
    attr.mq_maxmsg = MAX_MSGS;
    attr.mq_msgsize = MSG_SIZE;
    attr.mq_curmsgs = 0;

    // 创建或打开消息队列
    mq = mq_open(QUEUE_NAME, O_CREAT | O_WRONLY, 0644, &attr);
    if (mq == (mqd_t)-1) {
        perror("mq_open");
        exit(1);
    }

    // 发送消息
    for (i = 0;i<60 ; i++) {
        sprintf(msg_buffer, "Message %d", i);
        if (mq_send(mq, msg_buffer, strlen(msg_buffer) + 1, priority) == -1) {
            perror("mq_send");
            break;
        }
        printf("Sent: %s\n", msg_buffer);
        sleep(1);
    }

    // 关闭消息队列
    mq_close(mq);
    mq_unlink(QUEUE_NAME);

    return 0;
}
