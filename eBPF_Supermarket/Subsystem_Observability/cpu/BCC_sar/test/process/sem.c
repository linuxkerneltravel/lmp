#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/sem.h>
#include <assert.h>

#define CNT 50

union semun {
    int val;
    unsigned short *array;
};

static int set_semvalue(void);
static void del_semvalue(void);
static int semaphore_p(void);
static int semaphore_v(void);

static int sem_id;

int main(int argc, char *argv[]) {
    int i, pause_time, pid;

    srand((unsigned int)getpid());

    // 初始化获取sem
    sem_id = semget((key_t) 1254, 1, 0666 | IPC_CREAT);
    assert(set_semvalue() != 0);

    pid = fork();
    if (pid) { // father
        printf("process %d(F) and %d(C) are running:\n", getpid(), pid);

        for (i = 0; i < CNT; i++) {
            semaphore_p();
            printf("F"); fflush(stdout);
            sleep(1);

            semaphore_v();
        }

        sleep(5);
        del_semvalue();
        printf("\n");
    } else {
        for (i = 0; i < CNT; i++) {
            semaphore_p();
            printf("C"); fflush(stdout);
            sleep(1);
            semaphore_v();
        }
    }
    return 0;
}

// 将信号量初始化为0
static int set_semvalue(void) {
    union semun sem_union;

    sem_union.val = 1;
    if (semctl(sem_id, 0, SETVAL, sem_union) == -1)
        return 0;
    return 1;
}

static del_semvalue(void) {
    union semun sem_union;

    if (semctl(sem_id, 0, IPC_RMID, sem_union) == -1) {
        fprintf(stderr, "Failed to delete sem.\n");
    }
}

static int semaphore_p(void) {
    struct sembuf sem_b;
    sem_b.sem_num = 0;
    sem_b.sem_op = -1;
    sem_b.sem_flg = SEM_UNDO;

    if (semop(sem_id, &sem_b, 1) == -1) {
        fprintf(stderr, "p failed.\n");
        return 0;
    }

    return 1;
}

static int semaphore_v(void) {
    struct sembuf sem_b;
    sem_b.sem_num = 0;
    sem_b.sem_op = 1;
    sem_b.sem_flg = SEM_UNDO;

    if (semop(sem_id, &sem_b, 1) == -1) {
        fprintf(stderr, "v failed.\n");
        return 0;
    }

    return 1;
}