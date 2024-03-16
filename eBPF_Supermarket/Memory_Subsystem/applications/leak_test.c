#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_ITEMS 1000
#define MAX_NAME_LENGTH 20

typedef struct {
    char name[MAX_NAME_LENGTH];
    int *data;
} Item;

static Item *create_item(const char *name, int size) {
    Item *item = (Item *)malloc(sizeof(Item));
    if (item != NULL) {
        strncpy(item->name, name, MAX_NAME_LENGTH - 1);
        item->name[MAX_NAME_LENGTH - 1] = '\0';
        item->data = (int *)malloc(size * sizeof(int));
        for (int i = 0; i < size; ++i) {
            item->data[i] = i;
        }
    }
    return item;
}

static void destroy_item(Item *item) {
    if (item != NULL) {
        free(item->data);
        free(item);
    }
}

static void *alloc_memory(const char *name, int size) {
    Item *item = create_item(name, size);
    sleep(1);
    return item->data;
}

static void process_data(int *data, int size) {
    for (int i = 0; i < size; ++i) {
        data[i] *= 2;
    }
}

int main(int argc, char *argv[]) {
    int *data_ptrs[MAX_ITEMS];
    const int alloc_size = 1000;

    for (int i = 0; ; ++i) {
        char name[MAX_NAME_LENGTH];
        snprintf(name, MAX_NAME_LENGTH, "Item_%d", i);
        data_ptrs[i] = (int *)alloc_memory(name, alloc_size);
        process_data(data_ptrs[i], alloc_size);

        sleep(2);

        if (i % 2 == 0) {
            free(data_ptrs[i]);
        }
    }

    return 0;
}
