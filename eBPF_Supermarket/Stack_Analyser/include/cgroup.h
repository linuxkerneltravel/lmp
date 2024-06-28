#include <stdint.h>
struct cgid_file_handle
{
    // struct file_handle handle;
    unsigned int handle_bytes;
    int handle_type;
    uint64_t cgid;
};
uint64_t get_cgroupid(const char *pathname);