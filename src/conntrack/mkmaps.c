#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>

#include "shared.h"


static int bpf_map_create(enum bpf_map_type type, uint32_t size_key,
                          uint32_t size_value, uint32_t max_elem,
                          uint32_t flags)
{
        union bpf_attr attr = {};

        attr.map_type = type;
        attr.key_size = size_key;
        attr.value_size = size_value;
        attr.max_entries = max_elem;
        //attr.map_flags = flags;

        return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_map_update(int fd, const void *key, const void *value,
                          uint64_t flags)
{
        union bpf_attr attr = {};

        attr.map_fd = fd;
        attr.key = (uint64_t)(key);
        attr.value = (uint64_t)(value);
        attr.flags = flags;

        return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_obj_get(const char *pathname, enum bpf_prog_type type)
{
    union bpf_attr attr = {0};
    attr.pathname = (uint64_t*)(pathname);
    return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}


static int bpf_mnt_fs(const char *target)
{
        bool bind_done = false;

        while (mount("", target, "none", MS_PRIVATE | MS_REC, NULL)) {
                if (errno != EINVAL || bind_done) {
                        fprintf(stderr, "mount --make-private %s failed: %s\n",
                                target, strerror(errno));
                        return -1;
                }

                if (mount(target, target, "none", MS_BIND, NULL)) {
                        fprintf(stderr, "mount --bind %s %s failed: %s\n",
                                target, target, strerror(errno));
                        return -1;
                }

                bind_done = true;
        }

        if (mount("bpf", target, "bpf", 0, "mode=0700")) {
                fprintf(stderr, "mount -t bpf bpf %s failed: %s\n",
                        target, strerror(errno));
                return -1;
        }

        return 0;
}

int main(int argc, char *argv[]) {
    while (0 == umount("bpf"))
        ;

    
    //mount("bpf", "/sys/fs/bpf", "bpf", 0, 0);
    bpf_mnt_fs("/sys/fs/bpf");
    mkdir("/sys/fs/bpf/tc", 0700);
    mkdir("/sys/fs/bpf/tc/globals", 0700);

    int map_fd = bpf_obj_get(argv[1], BPF_MAP_TYPE_HASH);
    if (map_fd == -1) {
        map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(struct conntrack_conf_t), 32, 0);
        union bpf_attr attr = {};
        attr.pathname = (uint64_t) argv[1];
        attr.bpf_fd = map_fd;
        if (syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr)) == -1)
            return 2;
        if (bpf_obj_get(argv[1], BPF_MAP_TYPE_HASH) == -1)
            return 3;
    }

    struct conntrack_conf_t conf = {0};
    uint32_t key = 0;
    conf.valid = true;
    
    if (bpf_map_update(map_fd, &key, &conf, 0) == -1) return 3;

    for(;;) sleep(1000);
}

