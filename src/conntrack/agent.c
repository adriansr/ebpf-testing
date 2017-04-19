/*
 * Copyright 2017 Midokura SARL
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// see iproute2/examples/bpf/bpf_agent.c

#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include "bpf_elf.h"
#include "bpf_scm.h"
#include "shared.h"

#define min(A,B) ( (A)<(B)? (A) : (B) )

static void bpf_info_loop(int *fds, struct bpf_map_aux *aux)
{
    int i, tfd[BPF_MAP_ID_MAX];

    printf("ver: %d\nobj: %s\ndev: %lu\nino: %lu\nmaps: %u\n",
           aux->uds_ver, aux->obj_name, aux->obj_st.st_dev,
           aux->obj_st.st_ino, aux->num_ent);

    for (i = 0; i < aux->num_ent; i++) {
        printf("map%d:\n", i);
        printf(" `- fd: %u\n", fds[i]);
        printf("  | serial: %u\n", aux->ent[i].id);
        printf("  | type: %u\n", aux->ent[i].type);
        printf("  | max elem: %u\n", aux->ent[i].max_elem);
        printf("  | size key: %u\n", aux->ent[i].size_key);
        printf("  ` size val: %u\n", aux->ent[i].size_value);

        tfd[aux->ent[i].id] = fds[i];
    }
    
    // TODO: print periodical stats from other maps
}

static int bpf_map_set_recv(int fd, int *fds,  struct bpf_map_aux *aux,
                unsigned int entries)
{
    struct bpf_map_set_msg msg;
    int *cmsg_buf, min_fd, i;
    char *amsg_buf, *mmsg_buf;

    cmsg_buf = bpf_map_set_init(&msg, NULL, 0);
    amsg_buf = (char *)msg.aux.ent;
    mmsg_buf = (char *)&msg.aux;

    for (i = 0; i < entries; i += min_fd) {
        struct cmsghdr *cmsg;
        int ret;

        min_fd = min(BPF_SCM_MAX_FDS * 1U, entries - i);

        bpf_map_set_init_single(&msg, min_fd);

        ret = recvmsg(fd, &msg.hdr, 0);
        if (ret <= 0)
            return ret ? : -1;

        cmsg = CMSG_FIRSTHDR(&msg.hdr);
        if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS)
            return -EINVAL;
        if (msg.hdr.msg_flags & MSG_CTRUNC)
            return -EIO;

        min_fd = (cmsg->cmsg_len - sizeof(*cmsg)) / sizeof(fd);
        if (min_fd > entries || min_fd <= 0)
            return -1;

        memcpy(&fds[i], cmsg_buf, sizeof(fds[0]) * min_fd);
        memcpy(&aux->ent[i], amsg_buf, sizeof(aux->ent[0]) * min_fd);
        memcpy(aux, mmsg_buf, offsetof(struct bpf_map_aux, ent));

        if (i + min_fd == aux->num_ent)
            break;
    }

    return 0;
}

static int bpf_update_elem(int fd, const void *key, const void *value,
                   uint64_t flags) {
    union bpf_attr attr = {
    .map_fd = fd,
    .key    = (uint64_t)key,
    .value  = (uint64_t)value,
    .flags  = flags,
    };

    // Using syscall here as my libc doesn't have a wrapper to bpf(2)
    // as it's fairly recent
    //  return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    return syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int setup(int map_fd) {
    uint32_t key = 0;
    struct conntrack_conf_t conf = {0};
    conf.valid = true;
    conf.source_address = /*htons*/( (10 << 24) | (123 << 16) | (45 << 8) | 2);
    conf.expiration_ns = 10000000L;

    return bpf_update_elem(map_fd, &key, &conf, 0);
}


int main(int argc, char *argv[]) {
    struct sockaddr_un addr;
    struct bpf_map_aux aux;
    int ret, fd, i;
    int fds[BPF_MAP_ID_MAX];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path>\n", argv[0]);
        return 1;
    }

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Cannot open socket: %s\n", strerror(errno));
        return 2;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, argv[argc - 1], sizeof(addr.sun_path));

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        fprintf(stderr, "Cannot bind to socket: %s\n",
        strerror(errno));
        exit(1);
    }

    memset(fds, 0, sizeof(fds));
    memset(&aux, 0, sizeof(aux));

    for (i=0;i<1;++i) {
    ret = bpf_map_set_recv(fd, fds, &aux, BPF_SCM_MAX_FDS);
    
    if (ret >= 0) {
        ret = setup(fds[BPF_MAP_ID_CONF]);
        if (ret == 0) {
            bpf_info_loop(fds, &aux);
        } else {
            fprintf(stderr, "setup failed: %d %d\n", ret, errno);
        }
    }
    }

    for (i = 0; i < aux.num_ent; i++)
        close(fds[i]);
    
    close(fd);

    return 0;
}

