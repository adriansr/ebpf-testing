#ifndef CT_SHARED_H_INCLUDED
#define CT_SHARED_H_INCLUDED

/* Shared map identifiers and structures between BPF program and 
   userspace agent 
  */

enum {
    BPF_MAP_ID_CONF,
    BPF_MAP_ID_CT,
    BPF_MAP_ID_MAX
};

struct conntrack_conf_t {
    bool     valid;
    uint32_t source_address;
    uint64_t expiration_ns;
};

struct conntrack_key_t {
    uint32_t src_addr,
             dst_addr;
    uint16_t src_port,
             dst_port;
    uint8_t protocol;
};

struct conntrack_value_t {
    uint64_t last_seen;
};

#endif /* CT_SHARED_H_INCLUDED */
