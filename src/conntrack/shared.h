#ifndef CT_SHARED_H_INCLUDED
#define CT_SHARED_H_INCLUDED

/* Shared map identifiers and structures between BPF program and 
   userspace app 
  */

enum {
    BPF_MAP_ID_CONF,
    BPF_MAP_ID_MAX
};

struct conntrack_conf_t {
    bool     valid;
    uint32_t source_address;
};

#endif /* CT_SHARED_H_INCLUDED */
