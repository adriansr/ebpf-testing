BPF_TARGET=bpf_conntrack
AGENT_TARGET=agent

LLC ?= llc
CLANG ?= clang

all: $(BPF_TARGET).o $(AGENT_TARGET)

clean:
	@rm -f *.o *.llvm $(BPF_TARGET) $(AGENT_TARGET)

.PHONY: clean verify_cmds verify_target_bpf check_headers $(CLANG) $(LLC)

$(AGENT_TARGET): $(AGENT_TARGET).o
	$(CC) $< -o $@

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
                if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
                        echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
                        exit 1; \
                else true; fi; \
        done

verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
                echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
                echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
                exit 2; \
        else true; fi

$(BPF_TARGET).c: verify_target_bpf

$(BPF_TARGET).llvm: $(BPF_TARGET).c
	$(CLANG) -I. \
		 -Wno-unused-value -Wno-pointer-sign \
		 -Wno-compare-distinct-pointer-types \
		 -Wno-gnu-variable-sized-type-not-at-end \
		 -Wno-address-of-packed-member -Wno-tautological-compare \
		 -O2 -emit-llvm -c $< -o $@

$(BPF_TARGET).o: $(BPF_TARGET).llvm
	$(LLC) -march=bpf -filetype=obj -o $@ $<
