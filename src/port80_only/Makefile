OBJ=parse_mido_80.o

LLC ?= llc
CLANG ?= clang

all: $(OBJ)

clean:
	@rm -f $(OBJ) *.llvm

.PHONY: clean verify_cmds verify_target_bpf check_headers $(CLANG) $(LLC)

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

%.c: verify_target_bpf

%.o: %.c

%.llvm: %.c
	$(CLANG) -I. \
		 -Wno-unused-value -Wno-pointer-sign \
		 -Wno-compare-distinct-pointer-types \
		 -Wno-gnu-variable-sized-type-not-at-end \
		 -Wno-address-of-packed-member -Wno-tautological-compare \
		 -O2 -emit-llvm -c $< -o $@

%.o: %.llvm
	$(LLC) -march=bpf -filetype=obj -o $@ $<
