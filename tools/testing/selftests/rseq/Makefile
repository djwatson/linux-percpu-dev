CFLAGS += -O2 -Wall -g -I../../../../usr/include/
LDFLAGS += -lpthread

TESTS = basic_test basic_percpu_ops_test param_test

all: $(TESTS)
%: %.c rseq.h rseq.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

include ../lib.mk

clean:
	$(RM) $(TESTS)
