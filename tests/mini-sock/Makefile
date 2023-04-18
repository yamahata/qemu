# SPDX-License-Identifier: GPL-2.0-or-later
#
# test program for qemu mini sock device backend
#
# Copyright (c) 2023 Intel Corporation
#
# Author:
#  Isaku Yamahata <isaku.yamahata@gmail.com>
#

PROGS = \
	server \
	client

CFLAGS=-Wall -g3 -D_GNU_SOURCE -MD

.PHONY: all
all: $(PROGS)

.PHONY: clean
clean:
	$(RM) *.o
	$(RM) $(PROGS)
