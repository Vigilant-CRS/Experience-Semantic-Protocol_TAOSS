# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror

libesp_example_adapter.so: esp_example_adapter.c ../../rust/esp-rs/include/esp_neural.h
	$(CC) -shared -fPIC $(CFLAGS) -I ../../rust/esp-rs/include $< -o $@ -lm

clean:
	rm -f libesp_example_adapter.so

.PHONY: clean
