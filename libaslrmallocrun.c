// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef LIBASLRMALLOC
#error LIBASLRMALLOC not defined
#endif

static void usage(void) {
	printf("USAGE:");
	printf("  libaslrmallocrun <PROGRAM> [ARGUMENTS]");
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		usage();
		return 1;
	}

	char *new_ld_preload = LIBASLRMALLOC;
	const char *ld_preload = getenv("LD_PRELOAD");
	if (ld_preload != NULL) {
		if (asprintf(&new_ld_preload, "%s %s", ld_preload, LIBASLRMALLOC) == -1)
			abort();
	}
	if (setenv("LD_PRELOAD", new_ld_preload, 1) != 0)
		abort();

	if (execvp(argv[1], &argv[1]) == -1) {
		printf("libaslrmallocrun: Failed to start '%s': %s\n", argv[1], strerror(errno));
		return 1;
	}
}
