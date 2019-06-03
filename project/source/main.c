#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define strdup _strdup
static char * sep = "\\";
#else
static char * sep = "/";
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha.h"

int main(int argc, char * argv[])
{
	char * exe = 0;
	char * token = 0;
	unsigned char * d = 0;

	if (argc > 1) {
		for (int i = 1; i < argc; ++i) {
			d = digest(argv[i]);

			for (int j = 0; j < 32; ++j) {
				printf("%02x", d[j]);
			}
			printf("\n");
			free(d);
		}
	} else {
		// Get executable basename
		token = strtok(argv[0], sep);
		exe = strdup(token);
		while ((token = strtok(0, sep)) != 0) {
			exe = strdup(token);
		}
		fprintf(stderr, "Usage: %s <input> [... input]\n", exe);
		free(exe);
	}

	return 0;
}
