#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
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
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

	char * exe = 0;
	char * token = 0;
	char * next_token = 0;
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
		token = strtok_s(argv[0], sep, &next_token);
		exe = _strdup(token);
		while ((token = strtok_s(0, sep, &next_token)) != 0) {
			free(exe);
			exe = _strdup(token);
		}
		fprintf(stderr, "Usage: %s <input> [... input]\n", exe);
		free(exe);
	}

	return 0;
}
