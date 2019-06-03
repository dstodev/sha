#include <stdio.h>
#include <stdlib.h>

#include "sha.h"

int main(int argc, char * argv[])
{
	if (argc > 1) {
		printf("Parameters:\n");
		for (int i = 1; i < argc; ++i) {
			printf("%d. %s\n", i, argv[i]);
		}
		printf("\n");
	}

	unsigned char * d = digest("test");

	for (int i = 0; i < 32; ++i) {
		printf("%02x ", d[i]);
	}

	free(d);

	return 0;
}
