#include <stdio.h>

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

	char * d = digest("test");

	return 0;
}
