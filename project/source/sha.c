#include "sha.h"

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SHA_ADD(x, y) ((x + y) % pow(2, 32));
#define SHA_SHR(x, n) (x >> n);
#define SHA_ROTR(x, n) ((x >> n) | (x << (32 - n)));

#define SHA_CH(x, y, z) ((x & y) ^ (~x & z));
#define SHA_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z));
#define SHA_BIGMA_0_256(x) (SHA_ROTR(x, 02) ^ SHA_ROTR(x, 13) ^ SHA_ROTR(x, 22));
#define SHA_BIGMA_1_256(x) (SHA_ROTR(x, 06) ^ SHA_ROTR(x, 11) ^ SHA_ROTR(x, 25));
#define SHA_SIGMA_0_256(x) (SHA_ROTR(x, 07) ^ SHA_ROTR(x, 18) ^ SHA_SHR(x, 03));
#define SHA_SIGMA_1_256(x) (SHA_ROTR(x, 17) ^ SHA_ROTR(x, 19) ^ SHA_SHR(x, 10));

typedef struct sha_constants_t
{
	uint32_t k[64];  // K constants.
	uint32_t h[8];   // H constants.

} sha_constants_t;

static void populate_sha_constants(sha_constants_t * c);

char * digest(const char * message)
{
	const char * border = "\x80\n";  // (1<<7)
	char * padded_message;
	size_t message_size;
	sha_constants_t c;
	uint64_t blocks;
	uint64_t l;

	// Populate K and H constants
	populate_sha_constants(&c);

	// Calculate size l of message in bits
	l = (uint64_t) strlen(message) * 8;

	// Calculate number of 512-bit blocks
	if ((blocks = (uint64_t) ceil((l + 65.0) / 512)) > 0) {

		// Allocate memory for padded message
		message_size = blocks * 64 * sizeof(char) + 1;
		padded_message = malloc(message_size);
		memset(padded_message, 0, message_size);

		/*
		| 512-bits message | ... | n-bits message | 1 | zero padding 'k' | length in bits 'l' |
		*/

		// Copy message to padded string
		strcpy_s(padded_message, message_size, message);

		// Characters are byte aligned; will always have 0x80 after message field
		strcat_s(padded_message, message_size, border);

		// Insert length value at the end of the padded message
		for (int i = 7; i >= 0; --i) {
			padded_message[blocks * 64 - i - 1] = (l & (0xFF << (i * 8))) >> (i * 8);
		}
	}

	return 0;
}

static void generate_prime_numbers(unsigned int * arr, unsigned int n)
{
	int i = 2;
	char flag;

	if (arr) {
		// Find primes up to n.
		for (unsigned int count = 0; count <= n;) {
			flag = 1;
			for (int j = 2; j <= sqrt(i); ++j) {
				if (i % j == 0) {
					flag = 0;
					break;
				}
			}
			if (flag) {
				arr[count++] = i;
			}
			++i;
		}
	}
}

static void generate_k_constants(uint32_t * arr)
{
	/* Array size must be 64 (there are 64 'k' constants) */

	static uint32_t k[64];
	uint32_t primes[64];
	double temp;
	char initialized = 0;

	// Calculating prime numbers and their cube roots takes a lot of time; only do it if it hasn't been done
	// already.
	if (!initialized) {
		generate_prime_numbers(primes, 64);
		for (int i = 0; i < 64; ++i) {
			temp = cbrt(primes[i]);  // Cube root of prime number.
			temp = fmod(temp, 1);    // Modulus by 1 to get rid of whole value.
			temp *= pow(2, 32);  // Multiply by 2^32 to get the first 32 bits of the fractional component as
			                     // a whole value.
			temp = floor(temp);  // Keep only the whole value.
			k[i] = (uint32_t) temp;  // Store the value.
		}
		initialized = 1;
	}

	if (arr) {
		for (int i = 0; i < 64; ++i) {
			arr[i] = k[i];
		}
	}
}

static void generate_h_constants(uint32_t * arr)
{
	/* Array size must be 8 (there are 8 'h' constants) */

	// Initial 'h' constants aren't calculable.
	arr[0] = 0x6a09e667;
	arr[1] = 0xbb67ae85;
	arr[2] = 0x3c6ef372;
	arr[3] = 0xa54ff53a;
	arr[4] = 0x510e527f;
	arr[5] = 0x9b05688c;
	arr[6] = 0x1f83d9ab;
	arr[7] = 0x5be0cd19;
}

static void populate_sha_constants(sha_constants_t * c)
{
	generate_k_constants(c->k);
	generate_h_constants(c->h);
}
