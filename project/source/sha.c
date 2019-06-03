#include "sha.h"

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <winsock.h>

#define SHA_ADD(x, y) ((x + y) % pow(2, 32))
#define SHA_SHR(x, n) (x >> n)
#define SHA_ROTR(x, n) ((x >> n) | (x << (32 - n)))

#define SHA_CH(x, y, z) ((x & y) ^ (~x & z))
#define SHA_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA_BIGMA_0_256(x) (SHA_ROTR(x, 02) ^ SHA_ROTR(x, 13) ^ SHA_ROTR(x, 22))
#define SHA_BIGMA_1_256(x) (SHA_ROTR(x, 06) ^ SHA_ROTR(x, 11) ^ SHA_ROTR(x, 25))
#define SHA_SIGMA_0_256(x) (SHA_ROTR(x, 07) ^ SHA_ROTR(x, 18) ^ SHA_SHR(x, 03))
#define SHA_SIGMA_1_256(x) (SHA_ROTR(x, 17) ^ SHA_ROTR(x, 19) ^ SHA_SHR(x, 10))

#define htonll(x) ((1 == htonl(1)) ? (x) : ((uint64_t) htonl((x) &0xFFFFFFFF) << 32) | htonl((x) >> 32))

typedef struct sha_variables_t
{
	uint32_t k[64];  // K constants.
	uint32_t h[8];   // H constants.
} sha_variables_t;

static void populate_sha_constants(sha_variables_t * constants);
static void sha_encrypt(const char * message, sha_variables_t * c);
static inline uint64_t bit_size(const char * message);
static inline uint64_t block_size(const char * message);

char * digest(const char * message)
{
	sha_variables_t c;
	char * digest = 0;

	// Populate K and H constants
	populate_sha_constants(&c);

	// Encrypt message
	sha_encrypt(message, &c);

	// Return digest
	digest = (char *) malloc(32);
	for (int i = 0; i < 8; ++i) {
		c.h[i] = htonl(c.h[i]);
	}
	memcpy(digest + 0x00, &c.h[0], 4);
	memcpy(digest + 0x04, &c.h[1], 4);
	memcpy(digest + 0x08, &c.h[2], 4);
	memcpy(digest + 0x0C, &c.h[3], 4);
	memcpy(digest + 0x10, &c.h[4], 4);
	memcpy(digest + 0x14, &c.h[5], 4);
	memcpy(digest + 0x18, &c.h[6], 4);
	memcpy(digest + 0x1C, &c.h[7], 4);

	return digest;
}

static inline uint64_t bit_size(const char * message)
{
	return (message ? (uint64_t)(strlen(message) * 8) : 0);
}

static inline uint64_t block_size(const char * message)
{
	return (message ? (uint64_t) ceil((bit_size(message) + 65.0) / 512) : 0);
}

static void generate_prime_numbers(uint32_t * arr, uint32_t n)
{
	int i = 2;
	char flag;

	if (arr) {
		// Find primes up to n.
		for (uint32_t count = 0; count < n;) {
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
	static char initialized = 0;
	uint32_t primes[64];
	double temp;

	// Calculating prime numbers and their cube roots takes a lot of time; only do it if it hasn't been done
	// already.
	if (!initialized) {
		generate_prime_numbers(primes, 64);
		for (int i = 0; i < 64; ++i) {
			temp = cbrt((double) primes[i]);  // Cube root of prime number.
			temp = fmod(temp, 1);             // Modulus by 1 to get rid of whole value.
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

static void populate_sha_constants(sha_variables_t * c)
{
	generate_k_constants(c->k);
	generate_h_constants(c->h);
}

static char * form_message(const char * message)
{
	const char * border = "\x80\n";  // (1<<7)
	char * formed_message = 0;
	uint64_t message_size;
	uint64_t blocks;
	uint64_t l;

	// Calculate number of 512-bit blocks
	if ((blocks = block_size(message)) > 0) {

		l = bit_size(message);

		// Allocate memory for padded message
		message_size = blocks * 64 * sizeof(char) + 1;
		formed_message = (char *) malloc(message_size);
		memset(formed_message, 0, message_size);

		/*
		| 512-bits message | ... | n-bits message | 1 | zero padding 'k' | length in bits 'l' |
		*/

		// Copy message to padded string
		strcpy_s(formed_message, message_size, message);

		// Characters are byte aligned; will always have 0x80 after message field
		strcat_s(formed_message, message_size, border);

		// Insert length value at the end of the padded message
		for (int i = 7; i >= 0; --i) {
			formed_message[blocks * 64 - i - 1] = (l & (0xFF << (i * 8))) >> (i * 8);
		}
	}

	return formed_message;
}

void sha_encrypt(const char * message, sha_variables_t * constants)
{
	uint64_t blocks;
	char * formed_message;
	char(*chunks)[64];
	uint32_t words[64];
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t T1, T2;

	if (message) {
		// Form message to digest (insert padding, length bits, etc.)
		formed_message = form_message(message);

		// Slice message into 512-bit chunks
		blocks = block_size(message);
		chunks = ((char(*)[64]) malloc(sizeof(char) * 64 * blocks));
		memset(chunks, 0, sizeof(char) * 64 * blocks);

		for (int i = 0; i < blocks; ++i) {
			strncpy_s(chunks[i], 64, &formed_message[i * 64], 64);
		}

		for (int i = 0; i < blocks; ++i) {
			// Clear words
			memset(words, 0, sizeof(words));

			// 1. Prepare the message schedule.
			memcpy(words, chunks[i], 64);
			for (int j = 16; j < 64; ++j) {
				words[j] = SHA_SIGMA_1_256(words[j - 2]) + words[j - 7] +
				           SHA_SIGMA_0_256(words[j - 15]) + words[j - 16];
			}

			// 2. Initialize eight working variables with the (i-1)st hash values.
			a = constants->h[0];
			b = constants->h[1];
			c = constants->h[2];
			d = constants->h[3];
			e = constants->h[4];
			f = constants->h[5];
			g = constants->h[6];
			h = constants->h[7];

			// 3. For t=0 to 63
			for (int j = 0; j < 64; ++j) {
				T1 = h + SHA_BIGMA_1_256(e) + SHA_CH(e, f, g) + constants->k[j] + words[j];
				T2 = SHA_BIGMA_0_256(a) + SHA_MAJ(a, b, c);
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
			}

			// 4. Compute the i-th intermediate hash value H
			constants->h[0] += a;
			constants->h[1] += b;
			constants->h[2] += c;
			constants->h[3] += d;
			constants->h[4] += e;
			constants->h[5] += f;
			constants->h[6] += g;
			constants->h[7] += h;
		}

		free(chunks);
	}
}
