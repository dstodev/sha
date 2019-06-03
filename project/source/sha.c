#include "sha.h"

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SHA_ADD(x, y) ((x + y) % 4294967296)
#define SHA_SHR(x, n) (x >> n)
#define SHA_ROTR(x, n) ((x >> n) | (x << (32 - n)))

#define SHA_CH(x, y, z) ((x & y) ^ (~x & z))
#define SHA_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA_BIGMA_0_256(x) (SHA_ROTR(x, 02) ^ SHA_ROTR(x, 13) ^ SHA_ROTR(x, 22))
#define SHA_BIGMA_1_256(x) (SHA_ROTR(x, 06) ^ SHA_ROTR(x, 11) ^ SHA_ROTR(x, 25))
#define SHA_SIGMA_0_256(x) (SHA_ROTR(x, 07) ^ SHA_ROTR(x, 18) ^ SHA_SHR(x, 03))
#define SHA_SIGMA_1_256(x) (SHA_ROTR(x, 17) ^ SHA_ROTR(x, 19) ^ SHA_SHR(x, 10))

typedef struct sha_variables_t
{
	uint32_t k[64];  // K constants.
	uint32_t h[8];   // H variables.
} sha_variables_t;

static void populate_sha_constants(sha_variables_t * constants);
static void sha_hash(const char * message, sha_variables_t * c);

unsigned char * digest(const char * message)
{
	sha_variables_t c;
	unsigned char * hash = 0;

	if (message) {
		// Populate K and H constants
		populate_sha_constants(&c);

		// Apply hash algorithm
		sha_hash(message, &c);

		// Append all calculated H variables
		hash = (unsigned char *) malloc(32);
		for (int i = 0; i < 8; ++i) {
			hash[i * 4 + 0] = (unsigned char) ((c.h[i] & (0xFF << 24)) >> 24);
			hash[i * 4 + 1] = (unsigned char) ((c.h[i] & (0xFF << 16)) >> 16);
			hash[i * 4 + 2] = (unsigned char) ((c.h[i] & (0xFF << 8)) >> 8);
			hash[i * 4 + 3] = (unsigned char) (c.h[i] & (0xFF));
		}

		// Return hash digest
	}

	return hash;
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
		generate_prime_numbers(primes, sizeof(primes) / sizeof(uint32_t));
		for (int i = 0; i < sizeof(primes) / sizeof(uint32_t); ++i) {
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
		for (int i = 0; i < sizeof(k) / sizeof(uint32_t); ++i) {
			arr[i] = k[i];
		}
	}
}

static void initialize_h_variables(uint32_t * arr)
{
	/* Array size must be 8 (there are 8 'h' variables) */

	static uint32_t h[8];
	static char initialized = 0;
	uint32_t primes[8];
	double temp;

	// Calculating prime numbers and their square roots takes a lot of time; only do it if it hasn't been done
	// already.
	if (!initialized) {
		generate_prime_numbers(primes, sizeof(primes) / sizeof(uint32_t));
		for (int i = 0; i < sizeof(primes) / sizeof(uint32_t); ++i) {
			temp = sqrt((double) primes[i]);  // Cube root of prime number.
			temp = fmod(temp, 1);             // Modulus by 1 to get rid of whole value.
			temp *= pow(2, 32);  // Multiply by 2^32 to get the first 32 bits of the fractional component as
			                     // a whole value.
			temp = floor(temp);  // Keep only the whole value.
			h[i] = (uint32_t) temp;  // Store the value.
		}
		initialized = 1;
	}

	if (arr) {
		for (int i = 0; i < sizeof(h) / sizeof(uint32_t); ++i) {
			arr[i] = h[i];
		}
	}
}

static void populate_sha_constants(sha_variables_t * c)
{
	generate_k_constants(c->k);
	initialize_h_variables(c->h);
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
		message_size = blocks * 64 * sizeof(char);
		formed_message = (char *) malloc(message_size);
		memset(formed_message, 0, message_size);

		/*
		| 512-bits message | ... | n-bits message | 1 | zero padding 'k' | length in bits 'l' |
		*/

		// Copy message to padded string
		memcpy(formed_message, message, strlen(message));

		// Characters are byte aligned; will always have 0x80 after message field
		memcpy(formed_message + strlen(message), border, 1);

		// Insert length value at the end of the padded message
		// memcpy(formed_message + (blocks * 64) - 8, &l, 8);
		for (int i = 7; i >= 0; --i) {
			formed_message[blocks * 64 - i - 1] = (l & (0xFF << (i * 8))) >> (i * 8);
		}
	}

	return formed_message;
}

void sha_hash(const char * message, sha_variables_t * constants)
{
	uint64_t blocks;
	char * formed_message;
	unsigned char(*chunks)[64];
	uint32_t words[64];
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t T1, T2;

	if (message) {
		// Form message to digest (insert padding, length bits, etc.)
		formed_message = form_message(message);

		// Slice message into 512-bit chunks
		blocks = block_size(message);
		chunks = ((unsigned char(*)[64]) malloc(sizeof(unsigned char) * 64 * blocks));
		memset(chunks, 0, sizeof(unsigned char) * 64 * blocks);

		for (int i = 0; i < blocks; ++i) {
			memcpy(chunks[i], formed_message + (i * 64), 64);
		}

		for (int i = 0; i < blocks; ++i) {
			// Clear words
			memset(words, 0, sizeof(words));

			// 1. Prepare the message schedule.
			for (int j = 0; j < 16; ++j) {
				words[j] = chunks[i][j * 4] << 24 | chunks[i][j * 4 + 1] << 16 |
				           chunks[i][j * 4 + 2] << 8 | chunks[i][j * 4 + 3];
			}
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
			constants->h[0] = SHA_ADD(a, constants->h[0]);
			constants->h[1] = SHA_ADD(b, constants->h[1]);
			constants->h[2] = SHA_ADD(c, constants->h[2]);
			constants->h[3] = SHA_ADD(d, constants->h[3]);
			constants->h[4] = SHA_ADD(e, constants->h[4]);
			constants->h[5] = SHA_ADD(f, constants->h[5]);
			constants->h[6] = SHA_ADD(g, constants->h[6]);
			constants->h[7] = SHA_ADD(h, constants->h[7]);
		}

		free(chunks);
	}
}
