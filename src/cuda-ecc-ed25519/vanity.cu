#include <vector>
#include <random>
#include <chrono>

#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>

#include "curand_kernel.h"
#include "ed25519.h"
#include "fixedint.h"
#include "gpu_common.h"
#include "gpu_ctx.h"

#include "keypair.cu"
#include "sc.cu"
#include "fe.cu"
#include "ge.cu"
#include "sha512.cu"
#include "../config.h"

/* -- Types ----------------------------------------------------------------- */

typedef struct {
	// CUDA Random States.
	curandState*    states[8];
} config;

/* -- Prototypes, Because C++ ----------------------------------------------- */

void            vanity_setup(config& vanity);
void            vanity_run(config& vanity);
void __global__ vanity_init(curandState* state);
void __global__ vanity_scan(curandState* state);
bool __device__ b58enc(char* b58, size_t* b58sz, uint8_t* data, size_t binsz);

/* -- Entry Point ----------------------------------------------------------- */

int main(int argc, char const* argv[]) {
	ed25519_set_verbose(true);

	config vanity;
	vanity_setup(vanity);
	vanity_run(vanity);
}

/* -- Vanity Step Functions ------------------------------------------------- */

void vanity_setup(config &vanity) {
	printf("GPU: Initializing Memory\n");
	int gpuCount = 0;
	cudaGetDeviceCount(&gpuCount);

	// Create random states so kernels have access to random generators
	// while running in the GPU.
	for (int i = 0; i < gpuCount; ++i) {
		cudaSetDevice(i);

		// Fetch Device Properties
		cudaDeviceProp device;
		cudaGetDeviceProperties(&device, i);

		// Calculate Occupancy
		int blockSize       = 0,
		    minGridSize     = 0,
		    maxActiveBlocks = 0;
		cudaOccupancyMaxPotentialBlockSize(&minGridSize, &blockSize, vanity_init, 0, 0);
		cudaOccupancyMaxActiveBlocksPerMultiprocessor(&maxActiveBlocks, vanity_init, blockSize, 0);

		// Output Device Details
		// 
		// Our kernels currently don't take advantage of data locality
		// or how warp execution works, so each thread can be thought
		// of as a totally independent thread of execution (bad). On
		// the bright side, this means we can really easily calculate
		// maximum occupancy for a GPU because we don't have to care
		// about building blocks well. Essentially we're trading away
		// GPU SIMD ability for standard parallelism, which CPUs are
		// better at and GPUs suck at.
		//
		// Next Weekend Project: ^ Fix this.
		printf("GPU: (%s <%d, %d, %d>) -- W: %d, P: %d, TPB: %d, MTD: (%dx, %dy, %dz), MGS: (%dx, %dy, %dz)\n",
			device.name,
			blockSize,
			minGridSize,
			maxActiveBlocks,
			device.warpSize,
			device.multiProcessorCount,
		       	device.maxThreadsPerBlock,
			device.maxThreadsDim[0],
			device.maxThreadsDim[1],
			device.maxThreadsDim[2],
			device.maxGridSize[0],
			device.maxGridSize[1],
			device.maxGridSize[2]
		);

		cudaMalloc((void **)&(vanity.states[i]), 4 * 512 * sizeof(curandState));
		vanity_init<<<maxActiveBlocks, blockSize>>>(vanity.states[i]);
	}

	printf("END: Initializing Memory\n");
}

void vanity_run(config &vanity) {
	int gpuCount = 0;
	cudaGetDeviceCount(&gpuCount);

	for (int i = 0; i < 1024; ++i) {
		auto start  = std::chrono::high_resolution_clock::now();

		// Run on all GPUs
		for (int i = 0; i < gpuCount; ++i) {
			cudaSetDevice(i);
			// Calculate Occupancy
			int blockSize       = 0,
			    minGridSize     = 0,
			    maxActiveBlocks = 0;
			cudaOccupancyMaxPotentialBlockSize(&minGridSize, &blockSize, vanity_scan, 0, 0);
			cudaOccupancyMaxActiveBlocksPerMultiprocessor(&maxActiveBlocks, vanity_scan, blockSize, 0);
			printf("GPU: <%d, %d, %d> vanity_scan\n", blockSize, minGridSize, maxActiveBlocks);
			vanity_scan<<<maxActiveBlocks, blockSize>>>(vanity.states[i]);
		}

		// Synchronize while we wait for kernels to complete. I do not
		// actually know if this will sync against all GPUs, it might
		// just sync with the last `i`, but they should all complete
		// roughly at the same time and worst case it will just stack
		// up kernels in the queue to run.
		cudaDeviceSynchronize();
		auto finish = std::chrono::high_resolution_clock::now();

		// Print out performance Summary
		std::chrono::duration<double> elapsed = finish - start;
		printf("Attempts: %d in %f at %fcps\n",
			(8 * 8 * 256 * 100000),
			elapsed.count(),
			(8 * 8 * 256 * 100000) / elapsed.count()
		);
	}
}

/* -- CUDA Vanity Functions ------------------------------------------------- */

void __global__ vanity_init(curandState* state) {
	int id = threadIdx.x + (blockIdx.x * blockDim.x);
	curand_init(580000+id, id, 0, &state[id]);
}

void __global__ vanity_scan(curandState* state) {
	int id = threadIdx.x + (blockIdx.x * blockDim.x);

	// Local Kernel State
	ge_p3 A;
	curandState localState     = state[id];
	unsigned char seed[32]     = {0};
	unsigned char publick[32]  = {0};
	unsigned char privatek[64] = {0};
	char key[256]              = {0};
	char pkey[256]             = {0};

	// Start from an Initial Random Seed (Slow)
	// NOTE: Insecure random number generator, do not use keys generator by
	// this program in live.
	for (int i = 0; i < 32; ++i) {
		float random    = curand_uniform(&localState);
		uint8_t keybyte = (uint8_t)(random * 255);
		seed[i]         = keybyte;
	}

	// Generate Random Key Data
	size_t keys_found = 0;
	sha512_context md;

	// I've unrolled all the MD5 calls and special cased them to 32 byte
	// inputs, which eliminates a lot of branching. This is a pretty poor
	// way to optimize GPU code though.
	//
	// A better approach would be to split this application into two
	// different kernels, one that is warp-efficient for SHA512 generation,
	// and another that is warp efficient for bignum division to more
	// efficiently scan for prefixes. Right now bs58enc cuts performance
	// from 16M keys on my machine per second to 4M.
	for (int attempts = 0; attempts < 100000; ++attempts) {
		// sha512_init Inlined
		md.curlen   = 0;
		md.length   = 0;
		md.state[0] = UINT64_C(0x6a09e667f3bcc908);
		md.state[1] = UINT64_C(0xbb67ae8584caa73b);
		md.state[2] = UINT64_C(0x3c6ef372fe94f82b);
		md.state[3] = UINT64_C(0xa54ff53a5f1d36f1);
		md.state[4] = UINT64_C(0x510e527fade682d1);
		md.state[5] = UINT64_C(0x9b05688c2b3e6c1f);
		md.state[6] = UINT64_C(0x1f83d9abfb41bd6b);
		md.state[7] = UINT64_C(0x5be0cd19137e2179);

		// sha512_update inlined
		// 
		// All `if` statements from this function are eliminated if we
		// will only ever hash a 32 byte seed input. So inlining this
		// has a drastic speed improvement on GPUs.
		//
		// This means:
		//   * Normally we iterate for each 128 bytes of input, but we are always < 128. So no iteration.
		//   * We can eliminate a MIN(inlen, (128 - md.curlen)) comparison, specialize to 32, branch prediction improvement.
		//   * We can eliminate the in/inlen tracking as we will never subtract while under 128
		//   * As a result, the only thing update does is copy the bytes into the buffer.
		const unsigned char *in = seed;
		for (size_t i = 0; i < 32; i++) {
			md.buf[i + md.curlen] = in[i];
		}
		md.curlen += 32;


		// sha512_final inlined
		// 
		// As update was effectively elimiated, the only time we do
		// sha512_compress now is in the finalize function. We can also
		// optimize this:
		//
		// This means:
		//   * We don't need to care about the curlen > 112 check. Eliminating a branch.
		//   * We only need to run one round of sha512_compress, so we can inline it entirely as we don't need to unroll.
		md.length += md.curlen * UINT64_C(8);
		md.buf[md.curlen++] = (unsigned char)0x80;

		while (md.curlen < 120) {
			md.buf[md.curlen++] = (unsigned char)0;
		}

		STORE64H(md.length, md.buf+120);

		// Inline sha512_compress
		uint64_t S[8], W[80], t0, t1;
		int i;

		/* Copy state into S */
		for (i = 0; i < 8; i++) {
			S[i] = md.state[i];
		}

		/* Copy the state into 1024-bits into W[0..15] */
		for (i = 0; i < 16; i++) {
			LOAD64H(W[i], md.buf + (8*i));
		}

		/* Fill W[16..79] */
		for (i = 16; i < 80; i++) {
			W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
		}

		/* Compress */
		#define RND(a,b,c,d,e,f,g,h,i) \
		t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]; \
		t1 = Sigma0(a) + Maj(a, b, c);\
		d += t0; \
		h  = t0 + t1;

		for (i = 0; i < 80; i += 8) {
			RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i+0);
			RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],i+1);
			RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],i+2);
			RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],i+3);
			RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],i+4);
			RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],i+5);
			RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],i+6);
			RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],i+7);
		}

		#undef RND

		/* Feedback */
		for (i = 0; i < 8; i++) {
			md.state[i] = md.state[i] + S[i];
		}

		// We can now output our finalized bytes into the output buffer.
		for (i = 0; i < 8; i++) {
			STORE64H(md.state[i], privatek+(8*i));
		}

		// Code Until here runs at 87_000_000H/s.

		// ed25519 Hash Clamping
		privatek[0]  &= 248;
		privatek[31] &= 63;
		privatek[31] |= 64;

		// ed25519 curve multiplication to extract a public key.
		ge_scalarmult_base(&A, privatek);
		ge_p3_tobytes(publick, &A);

		// Code Until here runs at 87_000_000H/s still!

		size_t keysize = 256;
		b58enc(key, &keysize, publick, 32);

		// Code Until here runs at 22_000_000H/s. b58enc badly needs optimization.

		// We don't have access to strncmp/strlen here, I don't know
		// what the efficient way of doing this on a GPU is, so I'll
		// start with a dumb loop. There seem to be implementations out
		// there of bignunm division done in parallel as a CUDA kernel
		// so it might make sense to write a new parallel kernel to do
		// this.
		for (int i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
			size_t found = 0;
			for (int j = 0; prefixes[i][j] != 0; ++j) {
				char lowered = (key[j] >= 65 && key[j] <= 90) 
					? key[j] + 32 
					: key[j];

				if (prefixes[i][found] == '?' || prefixes[i][found] == lowered)
				       	found++;
				else
					found = 0;

				if (found == 6)
					break;
			}

			if (found == 6) {
				keys_found += 1;
				size_t pkeysize = 256;
				b58enc(pkey, &pkeysize, seed, 32);
				printf("(%d): %s - %s\n", keysize, key, pkey);
			}
		}

		// Code Until here runs at 22_000_000H/s. So the above is fast enough.

		// Increment Seed.
		// NOTE: This is horrifically insecure. Please don't use these
		// keys on live. This increment is just so we don't have to
		// invoke the CUDA random number generator for each hash to
		// boost performance a little. Easy key generation, awful
		// security.
		for (int i = 0; i < 32; ++i) {
			if (seed[i] == 255) {
				seed[i]  = 0;
			} else {
				seed[i] += 1;
				break;
			}
		}
	}

	// Copy Random State so that future calls of this kernel/thread/block
	// don't repeat their sequences.
	state[id] = localState;
}

bool __device__ b58enc(
	char    *b58,
       	size_t  *b58sz,
       	uint8_t *data,
       	size_t  binsz
) {
	// Base58 Lookup Table
	const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	const uint8_t *bin = data;
	int carry;
	size_t i, j, high, zcount = 0;
	size_t size;
	
	while (zcount < binsz && !bin[zcount])
		++zcount;
	
	size = (binsz - zcount) * 138 / 100 + 1;
	uint8_t buf[256];
	memset(buf, 0, size);
	
	for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
	{
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
		{
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
			if (!j) {
				// Otherwise j wraps to maxint which is > high
				break;
			}
		}
	}
	
	for (j = 0; j < size && !buf[j]; ++j);
	
	if (*b58sz <= zcount + size - j) {
		*b58sz = zcount + size - j + 1;
		return false;
	}
	
	if (zcount) memset(b58, '1', zcount);
	for (i = zcount; j < size; ++i, ++j) b58[i] = b58digits_ordered[buf[j]];

	b58[i] = '\0';
	*b58sz = i + 1;
	
	return true;
}
