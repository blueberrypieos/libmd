/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */
/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 The Blueberry Pie OS Authors */
/* Modified 2026-11-04: SHA-0 (no rotate in the message expansion); Init, Update and Final on CC_SHA1_CTX. */

#include <stdint.h>
#include <string.h>

#include "sha.h"

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#ifndef WORDS_BIGENDIAN
# define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#else
# define blk0(i) block->l[i]
#endif
#define blk(i) (block->l[i&15] = block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15])

#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

typedef union {
	uint8_t c[64];
	uint32_t l[16];
} CHAR64LONG16;

static void
SHA0Transform(uint32_t state[5], const uint8_t buffer[CC_SHA1_BLOCK_BYTES])
{
	uint32_t a, b, c, d, e;
	uint8_t workspace[CC_SHA1_BLOCK_BYTES];
	CHAR64LONG16 *block = (CHAR64LONG16 *)workspace;

	(void)memcpy(block, buffer, CC_SHA1_BLOCK_BYTES);

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;

	a = b = c = d = e = 0;
}

int
SHA_Init(SHA_CTX *c)
{
	c->h0 = 0x67452301;
	c->h1 = 0xEFCDAB89;
	c->h2 = 0x98BADCFE;
	c->h3 = 0x10325476;
	c->h4 = 0xC3D2E1F0;
	c->Nl = 0;
	c->Nh = 0;
	c->num = 0;
	return (1);
}

int
SHA_Update(SHA_CTX *c, const void *data, size_t len)
{
	const uint8_t *in = data;
	uint8_t *buffer = (uint8_t *)c->data;
	uint32_t state[5];
	uint64_t count;
	size_t i, j;

	if (len == 0)
		return (1);

	count = ((uint64_t)c->Nh << 32 | c->Nl) + ((uint64_t)len << 3);
	c->Nl = (uint32_t)count;
	c->Nh = (uint32_t)(count >> 32);

	j = (size_t)c->num;
	if ((j + len) > 63) {
		state[0] = c->h0;
		state[1] = c->h1;
		state[2] = c->h2;
		state[3] = c->h3;
		state[4] = c->h4;
		(void)memcpy(&buffer[j], in, (i = 64-j));
		SHA0Transform(state, buffer);
		for ( ; i + 63 < len; i += 64)
			SHA0Transform(state, &in[i]);
		c->h0 = state[0];
		c->h1 = state[1];
		c->h2 = state[2];
		c->h3 = state[3];
		c->h4 = state[4];
		j = 0;
	} else {
		i = 0;
	}
	(void)memcpy(&buffer[j], &in[i], len - i);
	c->num = (int)(j + len - i);
	return (1);
}

int
SHA_Final(unsigned char *md, SHA_CTX *c)
{
	uint8_t finalcount[8];
	uint32_t state[5];
	unsigned int i;

	for (i = 0; i < 4; i++) {
		finalcount[i] = (uint8_t)((c->Nh >> ((3 - i) * 8)) & 255);
		finalcount[i + 4] = (uint8_t)((c->Nl >> ((3 - i) * 8)) & 255);
	}
	SHA_Update(c, "\200", 1);
	while (c->num != 56)
		SHA_Update(c, "\0", 1);
	SHA_Update(c, finalcount, 8);
	state[0] = c->h0;
	state[1] = c->h1;
	state[2] = c->h2;
	state[3] = c->h3;
	state[4] = c->h4;
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		md[i] = (unsigned char)
		   ((state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
	}
	memset_s(c, sizeof(*c), 0, sizeof(*c));
	return (1);
}
