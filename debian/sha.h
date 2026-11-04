/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 The Blueberry Pie OS Authors */

#ifndef PIE_LIBMD_SHA_H
#define PIE_LIBMD_SHA_H

#include <CommonCrypto/CommonDigest.h>
#include <sys/types.h>
#include <sys/cdefs.h>

typedef CC_SHA1_CTX SHA_CTX;
typedef CC_SHA1_CTX SHA1_CTX;

#define SHA_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH

__BEGIN_DECLS

int SHA_Init(SHA_CTX *context);
int SHA_Update(SHA_CTX *context, const void *data, size_t count);
int SHA_Final(unsigned char *digest, SHA_CTX *context);
char *SHA_End(SHA_CTX *context, char *hex);
char *SHA_Data(const void *data, unsigned int count, char *hex);
char *SHA_File(const char *path, char *hex);
char *SHA_FileChunk(const char *path, char *hex, off_t start, off_t count);
char *SHA_Fd(int descriptor, char *hex);
char *SHA_FdChunk(int descriptor, char *hex, off_t start, off_t count);

#define SHA1_Init CC_SHA1_Init
#define SHA1_Update CC_SHA1_Update
#define SHA1_Final CC_SHA1_Final
char *SHA1_End(SHA1_CTX *context, char *hex);
char *SHA1_Data(const void *data, unsigned int count, char *hex);
char *SHA1_File(const char *path, char *hex);
char *SHA1_FileChunk(const char *path, char *hex, off_t start, off_t count);
char *SHA1_Fd(int descriptor, char *hex);
char *SHA1_FdChunk(int descriptor, char *hex, off_t start, off_t count);

__END_DECLS

#endif
