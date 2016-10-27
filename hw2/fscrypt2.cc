#include "fscrypt.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

// encrypt plaintext of length bufsize. Use keystr as the key.
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, 
		 int *resultlen) {
  // Key setup
  BF_KEY key;
  BF_set_key(&key, strlen(keystr), (const unsigned char *)keystr);

  // Encrypt
  int blocks = bufsize / BLOCKSIZE;
  char pad = (BLOCKSIZE - (bufsize % BLOCKSIZE)) % BLOCKSIZE;

  // If there's a pad, we need one more block
  if (pad) {
    blocks++;
  }

  // Find output size
  size_t outlen = blocks * BLOCKSIZE;
  *resultlen = (int)outlen;
  unsigned char *outbuf = (unsigned char *)malloc(sizeof(unsigned char) * outlen);

  // Set up plaintext so the len is a multiple of 8, requires copying
  unsigned char *padded_ptxt = (unsigned char *)malloc(sizeof(unsigned char) * outlen);
  memcpy(padded_ptxt, (unsigned char *)plaintext, bufsize);
  memset(&padded_ptxt[bufsize], pad, pad);

  // Initialization vector, always all 0s
  const size_t ivec_size = 128;
  unsigned char ivec[ivec_size];
  memset(ivec, 0, ivec_size);
  
  BF_cbc_encrypt(padded_ptxt, outbuf, outlen, &key, ivec, BF_ENCRYPT);
  free(padded_ptxt);
  
  return (void *)outbuf;
}

// decrypt ciphertext of length bufsize. Use keystr as the key.
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, 
		 int *resultlen) {
  // Key setup
  BF_KEY key;
  BF_set_key(&key, strlen(keystr), (const unsigned char *)keystr);

  // Find output size
  unsigned char *outbuf = (unsigned char *)malloc(sizeof(unsigned char) * bufsize);

  // Initialization vector, always all 0s
  const size_t ivec_size = 128;
  unsigned char ivec[ivec_size];
  memset(ivec, 0, ivec_size);
  
  BF_cbc_encrypt((const unsigned char *)ciphertext, outbuf,
		 bufsize, &key, ivec, BF_DECRYPT);

  // Find the length of the result by looking for the null terminator
  int term;
  for (term = 1; term < BLOCKSIZE && outbuf[bufsize-term]; term++);
  *resultlen = bufsize - term + 1;

  
  return (void *)outbuf;
}
	
