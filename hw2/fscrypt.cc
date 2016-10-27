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
  
  size_t outlen = blocks * BLOCKSIZE;
  *resultlen = (int)outlen;
  unsigned char *outbuf = (unsigned char *)malloc(sizeof(unsigned char) * outlen);

  // Pointers to scan along in and out buffers
  const unsigned char *iscan = (const unsigned char*)plaintext;
  
  for (int i = 0; i < blocks; i++) {
    // Encrypt each BLOCKSIZE block
    BF_ecb_encrypt(&iscan[i*BLOCKSIZE],
		   &outbuf[i*BLOCKSIZE],
		   &key,
		   BF_ENCRYPT);
  }

  // Fill out the pad if necessary
  // [ g, o, a, t, 3, 3, 3, NULL ]
  if (pad) {
    int pad_start = outlen - BLOCKSIZE;
    assert(pad_start < bufsize);
    unsigned char padbuf[BLOCKSIZE];
    memset(padbuf, pad, BLOCKSIZE);
    strcpy((char *)padbuf, (char *)&iscan[pad_start]);
    BF_ecb_encrypt(padbuf, &outbuf[pad_start], &key, BF_ENCRYPT);
  }
  
  return (void *)outbuf;
}

// decrypt ciphertext of length bufsize. Use keystr as the key.
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, 
		 int *resultlen) {
  // Key setup
  BF_KEY key;
  BF_set_key(&key, strlen(keystr), (const unsigned char *)keystr);

  unsigned char *outbuf = (unsigned char *)malloc(sizeof(unsigned char) * bufsize);
  int blocks = bufsize / BLOCKSIZE;

  // Pointers to scan along in and out buffers
  const unsigned char *iscan = (const unsigned char *)ciphertext;
  
  for (int i = 0; i < blocks; i++) {
    // Encrypt each BLOCKSIZE block
    BF_ecb_encrypt(&iscan[i*BLOCKSIZE],
		   &outbuf[i*BLOCKSIZE],
		   &key,
		   BF_DECRYPT);
  }

  int term;
  for (term = 1; term < BLOCKSIZE && outbuf[bufsize-term]; term++);
  *resultlen = bufsize - term + 1;

  return (void *)outbuf;
}
	
