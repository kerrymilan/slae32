/*
   robin verton, dec 2015
   implementation of the RC4 algo
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define N 256   // 2^8

void RC4(char *key, char *plaintext, unsigned char *ciphertext);

int main(int argc, char *argv[]) {

    char *key = "slae";
    char *shellcode = 
        "\x31\xdb\xf7\xe3\x43\x50\x0c\x04\x68\x72\x6c\x64"
        "\x0a\x68\x6f\x20\x77\x6f\x68\x48\x65\x6c\x6c\x89"
        "\xe1\xb2\x0c\xcd\x80\x89\xd8\xcd\x80";
    unsigned char *ciphertext = malloc(sizeof(int) * strlen(shellcode));

    printf("Encrypting with key \"%s\"\n", key);
    printf("Shellcode length: %d bytes\n", strlen(shellcode));
    printf("Plaintext:  ");
    for(size_t i = 0, len = strlen(shellcode); i < len; i++)
        printf("\\x%02hhX", shellcode[i]);

    RC4(key, shellcode, ciphertext);
    printf("\nCiphertext: ");
    for(size_t i = 0, len = strlen(shellcode); i < len; i++)
        printf("\\x%02hhX", ciphertext[i]);

    shellcode = ciphertext;
    RC4(key, shellcode, ciphertext);
    printf("\nPlaintext:  ");
    for(size_t i = 0, len = strlen(shellcode); i < len; i++)
        printf("\\x%02hhX", ciphertext[i]);

    printf("\n");
    return 0;
}

void swap(unsigned char *a, unsigned char *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

void KSA(char *key, unsigned char *S) {
    int len = strlen(key), j = 0;

    for(int i = 0; i < N; i++) S[i] = i;
    for(int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % len]) % N;
        swap(&S[i], &S[j]);
    }
}

void PRGA(unsigned char *S, char *plaintext, unsigned char *ciphertext) {
    int i = 0, j = 0;

    for(size_t n = 0, len = strlen(plaintext); n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;

        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];

        ciphertext[n] = rnd ^ plaintext[n];
    }
}

void RC4(char *key, char *plaintext, unsigned char *ciphertext) {
    unsigned char S[N];
    KSA(key, S);
    PRGA(S, plaintext, ciphertext);
}

