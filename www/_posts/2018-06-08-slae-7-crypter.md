---
layout: post
title: "SLAE x86 Exam Part 7"
description: "SLAE x86 Exam Part 7: Crypter"
modified: 2018-06-08T05:30:00-05:00
tags: [pentest, asm, x86, slae]
---

# Overview
This blog post has been created for completing the requirements of the
SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](/http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1260

---

For the 7th and final exam challenge, I chose to implement the RC4[^1] algorithm 
in C. This algorithm is designed to be easy to implement and was interesting to
me due to the relevance of its weaknesses elsewhere in the field of 
vulnerability research.  

Here is the reference code upon which we will base our implementation, 
taken from [Robin Verton's Github]()[^2].  I added some additional output 
messages, changed it to read input from a predefined string rather than `argv` 
(since reading shellcode from the command line was a problem), and made some 
minor non-functional adjustments for space efficiency and readability.

{% highlight c %}
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
{% endhighlight %}

The key and plaintext are both configurable by modifying the `main()` function.
Here is the output of "helloworld.nasm" from the previous exercise:

{% highlight bash %}
$ gcc -zexecstack -fno-stack-protector -ggdb3 ./rc4.c -o ./rc4 && ./rc4
Encrypting with key "slae"
Shellcode length: 33 bytes
Plaintext:  \x31\xDB\xF7\xE3\x43\x50\x0C\x04\x68\x72\x6C\x64\x0A\x68\x6F\x20\x77\x6F\x68\x48\x65\x6C\x6C\x89\xE1\xB2\x0C\xCD\x80\x89\xD8\xCD\x80
Ciphertext: \xC0\x58\xA8\xDB\x46\x8D\xEA\x5F\xE0\x5B\x7F\x1E\x22\xE9\xE3\xD7\x6E\x93\xAF\xEE\x1C\x08\x34\x30\xC8\x37\xD2\x23\x4B\x17\x95\x85\x69
Plaintext:  \x31\xDB\xF7\xE3\x43\x50\x0C\x04\x68\x72\x6C\x64\x0A\x68\x6F\x20\x77\x6F\x68\x48\x65\x6C\x6C\x89\xE1\xB2\x0C\xCD\x80\x89\xD8\xCD\x80
{% endhighlight %}

As a sanity check, I ran the ciphertext back through the RC4 algorithm with the
same key to make sure the plaintext matched the original input.

---

[^1]: https://en.wikipedia.org/wiki/RC4
[^2]: https://gist.github.com/rverton/a44fc8ca67ab9ec32089
