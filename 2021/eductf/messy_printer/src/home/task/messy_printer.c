#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#define RSA_E "3"

#define RSA_BIT 1024
#define RSA_LENGTH (RSA_BIT/8)

#define TITLE_SIZE 0x20
#define CONTENT_SIZE RSA_LENGTH

#define ITERATION 1000

#define ERROR() do { \
    exit(255); \
} while(0)

#define NOT_ENCRYPTED() do { \
    puts("Not Encryped!"); \
} while(0)

EVP_PKEY_CTX *ctx;
EVP_PKEY* publicKey;
ENGINE *engine;
RSA *rsaParam;
BIGNUM *n, *e, *halfN, *tmp;

char plaintext[CONTENT_SIZE+1];
void initialize();
void generateKey();
void myRead(char *, int);
void printfWrapper(const char *);


// HINT:
//   no pwnable part in this function
void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("()!(@)#\\x01\\xfa@)!(#)");
    puts("(}{?!)@(``!@#$x%!^?&)");
    puts("(!                 #)");
    puts("(_  Messy printer  _)");
    puts("(*                 :)");
    puts("((!&^^&@;#\\x01,!\\x12)");
    puts("(./123-!)@(\\xfdlO@!K)");
    puts("");
    puts("Send me your email. I'll help you obfuscate it to ensure the confidentiality!");

    // Allocate structure
    halfN = BN_new();
    if (!halfN)
        ERROR();
    tmp = BN_new();
    if (!tmp)
        ERROR();
    rsaParam = RSA_new();
    if (!rsaParam)
        ERROR();
    publicKey = EVP_PKEY_new();
    if (!publicKey)
        ERROR();

    // e for RSA key pair
    if (BN_dec2bn(&e, RSA_E) <= 0)
        ERROR();

    // Create OPENSSL engine
    engine = ENGINE_get_default_RSA();
}

// HINT:
//   no pwnable part in this function
void generateKey() {
    RSA_free(rsaParam);
    EVP_PKEY_free(publicKey);

    // Generate new RSA key pair
    rsaParam = RSA_new();
    if (!rsaParam)
        ERROR();
    publicKey = EVP_PKEY_new();
    if (!publicKey)
        ERROR();

    RSA_generate_key_ex(rsaParam, RSA_BIT, e, NULL);
    if (EVP_PKEY_set1_RSA(publicKey, rsaParam) <= 0)
        ERROR();

    // Get n from rsaParam
    RSA_get0_key(rsaParam, (const BIGNUM **)&n, NULL, NULL);
    if (BN_rshift1(halfN, n) <= 0)
        ERROR();

    // Set encryption context
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new(publicKey, engine);
    if (!ctx)
        ERROR();
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        ERROR();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0)
        ERROR();
}

// HINT:
//   no pwnable part in this function
void myRead(char *input, int size) {
    int i;
    for (i = 0; i < size; ++i) {
        read(0, &(input[i]), 1);
        if (input[i] == '\n') {
            input[i] = '\0';
            break;
        }
    }
    input[i] = '\0';
}

// HINT:
//   PWNABLE
void printfWrapper(const char *format) {
    size_t ciphertextLength, plaintextLength;
    int ret;
    char *ciphertext = NULL;

    // get printf output first
    memset(plaintext, '\x00', CONTENT_SIZE+1);
    ret = snprintf(plaintext, CONTENT_SIZE, format);
    if (ret <= 0 || ret > CONTENT_SIZE) {
        NOT_ENCRYPTED();
        return;
    }
    else
        plaintextLength = (size_t)ret;
    
    // We use no RSA padding
    // so we need to make sure plaintext is long enough
    // if n / 2 > plaintext
    // then plaintext = n - plaintext
    BN_clear(tmp);
    BN_bin2bn(plaintext, plaintextLength, tmp);
    if (BN_cmp(halfN, tmp) > 0) {
        BN_sub(tmp, n, tmp);
    }
    
    memset(plaintext, '\x00', CONTENT_SIZE+1);
    plaintextLength = BN_bn2bin(tmp, plaintext);
    if (plaintextLength <= 0)
        ERROR();

    // get ciphertext length and encrypt it
    if (EVP_PKEY_encrypt(ctx, NULL, &ciphertextLength, plaintext, plaintextLength) <= 0)
        ERROR();
    
    ciphertext = OPENSSL_malloc(ciphertextLength);
    if (!ciphertext)
        ERROR();
    memset(ciphertext, 0, ciphertextLength);

    if (EVP_PKEY_encrypt(ctx, ciphertext, &ciphertextLength, plaintext, plaintextLength) <= 0) {
        NOT_ENCRYPTED();
        OPENSSL_free(ciphertext);
        return;
    }
    write(1, ciphertext, ciphertextLength);
    OPENSSL_free(ciphertext);
}

// HINT:
//   PWNABLE
int main(int argc, char **argv) {
    void (*fp)(char *);
    int iteration;
    char *input;
    
    initialize();

    input = (char *) malloc(CONTENT_SIZE+1);
    iteration = ITERATION;
    char c;
    while (iteration--) {
        generateKey();
        puts("\nContinue? [y/n]: ");
        read(0, &c, 1);
        if (c == 'n' || c == 'N')
            break;
        puts("\nGive me title: ");
        myRead(input, TITLE_SIZE);
        printfWrapper(input);

        puts("\nGive me content: ");
        myRead(input, CONTENT_SIZE);
        printfWrapper(input);
    }
    free(input);
    
    // I'll make it easy this time.
    // However, I'll come back for revenge in the future...
    puts("Give me the magic: ");
    read(0, &fp, 8);
    fp("/bin/sh");
    return 0;
}
