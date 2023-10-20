#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

int main() {
    OpenSSL_add_all_algorithms();

    // SM2 密钥对生成
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (EC_KEY_generate_key(ec_key) != 1) {
        fprintf(stderr, "Error generating SM2 key pair\n");
        return 1;
    }

    // 获取私钥和公钥
    const BIGNUM *private_key = EC_KEY_get0_private_key(ec_key);
    const EC_POINT *public_key = EC_KEY_get0_public_key(ec_key);

    // 显示私钥
    printf("SM2 Private Key: %s\n", BN_bn2hex(private_key));

    // 显示公钥
    printf("SM2 Public Key: %s\n", EC_POINT_point2hex(EC_KEY_get0_group(ec_key), public_key, POINT_CONVERSION_UNCOMPRESSED, NULL));

    // 创建 EVP_PKEY 对象并设置私钥
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        fprintf(stderr, "Error setting EC key to EVP_PKEY\n");
        return 1;
    }

    // SM2 加密测试
    const char *plaintext = "This is a secret message to encrypt";
    unsigned char ciphertext[1024];
    size_t ciphertext_len;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_encrypt(ctx, ciphertext, &ciphertext_len, (const unsigned char *)plaintext, strlen(plaintext)) <= 0) {
        fprintf(stderr, "Error encrypting with SM2\n");
        return 1;
    }

    // 显示加密结果
    printf("SM2 Encrypted Text: ");
    for (size_t i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // SM2 解密测试
    unsigned char decrypted_text[1024];
    size_t decrypted_len;

    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_decrypt(ctx, decrypted_text, &decrypted_len, ciphertext, ciphertext_len) <= 0) {
        fprintf(stderr, "Error decrypting with SM2\n");
        return 1;
    }

    // 显示解密结果
    printf("SM2 Decrypted Text: %s\n", decrypted_text);

    // 释放资源
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EC_KEY_free(ec_key);

    return 0;
}


