#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main() {
    OpenSSL_add_all_algorithms();

    // 使用 EVP 接口进行 SM4 加密
    const char *plaintext = "Your new secret message";
    const char *key = "new16bytesecretkey"; // 16字节的密钥
    const char *iv = "new16byteivvalue";  // 16字节的初始向量

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv, 1); // 1表示加密模式

    unsigned char ciphertext[1024];
    int ciphertext_len;

    EVP_CipherUpdate(ctx, ciphertext, &ciphertext_len, (unsigned char *)plaintext, strlen(plaintext));
    int final_len;
    EVP_CipherFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    // 打印加密结果
    printf("SM4 Cipher Text: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // 使用 EVP 接口进行 SM3 哈希计算
    const char *message = "Your new secret message";

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
    EVP_DigestUpdate(mdctx, message, strlen(message));

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    EVP_DigestFinal_ex(mdctx, md_value, &md_len);

    EVP_MD_CTX_free(mdctx);

    // 打印 SM3 哈希值
    printf("SM3 Hash Value: ");
    for (unsigned int i = 0; i < md_len; i++) {
        printf("%02x", md_value[i]);
    }
    printf("\n");

    return 0;
}


