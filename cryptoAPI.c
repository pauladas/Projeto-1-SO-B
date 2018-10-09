#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <crypto/internal/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

#define SHA256_LENGTH 32

static int __init sha256_init(void){
    struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;
    unsigned char output[SHA256_LENGTH];
    unsigned char buf[10];
    int i;
    //char str[] = "ABCDEF0123456789";
    char str = 'A';

    memset(buf, str, 10);
    /*
     * Memset
     * 1- Área de memória apontada
     * 2- Constante que preencherá a área apontada em 1
     * 3- Quantidade de bytes que será preenchido
     */
    memset(output, 0x00, SHA256_LENGTH);

    tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
    /*
     *  Crypto Alloc Hash
     *  1- driver name of the message digest cipher
     *  2- specifies the type of the cipher
     *  3- specifies the mask for the cipher
     */

    desc.tfm = tfm;
    desc.flags = 0;

    sg_init_one(&sg, buf, 10);
    /*
     *  SG init One
     *  1- Ponteiro para Scatterlist (assim, utilizando Direct Memory Acess, diminuindo o tempo de acesso à memória)
     *  2- Área de memória 
     *  3- Qtd de bytes a serem gravados
     */
    crypto_hash_init(&desc);
    /*
     * Crypto Hash Init
     * 1- Cipher request handle that to be filled by caller. Desc is filled with the hash cipher handle; desc.flags is filled with either CRYPTO_TFM_REQ_MAY_SLEEP or 0.
     */

    crypto_hash_update(&desc, &sg, 10);
    /*
     *  Crypto Hash update
     *  1- Cipher request handle
     *  2- Scatter / gather list pointing to the data to be added to the message digest
     *  3- Number of bytes to be processed from sg
     */
    crypto_hash_final(&desc, output);
    /*
     * Crypto Hash Final
     * 1- cipher request handle
     * 2- message digest output buffer -- The caller must ensure that the out buffer has a sufficient size (e.g. by using the crypto_hash_digestsize function).
     */

    for (i = 0; i < 20; i++) {
        printk(KERN_ERR "%d-%d\n", output[i], i);
        //Coloca o output gerado pelo Hash
    }

    crypto_free_hash(tfm);

    return 0;
}

static void __exit sha256_exit(void){
    printk(KERN_INFO "sha256: %s\n", __FUNCTION__);
}


/* Inicializacao das funcoes de init e exit, ja que ambas foram criadas com macros */
module_init(sha256_init);
module_exit(sha256_exit);
