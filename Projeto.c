#include <linux/init.h>/* Macros Utilizadas para iniciar (__init) e terminar (__exit) o modulo */
#include <linux/module.h>/* Biblioteca para carregar o modulo de kernel no sistema */
#include <linux/device.h>/* Biblioteca para suportar o modulo de dispositivo */
#include <linux/kernel.h>/* Contem as funcoes macros e tipos de estruturas do kernel */
#include <linux/moduleparam.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/stat.h>
#include <linux/string.h>/* Biblioteca para manipular strings em nivel de kernel */
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <crypto/skcipher.h>
#include <linux/wait.h>
#include <linux/completion.h>
#include <linux/random.h>

MODULE_LICENSE("GPL v2");

struct tcrypt_result {
    struct completion completion;
    int err;
};

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS)
        return;
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
    //pr_info("Output: %s", )
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_skcipher_encrypt(sk->req);
    else
        rc = crypto_skcipher_decrypt(sk->req);

    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(&sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n", rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

/* Initialize and trigger cipher operation */
static int __init test_skcipher(void)
{
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *scratchpad = NULL; //variavel aonde ira a entrada
    char *ivdata = NULL;
    unsigned char key[32]; //chave
    int ret = -EFAULT;
    static int crypto_i;
    static char aux_string[16] = "1234567890abcdef";

    skcipher = crypto_alloc_skcipher("ecb-aes-aesni", 0, 0); //seta algoritimo aes ebc
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, test_skcipher_cb, &sk.result);

    /* AES 256 with random key */
    get_random_bytes(&key, 32);
    if (crypto_skcipher_setkey(skcipher, key, 32)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }
    
    pr_info("Key: %s", key);

    /* IV will be random */
    ivdata = kmalloc(16, GFP_KERNEL);
    if (!ivdata) {
        pr_info("could not allocate ivdata\n");
        goto out;
    }
    get_random_bytes(ivdata, 16);
    
    pr_info("IVdata: %s", ivdata);

    /* Input data will be random */
    scratchpad = kmalloc(16, GFP_KERNEL);
    //aloca 16 bytes em espaco de kernel e coloca o ponteiro desse espaco em scratchpad
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }
    //get_random_bytes(scratchpad, 16);
    
    
    //input
    for (crypto_i = 0; crypto_i < 16; crypto_i++) {
    	*(scratchpad + crypto_i) = aux_string[crypto_i];
    }

    pr_info("Input: %s", scratchpad);

    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, scratchpad, 16);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sf, 16, ivdata);
    init_completion(&sk.result.completion);

    /* encrypt data */
    //passa sk como argumento e 1 se for encriptacao ou 0 se for decriptacao
    ret = test_skcipher_encdec(&sk, 1);
    if (ret)
        goto out;

    pr_info("Encryption triggered successfully\n");

    pr_info("skcipher encrypt returned with %d result %d\n", &sk, sk->result.err);


out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (ivdata)
        kfree(ivdata);
    if (scratchpad)
        kfree(scratchpad);
    return ret;
}

static void __exit cryto_moduleExit(void) {
	pr_info("Fechando modulo\n");
}

module_init(test_skcipher);
module_exit(cryto_moduleExit);
