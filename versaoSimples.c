#include <linux/init.h>                                          /* Macros Utilizadas para iniciar (__init) e terminar (__exit) o modulo */
#include <linux/module.h>                                        /* Biblioteca para carregar o modulo de kernel no sistema */
#include <linux/device.h>                                        /* Biblioteca para suportar o modulo de dispositivo */
#include <linux/kernel.h>                                        /* Contem as funcoes macros e tipos de estruturas do kernel */
#include <linux/moduleparam.h>                                   
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/stat.h>
#include <linux/string.h>                                        /* Biblioteca para manipular strings em nivel de kernel */
#include <linux/fs.h>                                            
#include <linux/uaccess.h>
#include <crypto/skcipher.h>


struct encrypt_ctx {
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct completion complete;
	int err;
};

static void encrypt_cb(struct crypto_async_request *req, int error){
	struct crypto_ctx *ctx = req->data;
	if (error == -EINPROGRESS)
		return;
	ctx->err = error;
	complete(&ctx->completion);
}

static int init(struct encrypt_ctx *ctx) {
/*	Declaração:
*
*    A struct scatterlist is used to hold your plaintext in a format the crypto.h functions can understand, while a struct hash_desc is 
* 	used to configure the hashing.
*   The variable plaintext holds our plaintext string, while hashval will hold the hash of our plaintext.
*   Finally, len holds the length the plaintext string.
*/
	/* Create a CBC(AES) algorithm instance: */
	ctx->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	/* Create a request and assign it a callback: */
	ctx->req = skcipher_request_alloc(ctx->tfm, GFP_KERNEL);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, encrypt_cb, ctx);
	init_completion(&ctx.completion);

}

int encrypt(void *key, void *data, unsigned int size) {
	struct encrypt_ctx ctx;
	struct scatterlist sg;
	int ret;
	init(&ctx);

	/* Set the private key: */
	crypto_skcipher_setkey(ctx.tfm, key, 32);
	
	/*Now assign the src/dst buffer and encrypt data: */
	sg_init_one(&sg, data, size);
	skcipher_request_set_crypt(ctx.req, &sg, &sg, len, NULL);
	ret = crypto_skcipher_encrypt(ctx.req);

	if (ret == -EINPROGRESS || ret == -EBUSY) {
		wait_for_completion(&ctx.completion);
		ret = ctx.err;
	}
	cleanup(&ctx);
	return ctx.err;
}

static void cleanup(struct encrypt_ctx *ctx) {
	skcipher_request_free(ctx->req);
	crypto_free_skcipher(ctx->tfm);
}
