#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

#define SHA1_LENGTH     20

static int __init sha1_init(void)
{
    struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;
    unsigned char output[SHA1_LENGTH];
    unsigned char buf[10];
    int i;

    /*
    *   cria uma struct tipo scatterlist com nome sg
    *   cria ponteiro para uma struct tipo crypto_hash com nome *tfm
    *   struct tipo hash_desc com nome desc
    *   vetor de caracteres não assinalados, com nome output de tamanho sha1_length
    *   vetor decaracteres não assinalados, com nome buf de tamanho 10              //um buffer de caracgeres?
    *   inteiro de nome i
    * 
    *   imprime uma string de nome _function_ no kernel info
    * 
    *   //memset preenche uma quantidade de uma determinada área da memória com um dado valor. Em outras palavras, 
    *       inicializa algum objeto (variável, estrutura, etc).
    * 
    *   usa memset para encher a struct buf com a letra A nos primeiros 10 bytes
    *   usa memset para encher a struct output com o hexadecimal 0x00 nos "SHA1_LENGTH" bytes
    * 
    *   // funçao struct crypto_hash * crypto_alloc_hash(const char * alg_name, u32 type, u32 mask):
    *       Aloca um identificador de criptografia para um resumo de mensagem. A struct retornada crypto_hash é o 
    *       identificador de criptografia necessário para qualquer chamada de API subsequente para esse 
    *       resumo de mensagem. Alça de cifra alocada em caso de sucesso.
    * 
    *   struct tfm recebe o valor da alça de cifra com nome sha1, do tipo 0, com a máscara CRYPTO_ALG_ASYNC
    * 
    *   valor tfm dentro da struct desc recebe o valor dado anteriormente à struct tfm
    *   valor flag dentro da struct desc é setado para 0
    *   
    *   // funçao:void sg_init_one(struct scatterlist *, const void *, unsigned int) (set data buffer?)
    *   executa funçao sg_init_one passando o endereço da struct sg, a struct buff e o valor 10 como parametros
    * 
    *   //funçao: int crypto_hash_init(struct hash_desc * desc)
    *       A chamada (re) inicializa o resumo da mensagem referenciado pelo identificador de solicitação de 
    *       criptografia de hash. Qualquer estado potencialmente existente criado por operações anteriores é 
    *       descartado. argumento: pedido de cifra manipula aquele a ser preenchido pelo chamador - desc.tfm é 
    *       preenchido com o identificador de cifra de hash; desc.flags é preenchido com CRYPTO_TFM_REQ_MAY_SLEEP 
    *       ou 0.
    * 
    */
    printk(KERN_INFO "sha1: %s\n", __FUNCTION__);

    memset(buf, 'A', 10);
    memset(output, 0x00, SHA1_LENGTH);

    tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);

    desc.tfm = tfm;
    desc.flags = 0;

    sg_init_one(&sg, buf, 10);
    crypto_hash_init(&desc);

    crypto_hash_update(&desc, &sg, 10);
    crypto_hash_final(&desc, output);

    for (i = 0; i < 20; i++) {
        printk(KERN_ERR "%d-%d\n", output[i], i);
    }

    crypto_free_hash(tfm);

    return 0;
}

static void __exit sha1_exit(void)
{
    printk(KERN_INFO "sha1: %s\n", __FUNCTION__);
}

module_init(sha1_init);
module_exit(sha1_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Me");
