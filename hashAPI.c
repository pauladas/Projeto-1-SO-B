#include <linux/module.h>
#include <crypto/internal/hash.h>

#define SHA256_LENGTH (256 / 8) //Tamanho do hash final

static void show_hash_result(char *plaintext, char *hash_sha256) //Função para mostrar string antes hash e depois hash
{
    int i;                           //Variável para mostrar o resultado do hash
    char str[SHA256_LENGTH * 2 + 1]; //String resultado

    pr_info("sha256 test for string: \"%s\"\n", plaintext); //String base

    for (i = 0; i < SHA256_LENGTH; i++)
        sprintf(&str[i * 2], "%02x", (unsigned char)hash_sha256[i]); //Repassa a string em hash para a string resultado

    str[i * 2] = 0;       //Final da string
    pr_info("%s\n", str); //Mostra a string resultado
}
int cryptosha256_init(void)
{
    char *plaintext = "This is a test"; //String base para fazer o hash
    char hash_sha256[SHA256_LENGTH];    //String resultado do hash
    struct crypto_shash *sha256;        //Informação/handle do hash (TFM)
    struct shash_desc *shash;           //Struct com TFM e flags

    sha256 = crypto_alloc_shash("sha256", 0, 0); //Seta o hash para o algoritmo SHA256

    if (IS_ERR(sha256)) //Ve se dá erro
        return -1;

    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(sha256), GFP_KERNEL); //Aloca espaço para struct

    if (!shash) //Se não conseguiu alocar
        return -ENOMEM;

    shash->tfm = sha256; //Seta handle
    shash->flags = 0;    //Flag para 0

    if (crypto_shash_init(shash)) //Seta flags (preset a operação)
        return -1;

    if (crypto_shash_update(shash, plaintext, strlen(plaintext))) //Faz o hash em si
        return -1;

    if (crypto_shash_final(shash, hash_sha256)) //Finaliza operaçÕes
        return -1;

    kfree(shash);                             //Desaloca o espaço para struct
    crypto_free_shash(sha256);                //Libera o handle
    show_hash_result(plaintext, hash_sha256); //Mostra resultado do hash

    return 0;
}
void cryptosha256_exit(void)
{
}
module_init(cryptosha256_init);                     //Função de início será a cryptosha256_init
module_exit(cryptosha256_exit);                     //Função de fim será a cryptosha256_init
MODULE_AUTHOR("Paulo Figueiredo and Bruno Kitaka"); //Autores
MODULE_DESCRIPTION("Teste de um hash com sha256");  //Descrição do módulo
MODULE_LICENSE("GPL");                              //Licensa do módulo