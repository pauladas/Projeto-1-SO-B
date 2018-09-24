/*
 *  Sistemas Operacionais B
 *  Grupo:
 *  Bruno Kitaka        - 16156341
 *  Paulo Figueiredo    - 16043028
 *  Rafael Fioramonte   - 16032708
 *  Raissa Davinha      - 15032006
 *  Vinícius Trevisan   - 16011231
 */

#include <linux/module.h>               /* Requerido por todos os modulos */
#include <linux/kernel.h>               /* Requerido por KERN_INFO */
#include <linux/init.h>                 /* Biblioteca para utilizar macros */

MODULE_LICENSE("GPL");                  				//Acertando a licensa para GPL, para "regularização"
MODULE_DESCRIPTION("Driver de criptografia");           //Adicionar descrição ao módulo

static unsigned long buffer_size = 0;

static int __init cryptoModule_init(void)    //Função criada pelo usuário para ser executada ao carregar o módulo
{
    return 0;
}

static void __exit cryptoModule_exit(void)   //Função criada pelo usuário para ser executada ao retirar o módulo
{
    pr_info("Short is the life of a kernel module\n");      //Mensagem para deug
}

module_init(cryptoModule_init);              //Função que especifica qual função é executada como início do módulo
module_exit(cryptoModule_exit);              //Função que especifica qual função é executada como término do módulo
