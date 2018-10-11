/* FUNÇAO PARA MOSTRAR O RESULTADO DO HASH */
static void show_hash_result(char *plaintext, char *hash_sha256);
/* FUNÇAO PARA DAR INÍCIOU AO HASH (FUNÇAO CHAMADA CASO O MODULO HASH SEJA INICIALIZADO) */
int cryptosha256_init(void);
/* FUNÇAO FINAL AO HASH (FUNÇAO CHAMADA CASO O MODULO HASH SEJA FINALIZADO */
void cryptosha256_exit(void);