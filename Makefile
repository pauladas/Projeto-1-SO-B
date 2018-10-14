obj-m += modulocrypto.o
modulocrypto-objs := hashAPI.o cryptomodule.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules	#compilar o módulo

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean		#excluir o .ko
