stage1:stage_1.o head.o aes_lib.o
	gcc -w -o stage1 stage_1.o head.o aes_lib.o
head.o:head.h head.c
	gcc -c -w head.c
aes_lib.o:aes_lib.h aes_lib.c
	gcc -c -w aes_lib.c
stage_1.o:head.h stage_1.c
	gcc -c -w stage_1.c

clean:
	rm stage1 stage_1.o head.o aes_lib.o output.txt

