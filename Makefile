all: vmtrace short-loop

vmtrace: main.cpp
	g++ -std=c++14 -Wall -o vmtrace main.cpp

short-loop: short-loop.asm
	nasm -f elf64 -o short-loop.o short-loop.asm
	ld -o short-loop short-loop.o

clean:
	rm -f vmtrace short-loop short-loop.o
