#name for object
object = H3C

#define cross complier in here
CC = gcc

#complie source file
$(object):MD5.o core.o main.c
	$(CC) $^ -o $@


#install to binary directory
install:
	cp H3C /usr/bin/H3C


#clean object file
.PHONY:clean
clean:
	-rm -rf *.o $(object)
