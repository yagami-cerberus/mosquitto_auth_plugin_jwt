.PHONY: all clean

DEBUG_OPT=-DMQAP_DEBUG
CFLAGS=-I../lib -I../src -ljwt -Wall -Werror -ggdb 

all : auth_plugin_jwt.so 

auth_plugin_jwt.so : auth_plugin_jwt.c
	$(CC) ${CFLAGS} -fPIC -shared $^ -o $@ 

debug: auth_plugin_jwt_debug.so

auth_plugin_jwt_debug.so : auth_plugin_jwt.c
	$(CC) ${CFLAGS} ${DEBUG_OPT} -fPIC -shared $^ -o $@ 


clean :
	rm -f *.so *.test
