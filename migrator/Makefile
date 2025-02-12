all:
	$(CC) -I../module/include -c migrator.c -fPIC -O3
	$(CC) -shared -o libmigrator.so migrator.o
	$(CC) test.c -o test -L. -lmigrator

install:
	cp libmigrator.so /usr/lib

clean:
	rm -f migrator.o libmigrator.so test a.out
