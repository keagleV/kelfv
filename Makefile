insHeaders:
	cp src/*.h /usr/include
clean:
	rm -rf bin/*
build:
	#gcc -c src/kelfv.c -o /tmp/kelfv.o.tmp
	#objcopy --redefine-sym entry=kelfv /tmp/kelfv.o.tmp
	gcc -w -std=c99 src/kelfv.c -o bin/kelfv -fuse-ld=gold -O3
run:
	./bin/kelfv

rbuild:
	make build
	make run
togit:
	cp -r ./bin ./src ./todo Makefile ~/mygit/kelfv
