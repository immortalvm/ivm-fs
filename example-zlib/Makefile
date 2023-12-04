#Usage:
#    CC=/path/to/ivm64-gcc make

IVM_FSGEN:=$(if $(IVM_FSGEN),$(IVM_FSGEN),../ivm64-fsgen)

run: minigzip
	LD_LIBRARY_PATH=. ./minigzip  -c -d file.gz

minigzip: ivmfs.c minigzip.c libminiz.so
	$(CC) ivmfs.c minigzip.c -Izlib-1.2.11/ -L. -lminiz -o $@ 

ivmfs.c:
	echo "Hello\nworld!" > hello.txt
	gzip hello.txt
	mv hello.txt.gz file.gz
	$(IVM_FSGEN) file.gz > $@

libminiz.so:
	$(CC) -shared -fPIC zlib-1.2.11/*.c -Izlib-1.2.11/ -o $@ 

clean:
	rm -f libminiz.so ivmfs.c file.gz hello.txt minigzip *.sym *.b


	
