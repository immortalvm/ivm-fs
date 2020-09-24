all: checkenv 
	@echo "======== Compressing hello.txt -> hello.txt.gz ================="
	mkdir -p run && cd run && cp ../hello.txt . && rm -f hello.txt.gz && gzip hello.txt
	@echo
	
	@echo "======== Generating filesystem containing hello.txt.gz -> ivmfs.c"
	cd run ; \
	../../ivmfs-gen.sh hello.txt.gz > ivmfs.c ;
	@echo
	
	@echo "======== Compiling =============================================="
	cd run; \
	$(CC) -O2 -I.. ivmfs.c ../minigzip.c -L.. -lz  -o minigzip ;
	@echo
	
	@cd run ; \
    grep ivm64 ../libz.so | grep version |sort -u > lib.ver ; \
    grep ivm64 minigzip | grep version |sort -u > exe.ver ; \
	if ! cmp lib.ver exe.ver ; then echo "Library version mismatch"; exit 1; fi
	@echo
	
	@echo "======== Running ================================================"
	cd run; echo ; ./minigzip -d -c hello.txt.gz
	@echo
	

# check environment if compiler $(CC) is ivm64-gcc
checkenv:
	@if ! ($(CC) --version | grep ivm64-gcc) > /dev/null; then echo; echo "ivm64-gcc not found; define CC pointing to the ivm64-gcc compiler"; echo; exit 1; fi 
	@if ($(CC) --version | grep '1.0rc[1-4]') > /dev/null; then echo; echo "Required ivm64-gcc 1.0rc5 at least"; echo; exit 1 ; fi 
	@if echo $(CC) | grep ivm64 > /dev/null && ! which ivm >/dev/null; then  echo "ivm application not found in PATH"; exit 1; else exit 0; fi
	@if echo $(CC) | grep ivm64 > /dev/null && test -z "$$IVM_EMU"; then echo 'export variable IVM_EMU with your favourite ivm emulator; e.g. export IVM_EMU="ivm run", export IVM_EMU=/path/to/ivm_emu_fast'; exit 1; else exit 0; fi

clean:
	rm -rf ./run
