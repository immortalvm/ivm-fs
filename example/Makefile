# Example:
# CC=/tmp2/ivm-compiler/gcc-8.3.0-ivm64-1.0rc4/bin/ivm64-gcc  make
# CFLAGS="-O2" CC=/tmp2/ivm-compiler/gcc-8.3.0-ivm64-1.0rc4/bin/ivm64-gcc make
# 
# To debug the ivmfs library, define IVMFS_DEBUG:
# CFLAGS="-O2 -DIVMFS_DEBUG" CC=/tmp2/ivm-compiler/gcc-8.3.0-ivm64-1.0rc4/bin/ivm64-gcc make

# To show the list of files after the execution, define IVMFS_DUMPFILES:
# CFLAGS="-O2 -DIVMFS_DUMPFILES" CC=/tmp2/ivm-compiler/gcc-8.3.0-ivm64-1.0rc4/bin/ivm64-gcc make

# To show the contents of all files after the execution, define IVMFS_DUMPFILECONTENTS:
# CFLAGS="-O2 -DIVMFS_DUMPFILECONTENTS" CC=/tmp2/ivm-compiler/gcc-8.3.0-ivm64-1.0rc4/bin/ivm64-gcc make

WORKINGDIR=./run

CFLAGS_DEF = -O2
CFLAGS := $(if $(CFLAGS),$(CFLAGS),$(CFLAGS_DEF))

all: checkenv
	@echo Making working folder \"$(WORKINGDIR)\"
	mkdir -p $(WORKINGDIR)
	#
	@echo Creating c static filesystem:
	../ivmfs-gen.sh hello1.txt hello2.txt hello3.txt stdin > $(WORKINGDIR)/ivmfs.c
	@echo And copying files for standard gcc:
	cp hello1.txt hello2.txt hello3.txt stdin $(WORKINGDIR) 
	#
	@echo Compiling and running:
	$(CC) $(CFLAGS) main.c $(WORKINGDIR)/ivmfs.c -o $(WORKINGDIR)/a.out
	cd $(WORKINGDIR); ./a.out < stdin

# check environment if compiler $(CC) is ivm64-gcc
checkenv:
	@if echo $(CC) | grep ivm64 > /dev/null && ! which ivm >/dev/null; then  echo "ivm application not found in PATH"; exit 1; else exit 0; fi
	@if echo $(CC) | grep ivm64 > /dev/null && test -z "$$IVM_EMU"; then echo 'export variable IVM_EMU with your favourite ivm emulator; e.g. export IVM_EMU="ivm run", export IVM_EMU=/path/to/ivm_emu_fast'; exit 1; else exit 0; fi

clean:
	rm -rf ./run
