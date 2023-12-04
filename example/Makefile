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

IVM_FSGEN:=$(if $(IVM_FSGEN),$(IVM_FSGEN),../ivm64-fsgen)

all: checkenv
	@echo Making working folder \"$(WORKINGDIR)\"
	mkdir -p $(WORKINGDIR)
	#
	@echo Creating c static filesystem:
	$(IVM_FSGEN) hello1.txt hello2.txt hello3.txt stdin > $(WORKINGDIR)/ivmfs.c
	@echo And copying files for standard gcc:
	cp hello1.txt hello2.txt hello3.txt stdin $(WORKINGDIR) 
	#
	@echo Compiling and running:
	$(CC) $(CFLAGS) main.c $(WORKINGDIR)/ivmfs.c -o $(WORKINGDIR)/a.out
	cd $(WORKINGDIR); ./a.out < stdin

# check environment if compiler $(CC) is ivm64-gcc
checkenv: check-ivm64-gcc check-ivm64-gpp check-ivm64-as check-ivm64-emu

check-ivm64-gcc:
	@which $(CC) >/dev/null || (echo $(CC) compiler not found in PATH; exit 1)

check-ivm64-gpp:
	@which $(CXX) >/dev/null || (echo $(CXX) compiler not found in PATH; exit 1)

check-ivm64-as:
	@which `echo $$IVM_AS | cut -d' ' -f1 ` >/dev/null || which ivm64-as >/dev/null || which ivm >/dev/null || (echo Neither variable IVM_AS is a valid IVM assembler, nor applications 'ivm64-as' or 'ivm' can be found in PATH ; exit 1)

check-ivm64-emu:
	@which `echo $$IVM_EMU | cut -d' ' -f1` >/dev/null || which ivm64-emu >/dev/null || which ivm >/dev/null || (echo Neither variable IVM_EMU is a valid IVM emulator, nor applications 'ivm64-emu' or 'ivm' can be found in PATH ; exit 1)


clean:
	rm -rf ./run
