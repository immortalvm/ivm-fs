#!/bin/bash

# Preservation Virtual Machine Project
#
# This static filesystem generator allows to recreate a folderless 
# read/write static filesystem for testing the ivm64 ecosystem.
#
# By invoking the script with the list of files to include in the filesystem,
# it will print to stdout a C code with the file contents and some primitives
# (open, read, lseek) to access the files:
#
#    ivmfs-gen.sh file1.c file2.c ... > ivmfs.c
#
# Note: if the file name includes paths to directories they are
# considered part of the name (i.e. if you use "ivmfs-gen.sh /path/to/file"
# you need to open it as 'open("/path/to/file"...)'
#
# Then you can link a program with the generated C file, so that the primitives
# included in it will replace those of newlib, therefore enabling to access the
# files in a stardard way:
#
#     ivm64-gcc main.c ivmfs.c   # Always compile ivmfs.c before libraries
#
# where main.c can be like this:
#
#    main(){
#      FILE *f = fopen("file1.txt", "r");
#      int n = fread(buff, 1, 5, f);
#      ...
#     }
#
# The stdin can be simulated using the file defined by
# the macro STDIN_FILE ("stdin" by default). If
# a program requires STDIN, it will use the content of
# "stdin". To this end, this script should be invoked as:
#
#    ivmfs-gen.sh stdin file1.c file2.c ... > ivmfs.c
#
# Compilation options:
#
#    ivm64-gcc -DIVMFS_DEBUG ivmfs.c ....
#        -> print information for each file operation
#
#    ivm64-gcc -DIVMFS_DUMPFILES ivmfs.c ....
#        -> dump a list of files when the program exits
#
#    ivm64-gcc -DIVMFS_DUMPFILECONTENTS ivmfs.c ....
#        -> dump the contents of all files when the program exits
#
# Authors:
#  Eladio Gutierrez Carrasco
#  Sergio Romero Montiel
#  Oscar Plata Gonzalez
#  * University of Malaga
#
# Date: Ago 2020

cmdline="`basename $0` $@"
print_header(){
    cat << EEOOPP
/*
 * Preservation Virtual Machine Project
 *
 * Static filesystem generated with this command invocation:
 *    > $cmdline
 *
 * To be linked with the rest of the C files before libraries
 */

EEOOPP
}

print_preamble() {
    cat << EEOOPP
#ifdef __ivm64__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define FIRST_FILENO  3

// This file will emulate STDIN
#define STDIN_FILE "stdin"

#define BLKSIZE 64

#define MIN(a,b) ((a<b)?a:b)
#define MAX(a,b) ((a>b)?a:b)

#ifdef IVMFS_DUMPFILECONTENTS
#define IVMFS_DUMPFILES
#endif

typedef long fid_t;

static fid_t ofiles = FIRST_FILENO; //ever opened files

typedef struct {
    char* name;
    unsigned long size;
    char** data;
    unsigned long pos;
    fid_t fid; // 0 = closed
    int flags; // open() flags
    // If allocated == 0, the file has not been written
    unsigned long allocated;
} file_t;

EEOOPP
}


print_files() {

    if ! which hexdump >& /dev/null; then
        >&2 echo "hexdump not found; it is required by this script" 
        exit 1
    fi

    declare -A file_entry
    PACK=8
    if test $PACK -eq 4; then
        # Dump 4-byte words
        hdf() { hexdump -v -e '16/4 "%d, " "\n"' < "$1" | sed 's/, *,//g'; }
    elif test $PACK -eq 8; then
        # Dump 8-byte words (hexdump not supporting 16/8, so concatenating parts with sed)
        hdf() { hexdump -v -e '16/4 "0x%08x, " "\n"' < "$1" | sed -E 's/, 0x +//g' | sed -E 's/0x([0-9a-f]+)\s*,\s*0x([0-9a-f]+)/0x\2\1/g'; }
    else
        # Dump bytes
        hdf() { hexdump -v -e '16/1 "%d, " "\n"' < "$1" | sed 's/, *,//g'; }
    fi

    n=0
    while test $# -gt 0
    do
        if test -f "$1"
        then
            # For each file print a c statement like this;
            #   static char *file0 = (char[]){72, 101, 108, 108, 111};
            if test $PACK -eq 4; then
                echo "static uint32_t *file${n} = (uint32_t[]){$(hdf "$1")};" | sed 's/, *}/}/g'
            elif test $PACK -eq 8; then
                echo "static uint64_t *file${n} = (uint64_t[]){$(hdf "$1")};" | sed 's/, *}/}/g'
            else
                echo "static char *file${n} = (char[]){$(hdf "$1")};" | sed 's/, *}/}/g'
            fi

            # For each file, generate a statement initializing the
            # file descriptor of type file_t:
            #   // filename, filesize, (double) pointer to data, position, open file id, flags, allocated
            #   {"filename.txt", 6, &file0, 0, 0, 0, 0}
            size=$(wc -c < "$1")
            file_entry[$n]='{"'$1'"'", $size, (char**)&file${n}, 0, 0, 0, 0}"
        fi
        let n=n+1
        shift
    done

    # Print all initialization statements into one only array:
    #    static file_t filesystem[NFILES] =
    #    {
    #        {"file0.txt", 6, &file0, 0, 100},
    #        {"file1.txt", 2, &file1, 0, 200},
    #        ...
    #        {NULL, 0, NULL, 0, 0}
    #    };

    # Fix a number of max files
    MAXFILES=$(( 2*$n + 64 ))
    echo "#define MAX_FILES $MAXFILES"
    echo "static unsigned long nfiles = $n; // Files initially in the filesystem"
    echo
    echo "static file_t filesystem[MAX_FILES] ="
    echo '{'
    for f in ${!file_entry[@]}
    do
        echo '   ' ${file_entry[$f]}','
    done
    #echo '    {NULL, 0, NULL, 0, 0}'
    echo '};'

}

print_functions() {
cat << EEOOFF

// Get the index of an open file in the filesystem
// struct from its fid (fid -> idx)
// Return -1 if not open/not existing
static long find_open_file(fid_t fid)
{
    if (fid < FIRST_FILENO) {return -1;}
    long idx;
    for (idx=0; idx < nfiles; idx++){
        if (filesystem[idx].fid == fid){
            return idx;
        }
    }
    return -1;
}

// Get the index of a file in the filesystem struct
// from its name (name -> idx)
// Return -1 if not existing
static long find_file(char* name)
{
    long idx;
    for (idx=0; idx < nfiles; idx++){
        if (! strcmp(filesystem[idx].name, name)) {
            return idx;
        }
    }
    return -1;
}

static unsigned long dump_file_content(char *name)
{
    FILE* fp = fopen(name, "r");
    unsigned long s = 0;
    if (fp){
        for (int ch = getc(fp); ch != EOF; ch = getc(fp)) {
            fputc(ch, stderr);
            s++;
        }
        fclose(fp);
    }
    return s;
}

static void dump_all_files(void)
{
    for (long idx=0; idx<nfiles; idx++){
        char *name = filesystem[idx].name;
        unsigned long size = filesystem[idx].size;
        fprintf(stderr, "\n=======================================\n");
        fprintf(stderr, "filesystem[%ld]: '%s' %ld bytes\n",
              idx, name, size);
        fprintf(stderr, "=======================================\n");
    #ifdef IVMFS_DUMPFILECONTENTS
        unsigned long l=dump_file_content(name);
    #endif
    }
}

int open(const char *name, int flags, ...)
{
    /*
      +-------------+-------------------------------+
      |fopen() mode | open() flags                  |
      +-------------+-------------------------------+
      |     r       | O_RDONLY                      |
      +-------------+-------------------------------+
      |     w       | O_WRONLY | O_CREAT | O_TRUNC  |
      +-------------+-------------------------------+
      |     a       | O_WRONLY | O_CREAT | O_APPEND |
      +-------------+-------------------------------+
      |     r+      | O_RDWR                        |
      +-------------+-------------------------------+
      |     w+      | O_RDWR | O_CREAT | O_TRUNC    |
      +-------------+-------------------------------+
      |     a+      | O_RDWR | O_CREAT | O_APPEND   |
      +-------------+-------------------------------+
    */

    #ifdef IVMFS_DUMPFILES
    static int registered_dump = 0;
    if (! registered_dump){
        registered_dump = 1;
        atexit(dump_all_files);
    }
    #endif

    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[open] name=%s, flags=0x%x\n", name, flags);
    #endif

    long idx = find_file((char*)name);

    // Existing file
    if (idx >= 0) {
        if (! strcmp(name, filesystem[idx].name)){
            // Otherwise check if the file exists
            ofiles++;
            filesystem[idx].fid = ofiles;
            filesystem[idx].pos = 0;
            filesystem[idx].flags = flags;

            // if O_TRUNC, start from the beginning as a new file
            if (filesystem[idx].flags & O_TRUNC){
                    filesystem[idx].size = 0;
                    filesystem[idx].pos = 0;
            }

            #ifdef IVMFS_DEBUG
                fprintf(stderr, "[open] OK name=%s, flags=0x%x, fid=%ld\n", name, flags, ofiles);
            #endif

            return filesystem[idx].fid;
        }
    }

    // New file
    if (flags & O_CREAT) {
        if (nfiles < MAX_FILES - 1){
            ofiles++;
            idx = nfiles++;
            filesystem[idx].name = strdup(name);
            filesystem[idx].size = 0;
            filesystem[idx].pos = 0;
            filesystem[idx].fid = ofiles;
            filesystem[idx].flags = flags;
            filesystem[idx].allocated = 0;
            #ifdef IVMFS_DEBUG
                fprintf(stderr, "[open] NEW file: name=%s, flags=0x%x, idx=%ld, fid=%ld\n", name, flags, idx, ofiles);
            #endif
            return filesystem[idx].fid;
        } else {
            #ifdef IVMFS_DEBUG
                fprintf(stderr, "[open] NO RESOURCES for NEW file\n");
            #endif
            errno = ENOMEM;
            return -1;
        }
    }

    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[open] FAIL name=%s, flags=0x%x\n", name, flags);
    #endif

    errno = ENOSYS;
    return -1;
}


// Recreated stdin from file STDIN_FILE
static fid_t get_stdin_fileno(void){
    static fid_t stdin_fid = -2;
    if (stdin_fid == -2) {
        // STDIN_FILE not yet open
        // If open() fails, it would return -1
        // and will not retry opening stdin
        // again any more
        stdin_fid = open(STDIN_FILE, 0);
    }
    return stdin_fid;
}

ssize_t read(fid_t fid, char *buf, size_t len)
{
    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[read] fid=%ld len=%ld\n", fid, len);
    #endif

    if (STDIN_FILENO == fid){
        fid = get_stdin_fileno();
        if (fid == -1)
            return  0; // EOF
    }

    long idx = find_open_file(fid);

    if (idx < 0) {
      errno = EBADF;
      return  -1;
    }else {
      len = MIN(len, filesystem[idx].size - filesystem[idx].pos);
      if (len > 0){
          memcpy(buf, *(filesystem[idx].data) + filesystem[idx].pos, len);
          filesystem[idx].pos += len;
      }
      return len;
    }
}

int close (fid_t fid)
{
    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[close] fid=%ld\n", fid);
    #endif

    if (fid < FIRST_FILENO){
        // Trying to close stdin, stdout, stderr
        return 0;
    }
    long idx = find_open_file(fid);
    if (idx < 0) {
        errno = EBADF;
        return  -1;
    }else {
        filesystem[idx].pos = 0;
        filesystem[idx].fid = 0;
        return 0;
    }
}


off_t lseek (fid_t file, off_t offset, int whence)
{
    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[lseek] fid=%ld, offset=%ld, whence=%d\n", file, offset, whence);
    #endif

    long idx;
    unsigned long newpos;
    if ((STDOUT_FILENO == file) || (STDERR_FILENO == file)) {
        return  0;
    }

    if (STDIN_FILENO == file) {
        file = get_stdin_fileno();
    }

    if ((idx = find_open_file(file)) >= 0){
        switch(whence){
            case SEEK_CUR:
                newpos = filesystem[idx].pos + offset;
                break;
            case SEEK_END:
                newpos = filesystem[idx].size + offset;
                break;
            case SEEK_SET:
            default:
                newpos = offset;
                break;
        }
        if (newpos > filesystem[idx].size){
            // This implementation does not allow file resizing
            errno = EINVAL;
            return (off_t) -1;
        } else {
            filesystem[idx].pos = newpos;
            return newpos;
        }
    } else {
        errno = EBADF;
        return  (off_t) -1;
    }
}


__attribute__((optimize("O0")))
__attribute__((noinline, noclone))
static int _IVM64_putchar(int arg)
{
    unsigned char ascii = arg;
    int retval = ascii;

    #ifdef __ivm64__
        asm volatile ("load1! %0\n": "=m" (ascii));
        asm volatile ("put_char");
    #else
        retval = putchar(arg);
    #endif
    return retval;
}

ssize_t write(fid_t fid, char *ptr, size_t nbytes)
{
    int cont;
    char c;
    unsigned long allocated;

    if ((fid == STDOUT_FILENO) || (fid == STDERR_FILENO))
    {
        for (cont=0; cont<nbytes; cont++){
             c = ptr[cont];
             _IVM64_putchar(c);
        }
        return cont;
    } else {
        long idx = find_open_file(fid);

        #ifdef IVMFS_DEBUG
            // Never debug writing in stderr/stdout as it will
            // result in infinity recursion
            fprintf(stderr, "[write] fid=%ld, nbytes=%ld, pos=%ld\n", fid, nbytes, (idx<0)?-1:filesystem[idx].pos);
        #endif

        if (idx < 0) {
            errno = EBADF;
            return  -1;
        }else {
            if (filesystem[idx].flags & O_RDONLY){
               // Readonly
               errno = EBADF;
               return -1;
            }

            // Let's see if there is enough space
            if (filesystem[idx].allocated == 0) {
                // The file is not written yet
                // Allocate enough space in the worst case
                allocated = BLKSIZE *((nbytes + 1 + filesystem[idx].size)/BLKSIZE + 1);

                char **p = (char **)malloc(sizeof(char*));
                *p = (char *)malloc(allocated * sizeof(char));
                if (!p || !(*p)){
                    errno = EBADF;
                    return  -1;
                }
                filesystem[idx].allocated = allocated;

                // Dump the original content
                if (filesystem[idx].size > 0)
                    memcpy(*p, *(filesystem[idx].data), filesystem[idx].size);

                // update pointer to content
                filesystem[idx].data = p;

                #ifdef IVMFS_DEBUG
                    fprintf(stderr, "[write] allocated %ld bytes\n", allocated);
                #endif

            } else {
                // The file is dirty and may need more space
                unsigned int finalbyte = filesystem[idx].pos + nbytes - 1;
                if (finalbyte >= filesystem[idx].allocated) {
                    allocated = BLKSIZE *((nbytes + 1 + filesystem[idx].allocated)/BLKSIZE + 1);
                    char **p = filesystem[idx].data;
                    *p = (char *)realloc(*(filesystem[idx].data), allocated * sizeof(char));

                    if (!p){
                      errno = EBADF;
                      return  -1;
                    }
                    filesystem[idx].allocated = allocated;
                    filesystem[idx].data = p;

                    #ifdef IVMFS_DEBUG
                        fprintf(stderr, "[write] re-allocated %ld bytes\n", allocated);
                    #endif
                }
            }

            // Write the bytes to the file, and update size and position
            memcpy(*(filesystem[idx].data) + filesystem[idx].pos, ptr, nbytes);
            filesystem[idx].size = MAX(filesystem[idx].size, filesystem[idx].pos + nbytes);
            filesystem[idx].pos += nbytes;

            return nbytes;
        }
    }
}

inline
static int istat(long idx, struct stat *st)
{
    struct stat S;

    S.st_dev = 1;       /* ID of device containing file */
    S.st_ino = idx;     /* Inode number */
    S.st_mode = 0777;   /* File type and mode */
    S.st_nlink = 1;     /* Number of hard links */
    S.st_uid = 0;       /* User ID of owner */
    S.st_gid = 0;       /* Group ID of owner */
    S.st_rdev = 0;      /* Device ID (if special file) */

    S.st_size = filesystem[idx].size;   /* Total size, in bytes */
    S.st_blksize = BLKSIZE;             /* Block size for filesystem I/O */
    /* Number of 512B blocks allocated */
    S.st_blocks = (MAX(filesystem[idx].size, filesystem[idx].allocated)+(512-1))/512;

    *st = S;
    return 0;
}

int stat(const char *file, struct stat *st)
{
    struct stat S;
    long idx;

    if ((idx = find_file((char*)file)) < 0) {
        errno = ENOENT;
        return -1;
    }

    return istat(idx, st);
}

int fstat(int fid, struct stat *st)
{
    struct stat S;
    long idx;

    if ((idx = find_open_file(fid)) < 0) {
        errno = ENOENT;
        return -1;
    }

    return istat(idx, st);
}

int access(const char *pathname, int mode)
{
   struct stat s;
   return stat(pathname, &s);
}

int faccessat(int dirfd, const char *pathname, int mode, int flags)
{
    access(pathname, mode);
}


#endif /*__ivm64__*/
EEOOFF
}

#--------------------
print_header
print_preamble
print_files "$@"
print_functions
