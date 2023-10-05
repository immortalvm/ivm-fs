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
# Note that files or directories are added individually to the filesystem and,
# therefore, to add a folder recursively you may wish to do:
#
#     ivmfs-gen.sh $(find folder_name) ... > ivmfs.c
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
# Date: Ago 2020 - Jun 2023

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

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdarg.h>
#include <string.h>

// strdup is not a standard C function; it may fail if compiler
// is asked to be strict C compliant (e.g., -std=c++14)
char* strdup (const char* s);

// Which char is consider EOF (^D = 4)
#ifdef __ivm64__
#define SYSTEM_EOF 4
#else
#define SYSTEM_EOF EOF
#endif

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define FIRST_FILENO  3

// First inode number of this filesystem
// Below this number, the inode number may be reserved
#define IVMFS_FIRST_INO() 1000

// The default initial current directory
#define IVMFSROOT "/work"

// This file will emulate STDIN
#define STDIN_FILE IVMFSROOT"/stdin"

// When the file grows a multiple of this is allocated
#define BLKSIZE 64

// Allocate these extra blocks when writting
#define EXTRABLKS 8

// MAX/MIN only one evaluation
#define MIN(a,b) ({__typeof__(a) _a=(a); __typeof__(b) _b=(b); (_a < _b)?_a:_b;})
#define MAX(a,b) ({__typeof__(a) _a=(a); __typeof__(b) _b=(b); (_a > _b)?_a:_b;})

#ifdef IVMFS_DUMPFILECONTENTS
#define IVMFS_DUMPFILES
#endif

// Define this to include special symbols . and .. in directory listings
#define IVMFS_GETDENTS_RETURNS_DOT_DIRS


// See newlib/libc/include/sys/_default_fcntl.h
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH          16
#endif

// Linux specific flag
#ifndef O_TMPFILE
#define O_TMPFILE   0x800000
#endif

// Declare fid_t as int to be coherent with unistd.h declarations
typedef int fid_t;

// Prototypes of static FS's implementation functions
static int open0(const char *name, int flags, ...);
static int openat0(int dirfd, const char *pathname, int flags, ...);
static int close0(fid_t fid);
static ssize_t read0(fid_t fid, void *vbuf, size_t len);
static ssize_t write0(fid_t fid, const void *vptr, size_t nbytes);
static off_t lseek0(fid_t file, off_t offset, int whence);
static int stat0(const char *file, struct stat *st);
static int fstat0(int fid, struct stat *st);
static int lstat0(const char *pathname, struct stat *st);
static int access0(const char *pathname, int mode);
static int faccessat0(int dirfd, const char *pathname, int mode, int flags);
static int fstatat0(int dirfd, const char *pathname, struct stat *statbuf, int flags);
static int fsync0(int fd);
static int fdatasync0(int fd);
static int utimes0(const char *filename, const struct timeval times[2]);
static char* getcwd0(char *buf, size_t size);
static char *get_current_dir_name0(void);
static int truncate0(const char *path, off_t length);
static int ftruncate0(int fd, off_t length);
static int fcntl0(int fd, int cmd, ...);
static int unlink0(const char *pathname);
static int unlinkat0(int dirfd, const char *pathname, int flags);
static int rmdir0(const char *pathname);
static int mkdir0(const char *pathname, mode_t mode);
static int mkdirat0(int dirfd, const char *pathname, mode_t mode);
static int chdir0(const char *path);
static int fchdir0(int fd);
static int rename0(const char *oldpath, const char *newpath);
static int renameat0(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
static long getdents0(unsigned int fd, struct dirent *dirp, unsigned int count);
static void _seekdir0(DIR *dirp, long loc);
static ssize_t readlink0(const char *pathname, char *buf, size_t bufsiz);
static ssize_t readlinkat0(int dirfd, const char *pathname, char *buf, size_t bufsiz);
static int dup0(int oldfd);
static int dup2_0(int oldfd, int newfd);
static int symlink0(const char *target, const char *linkpath);
static int symlinkat0(const char *target, int newdirfd, const char *linkpath);
static char *realpath0(const char * __restrict path, char * __restrict resolved_path);
static int isatty0(int fd);

// Prototypes of static 'internal' functions
static long find_open_file(fid_t fid);
static long find_file(char* name);
//- static fid_t get_stdin_fileno(void);
static int file_stat(long idx, struct stat *st);
static long create_new_file(const char *name, int flags);
static long delete_file(long idx);
static long find_dir(char* name);
static long find_dir_nocanon(char* name);
static long file_in_dir(char *dir);
static void init_devices();
static void check_cwd();
static int resolve_path_internal(char *path,char *result,char *pos, int nocheck);
static char *realpath_nocheck(const char *path,char *resolved_path);
static char *realparentpath(const char *path, char *resolved_path);

char *dirname(char *path);
char *basename(char *path);

#ifdef IVMFS_DUMPFILES
static unsigned long dump_file_content(char *name);
static void dump_all_files(void);
#endif
static void close_all();

typedef enum filetype_e {IVMFS_REG=0, IVMFS_DIR=1, IVMFS_LNK=2} filetype_t;

typedef struct {
    char* name;
    unsigned long size;
    char** data;
    int flags; // open() flags
    // If allocated == 0, the file has not been written
    unsigned long allocated;
    filetype_t type; // it's a directory
    int nameallocated; // the file has been renamed (allocating the new string)
} file_t;

#define IVMFS_ISREG(a) ((a) == IVMFS_REG)
#define IVMFS_ISDIR(a) ((a) == IVMFS_DIR)
#define IVMFS_ISLNK(a) ((a) == IVMFS_LNK)

typedef enum devtype_e {DEVDISK = 0, DEVSTDIN, DEVSTDOUT, DEVSTDERR} devtype_t;

typedef struct {
    int  open;   // Is an open file or device? (0=free descriptor, 1=open(used))
    long idx;    // If it is an disk file, the index to which file in the file table
    long *pos_p; // File position is stored in this pointer, to be shared when calling dup()
    int flags;
    devtype_t dev; //0=disk file; 1=stdin; 2=stdout; 3=stder
} openfile_t;

EEOOPP
}


print_files() {
    if ! which hexdump >& /dev/null; then
        >&2 echo "hexdump not found; it is required by this script"
        exit 1
    fi

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

    # Associative arrays for file table entries
    declare -A file_entry
    declare -A dir_entry

    # An associative array with the files already processed
    declare -A seenfile

    nf=0
    nd=0

    # Add always '/', '/tmp', and IVMFSROOT
    seenfile["/"]=1
    dir_entry[$nd]='{(char*)"/", 0, (char**)0, 0, 0, IVMFS_DIR, 0}'
    let nd=nd+1
    #
    seenfile["/tmp"]=1
    dir_entry[$nd]='{(char*)"/tmp", 0, (char**)0, 0, 0, IVMFS_DIR, 0}'
    let nd=nd+1
    #
    #do no mark IVMFSROOT as seen, because it is not a true directory,
    #it corresponds to "." and it is defined in the C file
    dir_entry[$nd]='{(char*)IVMFSROOT, 0, (char**)0, 0, 0, IVMFS_DIR, 0}'
    let nd=nd+1

    while test $# -gt 0
    do
        #1>&2 echo "** #=$# @=$@"

        filename=''
        filetype=''
        size=0
        sep=
        # Only include existing regular files whose name is not an empty string
        if ! test -z "$1" && test -f "$1"
        then
            # REGULAR FILES
            size=$(wc -c < "$1")
            filetype=IVMFS_REG # 0=regular file
            sep=
            data="&file${nf}"

        elif ! test -z "$1" && test -d "$1"
        then
            # DIRECTORIES
            size=0
            filetype=IVMFS_DIR # 1=directory
            #sep='/'    # in this fs, directory names are ended by '/'
            sep=''    # now directory names are NOT ended by '/'
            test "$1" == '/' && sep='' # but do not add '/' to the root directory
            data=0
        else
            # Skip other file types (soft links, ...)
            shift
            continue
        fi

        # Get relative/absolute path
        if [[ "$1" =~ ^/.* ]]  ; then
            #Absolute name
            ivmfsroot=
            filename=$(realpath "$1")
        else
            rpath="$(realpath --relative-to=. "$1")"
            if [[ "$rpath" =~ ^[^.] ]] ; then
                #Filename relative to .
                ivmfsroot=IVMFSROOT\"/\"
                filename="$rpath"
            else
                #Filename not relative to ., absolutize it
                ivmfsroot=
                filename=$(realpath "$1")
            fi
        fi

        if ! test -z ${seenfile["$filename"]}; then
            # Do no process the same file twice
            shift
            continue
        fi

        # Create the data for regular files
        # For each file print a c statement like this;
        #   static char *file0 = (char[]){72, 101, 108, 108, 111};
        if test "$filetype" == IVMFS_REG ; then
            if test $PACK -eq 4; then
                echo "static uint32_t *file${nf} = (uint32_t[]){$(hdf "$1")};" | sed 's/, *}/}/g'
            elif test $PACK -eq 8; then
                echo "static uint64_t *file${nf} = (uint64_t[]){$(hdf "$1")};" | sed 's/, *}/}/g'
            else
                echo "static char *file${nf} = (char[]){$(hdf "$1")};" | sed 's/, *}/}/g'
            fi
        fi

        # Create the file/directory entry
        # For each file, generate a statement initializing the
        # file descriptor of type file_t:
        #   // filename, filesize, (double) pointer to data, flags, allocated, type, nameallocated
        #   {"filename.txt", 6, &file0, 0, 0, 0, 0}
        #file_entry[$n]='{(char*)'$ivmfsroot'"'$filename$sep'"'", $size, (char**)$data, 0, 0, $filetype, 0}"

        entry='{(char*)'$ivmfsroot'"'$filename$sep'"'", $size, (char**)$data, 0, 0, $filetype, 0}"
        if test "$filetype" == IVMFS_REG ; then
            # regular file
            file_entry[$nf]=$entry
            let nf=nf+1
        elif test "$filetype" == IVMFS_DIR ; then
            # directory
            dir_entry[$nd]=$entry
            let nd=nd+1
        fi

        seenfile["$filename"]=1

        # Traverse all dirs in the filename path
        # and append them to the argument list,
        # to include also these dirs in the file system
        dirname="$(dirname "$filename")"
        while test -z ${seenfile["$dirname"]} && [[ "$dirname" != "." ]] && [[ "$dirname" != "/" ]]
        do
            set -- "$@" "$dirname"
            dirname="$(dirname "$dirname")"
        done

        shift
    done

    # Number of entries (files+directories)
    n=$(($nf + $nd))

    # Print all initialization statements into one only array:
    #    static file_t filetable0[NFILES] =
    #    {
    #        {"file0.txt", 6, &file0, 0, 100},
    #        {"file1.txt", 2, &file1, 0, 200},
    #        ...
    #        {NULL, 0, NULL, 0, 0}
    #    };
    #    static file_t *filetable = filetable0;

    # Fix a number of max files
    MAXFILES=$(($n))

    echo ''
    echo ''
    cat << EEOOFF
#ifndef NAME_MAX
#define NAME_MAX 256
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_FILES $MAXFILES

// Initial filesystem table
static file_t filetable0[MAX_FILES] =
EEOOFF
#    echo "static file_t filetable[MAX_FILES] ="
    echo '{'
    # First, print directories
    for d in ${!dir_entry[@]}
    #~ for ((d=0; d<$nd; d++))
    do
        echo '   ' ${dir_entry[$d]}','
    done
    # Next, print regular files
    for f in ${!file_entry[@]}
    #~ for ((f=0; f<$nf; f++))
    do
        echo '   ' ${file_entry[$f]}','
    done
    #echo '    {NULL, 0, NULL, 0, 0}'
    echo '};'
    echo ''
}

print_structure() {
    cat << EEOOFF

typedef struct {
    unsigned long openfile_size;
    unsigned long nfiles;
    unsigned long max_files_allocated;
    file_t *filetable0;
    file_t *filetable;
    openfile_t *openfile;
    fid_t stdin_fid;
    char *cwd;

    long spawn_level;
    int close_all_done;
} file_data_t;

typedef struct {
    int (*open)(const char *name, int flags, ...);
    int (*openat)(int dirfd, const char *pathname, int flags, ...);
    int (*close)(fid_t fid);
    ssize_t (*read)(fid_t fid, void *vbuf, size_t len);
    ssize_t (*write)(fid_t fid, const void *vptr, size_t nbytes);
    off_t (*lseek)(fid_t file, off_t offset, int whence);
    int (*stat)(const char *file, struct stat *st);
    int (*fstat)(int fid, struct stat *st);
    int (*lstat)(const char *pathname, struct stat *st);
    int (*access)(const char *pathname, int mode);
    int (*faccessat)(int dirfd, const char *pathname, int mode, int flags);
    int (*fstatat)(int dirfd, const char *pathname, struct stat *statbuf, int flags);
    int (*fsync)(int fd);
    int (*fdatasync)(int fd);
    int (*utimes)(const char *filename, const struct timeval times[2]);
    char* (*getcwd)(char *buf, size_t size);
    char* (*get_current_dir_name)(void);
    int (*truncate)(const char *path, off_t length);
    int (*ftruncate)(int fd, off_t length);
    int (*fcntl)(int fd, int cmd, ...);
    int (*unlink)(const char *pathname);
    int (*unlinkat)(int dirfd, const char *pathname, int flags);
    int (*rmdir)(const char *pathname);
    int (*mkdir)(const char *pathname, mode_t mode);
    int (*mkdirat)(int dirfd, const char *pathname, mode_t mode);
    int (*chdir)(const char *path);
    int (*fchdir)(int fd);
    int (*rename)(const char *oldname, const char *newname);
    int (*renameat)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
    long (*getdents)(unsigned int fd, struct dirent *dirp, unsigned int count);
    void (*_seekdir)(DIR *dirp, long loc);
    ssize_t (*readlink)(const char *pathname, char *buf, size_t bufsiz);
    ssize_t (*readlinkat)(int dirfd, const char *pathname, char *buf, size_t bufsiz);
    int (*dup)(int oldfd);
    int (*dup2)(int oldfd, int newfd);
    int (*symlink)(const char *oldpath, const char *newpath);
    int (*symlinkat)(const char *target, int newdirfd, const char *linkpath);
    char* (*realpath)(const char * __restrict path, char * __restrict resolved_path);
    int (*isatty)(int fd);
} file_oper_t;

typedef struct {
    file_oper_t oper;
    file_data_t data;
} filesystem_t;

static filesystem_t filesystem0 = {
    {
        open: open0,
        openat: openat0,
        close: close0,
        read: read0,
        write: write0,
        lseek: lseek0,
        stat: stat0,
        fstat: fstat0,
        lstat: lstat0,
        access: access0,
        faccessat: faccessat0,
        fstatat: fstatat0,
        fsync: fsync0,
        fdatasync: fdatasync0,
        utimes: utimes0,
        getcwd: getcwd0,
        get_current_dir_name: get_current_dir_name0,
        truncate: truncate0,
        ftruncate: ftruncate0,
        fcntl: fcntl0,
        unlink: unlink0,
        unlinkat: unlinkat0,
        rmdir: rmdir0,
        mkdir: mkdir0,
        mkdirat: mkdirat0,
        chdir: chdir0,
        fchdir: fchdir0,
        rename: rename0,
        renameat: renameat0,
        getdents: getdents0,
        _seekdir: _seekdir0,
        readlink: readlink0,
        readlinkat: readlinkat0,
        dup: dup0,
        dup2: dup2_0,
        symlink: symlink0,
        symlinkat: symlinkat0,
        realpath: realpath0,
        isatty: isatty0,
    },
    {
        openfile_size: 0,
        nfiles: MAX_FILES,
        max_files_allocated: 0,
        filetable0: filetable0,
        filetable: filetable0,
        openfile: NULL,
        stdin_fid: -2,
        cwd: (char*)IVMFSROOT,
        spawn_level: 0,
        close_all_done: 0,
    },
};

static filesystem_t *filesystem = &filesystem0;

EEOOFF
}

print_functions() {
cat << EEOOFF

__attribute__((constructor))
void __IVMFS_start__(void)
{
    #ifdef IVMFS_DEBUG
    printf("[%s] IVMFS begins ...\n", __func__);
    #endif

    void *newfs = NULL;
    char *newFSstr = getenv("IVM_CRT0_FILESYSTEM");
    if (newFSstr) {

        newfs = (void*)(unsigned long)strtol(newFSstr, NULL, 16);
    }
    if (newfs) {

        fflush(stdout);
        fflush(stderr);
        filesystem = (filesystem_t*) newfs;
        filesystem->data.spawn_level++;
    }
    else {

        filesystem->data.spawn_level = 0;

        init_devices();

        check_cwd();

        char fsno[64];
        snprintf(fsno, 64, "%#lx", (unsigned long)filesystem);
        setenv("IVM_CRT0_FILESYSTEM", fsno, 1);
    }

    filesystem->data.close_all_done = 0;
    atexit(close_all);

    #ifdef IVMFS_DUMPFILES
    atexit(dump_all_files);
    #endif
}

__attribute__((destructor))
void __IVMFS_end__(void)
{
    #ifdef IVMFS_DEBUG
    printf("[%s] IVMFS ends ...\n", __func__);
    #endif
    filesystem->data.spawn_level = MAX(0,filesystem->data.spawn_level-1);
    filesystem->data.close_all_done = 0;
}

int open(const char *name, int flags, ...)
{
    va_list arg;
    va_start(arg, flags);
    int res = filesystem->oper.open(name, flags, arg);
    va_end(arg);
    return res;
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
    va_list arg;
    va_start(arg, flags);
    int res = filesystem->oper.openat(dirfd, pathname, flags, arg);
    va_end(arg);
    return res;
}

int close(fid_t fid)
{
    return filesystem->oper.close(fid);
}

ssize_t read(fid_t fid, void *vbuf, size_t len)
{
    return filesystem->oper.read(fid,vbuf,len);
}

ssize_t write(fid_t fid, const void *vptr, size_t nbytes)
{
    return filesystem->oper.write(fid,vptr,nbytes);
}

off_t lseek(fid_t file, off_t offset, int whence)
{
    return filesystem->oper.lseek(file,offset,whence);
}

int stat(const char *file, struct stat *st)
{
    return filesystem->oper.stat(file,st);
}

int fstat(int fid, struct stat *st)
{
    return filesystem->oper.fstat(fid,st);
}

int lstat(const char *pathname, struct stat *st)
{
    return filesystem->oper.lstat(pathname,st);
}

int access(const char *pathname, int mode)
{
    return filesystem->oper.access(pathname,mode);
}

int faccessat(int dirfd, const char *pathname, int mode, int flags)
{
    return filesystem->oper.faccessat(dirfd,pathname,mode,flags);
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    return filesystem->oper.fstatat(dirfd,pathname,statbuf,flags);
}

int fsync(int fd)
{
    return filesystem->oper.fsync(fd);
}

int fdatasync(int fd)
{
    return filesystem->oper.fdatasync(fd);
}

int utimes(const char *filename, const struct timeval times[2])
{
    return filesystem->oper.utimes(filename,times);
}

char* getcwd(char *buf, size_t size)
{
    return filesystem->oper.getcwd(buf, size);
}

char *get_current_dir_name(void)
{
    return filesystem->oper.get_current_dir_name();
}

int truncate(const char *path, off_t length)
{
    return filesystem->oper.truncate(path,length);
}

int ftruncate(int fd, off_t length)
{
    return filesystem->oper.ftruncate(fd,length);
}

int fcntl(int fd, int cmd, ...)
{
    va_list arg;
    va_start(arg, cmd);
    int res = filesystem->oper.fcntl(fd,cmd,arg);
    va_end(arg);
    return res;
}

int unlink(const char *pathname)
{
    return filesystem->oper.unlink(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags)
{
    return filesystem->oper.unlinkat(dirfd, pathname, flags);
}

int rmdir(const char *pathname)
{
    return filesystem->oper.rmdir(pathname);
}

int mkdir(const char *pathname, mode_t mode)
{
    return filesystem->oper.mkdir(pathname,mode);
}

int mkdirat(int dirfd, const char *pathname, mode_t mode)
{
    return filesystem->oper.mkdirat(dirfd, pathname, mode);
}

int chdir(const char *path)
{
    return filesystem->oper.chdir(path);
}

int fchdir(int fd)
{
    return filesystem->oper.fchdir(fd);
}

int rename(const char *oldpath, const char *newpath)
{
    return filesystem->oper.rename(oldpath, newpath);
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    return filesystem->oper.renameat(olddirfd, oldpath, newdirfd, newpath);
}

long getdents(unsigned int fd, struct dirent *dirp, unsigned int count){
    return filesystem->oper.getdents(fd, dirp, count);
}

void _seekdir(DIR *dirp, long loc)
{
    return filesystem->oper._seekdir(dirp,loc);
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    return filesystem->oper.readlink(pathname, buf, bufsiz);
}

ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    return filesystem->oper.readlinkat(dirfd, pathname, buf, bufsiz);
}

int dup(int oldfd)
{
    return filesystem->oper.dup(oldfd);
}

int dup2(int oldfd, int newfd)
{
    return filesystem->oper.dup2(oldfd, newfd);
}

int symlink(const char *target, const char *linkpath)
{
    return filesystem->oper.symlink(target, linkpath);
}

int symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    return filesystem->oper.symlinkat(target, newdirfd, linkpath);
}

char* realpath(const char * __restrict path, char * __restrict resolved_path)
{
    return filesystem->oper.realpath(path, resolved_path);
}

int isatty(int fd)
{
    return filesystem->oper.isatty(fd);
}

static char ivm64_getbyte()
{
    static unsigned long res;
    asm volatile("read_char\n\t"
                 "store8! %0":"=m"(res));
    return (unsigned char)res;
}
#define ivm64_outbyte_const(c) ({asm volatile ("put_char! %0": : "i" (c));})
#define ivm64_outbyte_var(c)   ({asm volatile ("load1! %0\n\tput_char": :"rm" (c));})
#define ivm64_outbyte(c)       (__builtin_constant_p(c)?ivm64_outbyte_const(c):ivm64_outbyte_var(c))

#define read_char ivm64_getbyte
#define put_char  ivm64_outbyte

static uint8_t read_utf8char() {
    static uint32_t c;
    static uint8_t buff[4];
    static int count=0, pos=0;

    if (pos == count) {

        asm volatile("read_char\n\t"
                     "store4! %0":"=m"(c));

        count = 0;
        pos = 0;
        buff[0]=0; buff[1]=0; buff[2]=0; buff[3]=0;

        if (c < 0x80) {
            buff[count++] = (uint8_t) c;
        } else if (c < 0x800) {
            buff[count++] = (uint8_t) (0xc0 | c >> 6);
            buff[count++] = (uint8_t) (0x80 | (0x3f & c));
        } else if (c < 0x10000) {
            buff[count++] = (uint8_t) (0xe0 | c >> 12);
            buff[count++] = (uint8_t) (0x80 | (0x3f & c >> 6));
            buff[count++] = (uint8_t) (0x80 | (0x3f & c));
        } else {
            buff[count++] = (uint8_t) (0xf0 | (0x07 & c >> 18));
            buff[count++] = (uint8_t) (0x80 | (0x3f & c >> 12));
            buff[count++] = (uint8_t) (0x80 | (0x3f & c >> 6));
            buff[count++] = (uint8_t) (0x80 | (0x3f & c));
        }
    }

    return buff[pos++];
}

static void put_utf8char(uint8_t c) {
    static int c0, c1, c2, c3;
    static uint32_t u0, u1, u2, u3;
    static int pos=0;
    uint32_t ret = 0;

    if (pos == 0) {
        pos++;
        c0 = c;
        u0 = (uint32_t)c0;
        if (c0 < 0x80){
            ret = u0;
            goto to_console;
        }
        u0 &= 0x1f;
        return;
    }
    else if (pos == 1) {
        pos++;
        c1 = c;
        u1 = (uint32_t)(c1 & 0x3f);
        if (c0 < 0xe0) {
            ret = (u0 << 6) + u1;
            goto to_console;
        }
        return;
    }
    else if (pos == 2) {
        pos++;
        c2 = c;
        u2 = (uint32_t)(c2 & 0x3f);
        if (c0 < 0xf0) {
            ret = (u0 << 12) + (u1 << 6) + u2;
            goto to_console;
        }
        return;
    }
    else {
        c3 = c;
        u3 = (uint32_t)(c3 & 0x3f);
        ret = (u0 << 18) + (u1 << 12) + (u2 << 6) + u3;
    }

    to_console:

        asm volatile ("load4! %0\n\tput_char": :"rm" (ret));
        pos = 0;
        return;
}

#if 1
#ifdef put_char
    #undef put_char
    #define put_char  put_utf8char
#endif
#ifdef read_char
    #undef read_char
    #define read_char read_utf8char
#endif
#endif

#define RLIMIT_NOFILE 64*1024
static openfile_t* reallocate_openfile(fid_t fid)
{
    ssize_t oldsize = filesystem->data.openfile_size;
    ssize_t newsize = MIN(fid*2 + 1, RLIMIT_NOFILE);

    #ifdef IVMFS_DEBUG
        printk("[%s] oldsize=%ld, newsize=%ld\n", __func__, oldsize, newsize);
    #endif

    openfile_t *newof = (openfile_t*)realloc(filesystem->data.openfile, newsize*sizeof(openfile_t));
    if (newof) {
        memset(&newof[oldsize], 0, (newsize-oldsize)*sizeof(openfile_t));
        filesystem->data.openfile_size = newsize;
        filesystem->data.openfile = newof;
    }
    if (fid >= filesystem->data.openfile_size) {

        return NULL;
    }
    return newof;
}

static fid_t openfile_entry(long idx)
{
    fid_t fid;
    for (fid = 0; fid < filesystem->data.openfile_size; fid++) {
        if (filesystem->data.openfile[fid].open == 0) break;
    }
    if (fid >= filesystem->data.openfile_size) {
        openfile_t *of = reallocate_openfile(fid);
        if (!of) {
            errno = ENFILE;
            fid = -1;
        }
    }
    if (fid >= 0) {
        openfile_t *of = &filesystem->data.openfile[fid];
        of->open = 1;
        of->idx = idx;
        of->flags = 0;
        of->dev = DEVDISK;

        of->pos_p = (long*)malloc(sizeof(long));
        *(of->pos_p) = 0;
    }
    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[openfile_entry] idx=%ld, fid=%d\n", idx, fid);
    #endif
    return fid;
}

static int is_valid_fileno(fid_t fid)
{
    return (fid >=0
            && fid < filesystem->data.openfile_size
            && filesystem->data.openfile[fid].open);
}

static long find_open_file(fid_t fid)
{

    if (fid < 0) {
        errno = EBADF;
        return -1;
    }
    long idx = -1;
    if (fid < filesystem->data.openfile_size) {
        if (filesystem->data.openfile[fid].open){
            idx = filesystem->data.openfile[fid].idx;
        }
    }
    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[find_open_file] fid=%d, idx=%ld", fid, idx);
        if (idx>=0){
            fprintf(stderr, " pos=%ld size=%ld", *filesystem->data.openfile[fid].pos_p, filesystem->data.filetable[idx].size);
        }
        fprintf(stderr, "\n");
    #endif
    return idx;
}

static void free_pos_pointer(fid_t fid){
    if (!is_valid_fileno(fid)){
        return;
    }
    long *pos_p = filesystem->data.openfile[fid].pos_p;
    int reused = 0;
    for (long k = 0; k < filesystem->data.openfile_size; k++) {
        if ( k != fid
             && filesystem->data.openfile[k].open
             && filesystem->data.openfile[k].pos_p == pos_p)
        {
            reused = 1;
            break;
        }
    }
    if (!reused && pos_p){
        free(pos_p);
        filesystem->data.openfile[fid].pos_p = NULL;
    }
}

static long remove_open_file(fid_t fid)
{
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] fid=%d\n", __func__, fid);
    #endif

    if (!is_valid_fileno(fid)){
        return -1;
    }
    long idx = -1;
    if (DEVDISK == filesystem->data.openfile[fid].dev){

        idx = find_open_file(fid);
        if (idx >= 0){
            free_pos_pointer(fid);
            filesystem->data.openfile[fid] = (openfile_t){0, 0, 0, 0, DEVDISK};
        }
    }
    return idx;
}

static long remove_open_device(fid_t fid)
{
    if (filesystem->data.spawn_level > 0
        && filesystem->data.close_all_done) {

        return 0;
    }

    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] fid=%d\n", __func__, fid);
    #endif

    if (!is_valid_fileno(fid)){
        return -1;
    }

    long err = -1;
    if (DEVDISK != filesystem->data.openfile[fid].dev){
        if (filesystem->data.openfile[fid].open){

            filesystem->data.openfile[fid] = (openfile_t){0, 0, 0, 0, DEVDISK};
            err = 0;
        }
    }
    return err;
}

static void open_device(int fd) {
    if (filesystem->data.openfile_size < FIRST_FILENO) {
         reallocate_openfile(FIRST_FILENO);
    }
    static long pos = 0;

    openfile_t newopenfile = (openfile_t){1, -1, &pos, 0, DEVSTDIN};

    switch (fd) {
        case STDIN_FILENO:
            filesystem->data.openfile[fd] = newopenfile;
            filesystem->data.openfile[fd].dev = DEVSTDIN;
            break;
        case STDOUT_FILENO:
            filesystem->data.openfile[fd] = newopenfile;
            filesystem->data.openfile[fd].dev = DEVSTDOUT;
            break;
        case STDERR_FILENO:
            filesystem->data.openfile[fd] = newopenfile;
            filesystem->data.openfile[fd].dev = DEVSTDERR;
            break;
    }
}

static void init_devices()
{
    open_device(STDIN_FILENO);
    open_device(STDOUT_FILENO);
    open_device(STDERR_FILENO);

    int fd =  open(STDIN_FILE, 0);
    if (fd >= 0){
        dup2(fd, STDIN_FILENO);
        close(fd);
    }
}

static fid_t find_fileno(long idx)
{
    if (idx < 0 || idx >= filesystem->data.nfiles) {
        return -2;
    }
    fid_t fid = (fid_t)(-1);
    long eidx = idx;
    for (fid_t ifid = 0; ifid < filesystem->data.openfile_size; ifid++) {
        if (filesystem->data.openfile[ifid].open
            && filesystem->data.openfile[ifid].idx == eidx){
            fid = ifid;
            break;
        }
    }
    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[%s] file entry idx=%ld -> fid=%d ('%s')\n", __func__, idx, fid, filesystem->data.filetable[eidx].name);
    #endif
    return fid;
}

static void close_all()
{
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[close_all]");
    #endif

    filesystem->data.close_all_done = 1;
    if (filesystem->data.spawn_level > 0) {
         return;
    }

    for (int fid = FIRST_FILENO; fid < filesystem->data.openfile_size; fid++) {
        if (filesystem->data.openfile[fid].open) {
            #ifdef IVMFS_DEBUG
            fprintf(stderr, "[%s] closing fid=%ld\n", __func__, fid);
            #endif
            close(fid);
        }
    }
}

#define get_position(FID) (*(filesystem->data.openfile[FID].pos_p))
#define set_position(FID,POS) do{*(filesystem->data.openfile[FID].pos_p)=(POS);}while(0)

static char *add_slash(char *buff, char *name){
    unsigned long l = strnlen(name, PATH_MAX+1);
    if (((l == (PATH_MAX-1)) && (name[l-2]!='/')) || (l >= PATH_MAX)){
        return NULL;
    }
    strcpy(buff, name);
    if (buff[0] && buff[l-1] != '/') {
        buff[l] = '/';
        buff[l+1] = '\0';
    }
    return buff;
}

static int has_trail(char *path){
    if (!*path) return 0;
    unsigned long l = strlen(path);
    if (l>1 && '/' == path[l-1]) return 1;
    if (l>2 && '/' == path[l-2] && '.' == path[l-1]) return 1;
    if (l>3 && '/' == path[l-3] && '.' == path[l-2] && '.' == path[l-1]) return 1;
    return 0;
}

static char *remove_trail2(char *path, char *path_copy, char *trail){
    long l = strnlen(path, PATH_MAX);
    strcpy(path_copy, path);
    if (!path_copy) return NULL;
    char *p = &path_copy[l-1];
    char *p0 = &path_copy[0];
    char trail_draft[PATH_MAX]; trail_draft[PATH_MAX-1]='\0';
    char *t= &trail_draft[PATH_MAX-2];
    while (p && p >= p0){
        if ((p-p0)>0 && '/' == *p) {
           *t=*p; t--;
           *p = '\0'; p--;
        }
        else if ((p-p0)>1 && '/' == *(p-1) && '.' == *p) {
            *(t-1)='/'; *t='.'; t-=2;
            *(p-1) = '\0'; p-=2;
        }
        else if ((p-p0)>2 && '/' == *(p-2) && '.' == *(p-1) && '.' == *p) {
            *(t-2)= '/' ; *(t-1)='.'; *t='.'; t-=3;
            *(p-2) = '\0'; p-=3;
        }
        else break;
    }
    strcpy(trail, t+1);

    if (*trail) {
        char dummybuff[PATH_MAX+1], dummyreal[PATH_MAX+1];
        char *dummystr = (char*)"/_dummy_";
        strcpy(dummybuff, dummystr);
        strcat(dummybuff, "/");
        strcat(dummybuff, trail);
        char *rl = realpath_nocheck(dummybuff, dummyreal);
        #ifdef IVMFS_DEBUG
        fprintf(stderr, "[%s] trail='%s' dummybuff='%s' dummyreal='%s'\n",__func__, trail, dummybuff, rl);
        #endif
        if (rl && !strcmp(dummystr, rl)) {

            strcpy(trail, "");
        }
    }

    return p0;
}

static int is_prefix(char *dirname, char* pathname){
    long ldirname = strlen(dirname);
    return  !strncmp(dirname, pathname, ldirname)
            && (1 == ldirname || '/' == pathname[ldirname]);
}

static int is_prefix_or_equal(char *dirname, char* pathname){
    long ldirname = strlen(dirname);
    return  !strncmp(dirname, pathname, ldirname)
            && (1 == ldirname || '/' == pathname[ldirname]
                || ('\0' == dirname[ldirname] && '\0' == pathname[ldirname]));
}

static long find_file(char* name)
{
    #ifdef IVMFS_DEBUG
    #define IVMFS_DEBUG_FIND_FILE
    #endif

    if (!name || !*name) {
        return -1;
    }
    if (strnlen(name,PATH_MAX+1) > PATH_MAX){
        return -1;
    }

    long idx;

    #ifdef IVMFS_DEBUG_FIND_FILE
    fprintf(stderr,"[%s] Finding file '%s'\n", __func__, name);
    #endif

    char fullname[PATH_MAX+1], *rl = name;
    rl = realpath_nocheck(name, fullname);

    #ifdef IVMFS_DEBUG_FIND_FILE
    fprintf(stderr, "[%s] name='%s' fullname='%s'\n", __func__, name, rl);
    #endif

    if (rl) {
        for (idx=0; idx < filesystem->data.nfiles; idx++){
        #ifdef IVMFS_DEBUG_FIND_FILE
        fprintf(stderr, "[%s] - data.filetable[%ld].name='%s' (%ld bytes)\n",
                        __func__, idx, filesystem->data.filetable[idx].name,  filesystem->data.filetable[idx].size);
        #endif
            if (! strcmp(filesystem->data.filetable[idx].name, rl)) {
                return idx;
            }
        }
    }

    return -1;
}

static long find_dir_internal(char* name, int canon)
{
    if (!name || !*name) {
        return -1;
    }

    long ln = strnlen(name,PATH_MAX+1);
    if (((ln == PATH_MAX) && (name[ln-1]!='/')) || (ln > PATH_MAX)){
        return -1;
    }

    long idx;
    char name_slash[PATH_MAX+1];

    static int canonizing=0;

    #ifdef IVMFS_DEBUG
    fprintf(stderr,"[%s] Finding directory name '%s' (canon=%d)\n", __func__, name, canon);
    #endif

    strcpy(name_slash, name);

    #ifdef IVMFS_DEBUG
    fprintf(stderr,"[%s] name='%s' name_slash='%s'\n", __func__, name, name_slash);
    #endif

    for (idx=0; idx < filesystem->data.nfiles; idx++){
        if (IVMFS_ISDIR(filesystem->data.filetable[idx].type)
            && ! strcmp(filesystem->data.filetable[idx].name, name_slash)) {
            #ifdef IVMFS_DEBUG
            fprintf(stderr,"[%s] precheck - found existing directory '%s' idx=%ld\n", __func__, name_slash, idx);
            #endif
            return idx;
        }
    }

    if (canon) {

        char *rl = NULL;
        if (!canonizing) {
            canonizing = 1;
            char name_canon[PATH_MAX];
            rl = realpath(name_slash, name_canon);
            #ifdef IVMFS_DEBUG
            fprintf(stderr," [%s] realpath('%s') = '%s'\n", __func__, name_slash, rl);
            #endif
            canonizing = 0;
            if (rl) {
                strcpy(name_slash, rl);
            } else{

                return -1;
            }
        }
    }

    #ifdef IVMFS_DEBUG
    fprintf(stderr,"[%s] Finding directory (after realpath_nocheck) '%s'\n", __func__, name_slash);
    #endif

    for (idx=0; idx < filesystem->data.nfiles; idx++){
        if (IVMFS_ISDIR(filesystem->data.filetable[idx].type)
            && ! strcmp(filesystem->data.filetable[idx].name, name_slash)) {
            #ifdef IVMFS_DEBUG
            fprintf(stderr,"[%s] Found existing directory '%s' idx=%ld\n", __func__, name_slash, idx);
            #endif
            return idx;
        }
    }

    long findprefix = -1;
    for (idx=0; idx < filesystem->data.nfiles; idx++){
        if (is_prefix(name_slash, filesystem->data.filetable[idx].name)) {
            #ifdef IVMFS_DEBUG
            fprintf(stderr,"[%s] Regular file '%s' has prefix '%s'\n", __func__,filesystem->data.filetable[idx].name, name_slash);
            #endif
            findprefix = idx;
            break;
        }
    }

    if (-1 != findprefix) {

        #ifdef IVMFS_DEBUG
        fprintf(stderr,"[%s] Trying to create directory entry for '%s'\n", __func__, name_slash);
        #endif
        long fd = create_new_file(name_slash, O_CREAT | O_DIRECTORY);
        return fd;
    }

    return -1;
}

static long find_dir(char* name) {
    return find_dir_internal(name, 1);
}

static long find_dir_nocanon(char* name) {
    return find_dir_internal(name, 0);
}

#ifdef IVMFS_DUMPFILES
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
    fflush(NULL);
    fprintf(stderr, "\n");
    for (long idx=0; idx<filesystem->data.nfiles; idx++){
        char *name = filesystem->data.filetable[idx].name;
        unsigned long size = filesystem->data.filetable[idx].size;
        int dir = IVMFS_ISDIR(filesystem->data.filetable[idx].type);
        fprintf(stderr, "\n=======================================\n");
        if ('*' == name[0])
            fprintf(stderr, "filetable[%ld]: '%s' [free entry]\n", idx, name);
        else if ('#' == name[0])
            fprintf(stderr, "filetable[%ld]: '%s' [deleted, not free yet]\n", idx, name);
        else if (dir)
            fprintf(stderr, "filetable[%ld]: '%s' [dir]\n", idx, name);
        else
            fprintf(stderr, "filetable[%ld]: '%s' %ld bytes\n", idx, name, size);
        fprintf(stderr, "=======================================\n");
    #ifdef IVMFS_DUMPFILECONTENTS
        unsigned long l=dump_file_content(name);
    #endif
    }
}
#endif

static int pathat(int dirfd, const char *pathname, char *buff, long size)
{
    if (!pathname || !*pathname || !buff){
        return -1;
    }

    long lp = strnlen(pathname, PATH_MAX+1);
    if ( lp > PATH_MAX || lp >= size){
        return -1;
    }

    if ('/' == pathname[0]) {

        strncpy(buff, pathname, size);
        buff[size-1] = '\0';
        return 0;
    }

    char dirname[PATH_MAX];

    if (AT_FDCWD != dirfd) {

        long idx = find_open_file(dirfd);
        if (idx < 0) {
            return -1;
        }
        file_t *f = &filesystem->data.filetable[idx];
        if (!IVMFS_ISDIR(f->type)){
            return -1;
        }
        strcpy(dirname, f->name);
    } else{

        getcwd(dirname, PATH_MAX);
    }
    dirname[PATH_MAX-1] = '\0';

    if (strlen(dirname)+ lp +1 > size) {

        return -1;
    }
    snprintf(buff, size, "%s/%s", dirname, pathname);
    buff[size-1] = '\0';

    return 0;
}

static long find_free_filetable_entry() {
    for (long idx=0; idx<filesystem->data.nfiles; idx++){
        #ifdef IVMFS_DEBUG
            fprintf(stderr, "[%s] file entry idx=%ld -> name'%s'\n",
                            __func__, idx, filesystem->data.filetable[idx].name);
        #endif
        if (!strcmp(filesystem->data.filetable[idx].name, "*")){
            return idx;
        }
    }
    return -1;
}

static long create_new_file(const char *name, int flags) {
    long idx = -1;
    errno = 0;

    if (!name || !*name || strnlen(name, PATH_MAX+1) > PATH_MAX) {
        return -1;
    }

    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] new file to be created '%s'\n", __func__, name);
    #endif

    char dn[PATH_MAX+1];
    strcpy(dn, name);
    if (find_dir(dirname(dn))< 0) {
        errno = ENOTDIR;
        return -1;
    }

    idx = find_free_filetable_entry();

    if (idx < 0) {
        if ( (0 == filesystem->data.nfiles)
             || (!filesystem->data.max_files_allocated && (filesystem->data.nfiles >= MAX_FILES - 1))
             || (filesystem->data.max_files_allocated  && (filesystem->data.nfiles >= filesystem->data.max_files_allocated - 1))
           ){
            #ifdef IVMFS_DEBUG
            fprintf(stderr, "[%s] number of files exceeded the space allocated\n", __func__);
            #endif

            file_t *newfiletable = NULL;
            if (!filesystem->data.max_files_allocated) {

                filesystem->data.max_files_allocated = MAX_FILES*2 + 512;
                newfiletable = (file_t*)malloc(sizeof(file_t)*filesystem->data.max_files_allocated);
                if (newfiletable) {
                    #ifdef IVMFS_DEBUG
                    fprintf(stderr, "[%s] copying fs to new table\n", __func__);
                    #endif

                    for (unsigned long k=0; k<MAX_FILES; k++){
                        newfiletable[k] = filesystem->data.filetable[k];
                    }
                }
            } else if (filesystem->data.filetable != filesystem->data.filetable0) {

                filesystem->data.max_files_allocated = 2*filesystem->data.max_files_allocated + 1;
                newfiletable = (file_t*)realloc(filesystem->data.filetable, sizeof(file_t)*filesystem->data.max_files_allocated);
            }

            if (!newfiletable) {

                #ifdef IVMFS_DEBUG
                fprintf(stderr, "[%s] NO RESOURCES for NEW file\n", __func__);
                #endif
                errno = ENOMEM;
                return -1;
            } else {

                filesystem->data.filetable = newfiletable;
            }
        }
        idx = filesystem->data.nfiles++;
    }

    if (idx >= 0) {
        filesystem->data.filetable[idx].name = strdup(name);
        filesystem->data.filetable[idx].nameallocated = 1;
        filesystem->data.filetable[idx].size = 0;

        filesystem->data.filetable[idx].allocated = 0;
        filesystem->data.filetable[idx].type = IVMFS_REG;
        if (flags & O_DIRECTORY){
           filesystem->data.filetable[idx].type = IVMFS_DIR;
        }
        #ifdef IVMFS_DEBUG
            fprintf(stderr, "[%s] NEW file just created: name='%s', flags=0x%x, idx=%ld, type=%d allocated=%d\n",
                             __func__, name, flags, idx,
                            filesystem->data.filetable[idx].type,
                            filesystem->data.filetable[idx].allocated);
        #endif

    }

    return idx;
}

static int open0(const char *name, int flags, ...)
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

      +-------------+-------------------------------+
      |  directory  | O_DIRECTORY                   |
      +-------------+-------------------------------+

    */

    #ifdef IVMFS_DEBUG
    fprintf(stderr, "\n===============================\n");
    fprintf(stderr, "[%s] name='%s', flags=0x%x\n", __func__, name, flags);
    #endif

    if (!name || !*name) {
        errno = ENOTDIR;
        return -1;
    }
    if (strnlen(name,PATH_MAX+1) > PATH_MAX){
        errno = ENAMETOOLONG;
        return -1;
    }

    long idx;

    int is_tmpfile = 0;
    char tmpname[PATH_MAX];
    if (flags & O_TMPFILE) {
        sprintf(tmpname, "/.tmpfile_%d", rand());
        name = tmpname;

        flags &= ~O_DIRECTORY;

        flags |= O_CREAT | O_TRUNC;
        is_tmpfile = 1;
    }

    if (flags & O_DIRECTORY) {

        if ((flags & 0x3) != O_RDONLY){
           errno = EISDIR;
           return -1;
        }

        if (flags & O_CREAT) {

            if (mkdir(name, 0777)){

                return -1;
            }
            return open(name, flags & (~O_CREAT));
        } else {

            #ifdef IVMFS_DEBUG
            fprintf(stderr,"[%s] Opening directory '%s'\n", __func__, name);
            #endif
            idx = find_dir((char*)name);
            #ifdef IVMFS_DEBUG
            fprintf(stderr,"[%s] Directory found '%s' idx=%ld\n", __func__, name, idx);
            #endif
        }
    } else {

        idx = find_file((char*)name);

        #ifdef IVMFS_DEBUG
        fprintf(stderr,"[%s] find_file '%s' returned idx=%ld\n", __func__, name, idx);
        #endif

        if (idx>=0 && IVMFS_ISDIR(filesystem->data.filetable[idx].type)
                   && !(flags & O_DIRECTORY)) {
            errno = EISDIR;
            return -1;
        }
    }

    int islink = (idx >= 0) && IVMFS_ISLNK(filesystem->data.filetable[idx].type);
    if (islink && (flags & O_NOFOLLOW)){

        errno = ELOOP;
        return -1;
    }

    if (islink && ((flags & O_EXCL) && (flags & O_CREAT))) {

        errno = EEXIST;
        return -1;
    }

    static long trylink = 0;
    if (!trylink && islink) {
        char linkname[PATH_MAX];
        char *rl = realpath(name, linkname);
        if (rl) {
            trylink = 1;
            int fid = open(rl, flags);
            trylink = 0;
            if (fid >= 0) {

                return fid;
            } else {

                return -1;
            }
        } else {

            errno = ENOENT;
            return -1;
        }
    }

    static long trylink2 = 0;
    if (!trylink && !trylink2 && (idx < 0)) {

        char linkname1[PATH_MAX];
        char *rl1 = realparentpath(name, linkname1);
        if (rl1) {

                trylink2 = 1;
                int fid = open(rl1, flags);
                trylink2 = 0;
                return fid;
        }
    }

    if (idx >= 0) {

        if ((flags & O_EXCL) && (flags & O_CREAT)) {

            errno = EEXIST;
            return -1;
        }

        int fid = openfile_entry(idx);
        filesystem->data.openfile[fid].flags = flags;

        if (flags & O_TRUNC){
            filesystem->data.filetable[idx].size = 0;
        }

        if (flags & O_APPEND){
            set_position(fid,  filesystem->data.filetable[idx].size);
        }

        #ifdef IVMFS_DEBUG
            fprintf(stderr, "[open] OK name=%s, flags=0x%x, fid=%d\n", name, flags, fid);
        #endif

        return fid;
    }

    if (flags & O_CREAT) {
        #ifdef IVMFS_DEBUG
            fprintf(stderr, "[%s] new file to be created '%s'\n", __func__, name);
        #endif

        char fullname[PATH_MAX+1], *rl;
        rl = realpath_nocheck(name, fullname);
        if (!rl) return -1;

        #ifdef IVMFS_DEBUG
            fprintf(stderr, "[%s] new file to be created '%s' fullname='%s'\n", __func__, name, rl);
        #endif

        idx = create_new_file(fullname, flags);
        if (idx >= 0){
            int fid = openfile_entry(idx);
            if (fid >=0) {

                filesystem->data.openfile[fid].flags = flags;
                if (is_tmpfile) {

                    unlink(name);
                }
            }

            return fid;
        }
    }

    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[%s] FAIL name=%s, flags=0x%x\n",__func__, name, flags);
    #endif

    if (!errno) errno = ENOSYS;
    return -1;
}

int openat0(int dirfd, const char *pathname, int flags, ...)
{
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] pathname=%s\n",__func__, pathname);
    #endif

    char filenamebuff[PATH_MAX];
    int err = pathat(dirfd, pathname, filenamebuff, PATH_MAX);

    if (!err) {
        va_list arg;
        va_start(arg, flags);
        int res = open(filenamebuff, flags, arg);
        va_end(arg);
        return res;
    } else {
        errno = ENOENT;
        return -1;
    }
}

static ssize_t read0(fid_t fid, void *vbuf, size_t len)
{
    #ifdef IVMFS_DEBUG
        fprintf(stderr, "\n===============================\n");
        fprintf(stderr, "[%s] fid=%d len=%ld\n", __func__, fid, len);
    #endif

    if (!is_valid_fileno(fid)){

        errno = EBADF;
        return 0;
    }

    char *buf = (char*)vbuf;

    if (filesystem->data.openfile[fid].open
        && (DEVSTDIN == filesystem->data.openfile[fid].dev)) {

            long i = 0;
            unsigned char ch;
            do {
                ch = read_char();
                if (ch == SYSTEM_EOF) break;
                buf[i++] = ch;
            } while (i < len && ch != '\n');
            return i;

    }

    long idx = find_open_file(fid);

    if (idx < 0) {
        errno = EBADF;
        return  -1;
    }

    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[%s] fid=%d, idx=%ld, name='%s'\n", __func__, fid, idx,
                        (idx>-1)?filesystem->data.filetable[idx].name:"");
    #endif

    if ((filesystem->data.openfile[fid].flags & 0x3) == O_WRONLY){

        #ifdef IVMFS_DEBUG
            fprintf(stderr, "[%s] fid=%d, idx=%ld name='%s' flags=0x%x (flags & 0x3 == O_WRONLY)\n", __func__, fid, idx,
    (idx>-1)?filesystem->data.filetable[idx].name:"", filesystem->data.openfile[fid].flags);
        #endif
        errno = EBADF;
        return -1;
    }

    long pos = get_position(fid);
    long elen = MIN((long)len, (long)filesystem->data.filetable[idx].size - pos);
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] let us read: requested len=%ld, effective len=%ld | idx=%ld pos=%ld, size=%ld\n",
                    __func__, len, elen, idx, pos, filesystem->data.filetable[idx].size);
    #endif
    if (elen > 0 && pos >= 0) {
        memcpy(buf, *(filesystem->data.filetable[idx].data) + pos, elen);
        set_position(fid, pos + elen);
        #ifdef IVMFS_DEBUG
            fprintf(stderr, "[%s] OK! count=%ld [fid=%d len=%ld newpos=%ld]\n", __func__, elen, fid, len, pos+len);
        #endif
        return elen;
    }

    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[%s] read failed: count=%ld [fid=%d len=%ld]\n", __func__, elen, fid, len);
    #endif
    return 0;
}

static int close0(fid_t fid)
{
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "\n===============================\n");
    fprintf(stderr, "[%s] fid=%d\n", __func__, fid);
    #endif

    if ((fid < 0) || (fid >=  filesystem->data.openfile_size)){

        errno = EBADF;
        return  -1;
    }

    if (DEVDISK != filesystem->data.openfile[fid].dev) {

        remove_open_device(fid);
        return 0;
    }

    long idx = remove_open_file(fid);
    if (idx < 0) {
        errno = EBADF;
        return  -1;
    }

    if (find_fileno(idx) == -1){

        if (filesystem->data.filetable[idx].name[0] == '#') {

            #ifdef IVMFS_DEBUG
            fprintf(stderr, "[%s] deleting file '%s'\n", __func__, filesystem->data.filetable[idx].name);
            #endif
            delete_file(idx);
        }
    }

    return 0;
}

static off_t lseek0(fid_t fid, off_t offset, int whence)
{
    #ifdef IVMFS_DEBUG
        fprintf(stderr, "\n===============================\n");
        fprintf(stderr, "[%s] fid=%d, offset=%ld, whence=%d\n", __func__, fid, offset, whence);
    #endif

    errno = 0;

    if ((fid < 0) || (fid >=  filesystem->data.openfile_size)){

        errno = EBADF;
        return   (off_t) -1;
    }

    long idx;
    long newpos;

    if (filesystem->data.openfile[fid].dev != DEVDISK) {
        return  0;
    }

    if ((idx = find_open_file(fid)) >= 0){
        switch(whence){
            case SEEK_CUR:
                newpos = get_position(fid) + offset;
                break;
            case SEEK_END:
                newpos = filesystem->data.filetable[idx].size + offset;
                break;
            case SEEK_SET:
                newpos = offset;
                break;
            default:
                errno = EINVAL;
                return  (off_t)(-1);
                break;
        }

        if (newpos < 0) {
            #ifdef IVMFS_DEBUG
            fprintf(stderr, "[%s] new pos=%ld < 0\n", __func__, newpos);
            #endif
            errno = EINVAL;
            return  (off_t)(-1);
        }

        set_position(fid, newpos);

        return newpos;
    } else {
        errno = EBADF;
        return  (off_t)(-1);
    }
}

static ssize_t write0(fid_t fid, const void *vptr, size_t nbytes)
{
    int cont;
    char c;
    unsigned long allocated;

    if (!is_valid_fileno(fid)){

        errno = EBADF;
        return 0;
    }

    char *ptr = (char*)vptr;

    if (filesystem->data.openfile[fid].open
        &&  ((DEVSTDOUT == filesystem->data.openfile[fid].dev)
            || (DEVSTDERR == filesystem->data.openfile[fid].dev)) )
    {
        for (cont=0; cont<nbytes; cont++){
             c = ptr[cont];
             put_char(c);
        }
        return cont;
    } else {
        long idx = find_open_file(fid);

        #ifdef IVMFS_DEBUG

            fprintf(stderr, "\n===============================\n");
            fprintf(stderr, "[%s] fid=%d, nbytes=%ld, pos=%ld allocated=%ld\n",
                             __func__, fid, nbytes, (idx<0)?-1:get_position(fid),
                            (idx<0)?-1: filesystem->data.filetable[idx].allocated);
        #endif

        if (idx < 0) {
            errno = EBADF;
            return  -1;
        } else {

            long start_size = filesystem->data.filetable[idx].size;
            long start_pos  = get_position(fid);

            if ((filesystem->data.openfile[fid].flags & 0x3) == O_RDONLY){

               errno = EBADF;
               return -1;
            }

            if (filesystem->data.openfile[fid].flags & O_APPEND){
                set_position(fid,  filesystem->data.filetable[idx].size);
            }

            if (filesystem->data.filetable[idx].allocated == 0) {

                allocated = BLKSIZE *( (MAX(filesystem->data.filetable[idx].size, get_position(fid)) + nbytes +1)/BLKSIZE + 1 + EXTRABLKS);
                char **p = (char **)malloc(sizeof(char*));
                *p = (char *)malloc(allocated * sizeof(char));
                if (!p || !(*p)){
                    #ifdef IVMFS_DEBUG
                        fprintf(stderr, "[%s] not enough space allocating %ld bytes\n", __func__, allocated);
                    #endif
                    errno = EBADF;
                    return  -1;
                }
		        filesystem->data.filetable[idx].allocated = allocated;

                if (filesystem->data.filetable[idx].size > 0)
                    memcpy(*p, *(filesystem->data.filetable[idx].data), filesystem->data.filetable[idx].size);

                filesystem->data.filetable[idx].data = p;

                #ifdef IVMFS_DEBUG
                    fprintf(stderr, "[%s] allocated %ld bytes\n", __func__, allocated);
                #endif

            } else {

                unsigned int finalbyte = get_position(fid) + nbytes - 1;
                if (finalbyte >= filesystem->data.filetable[idx].allocated) {

                    allocated = BLKSIZE *((finalbyte + 1)/BLKSIZE + 1 + EXTRABLKS);
                    char **p = filesystem->data.filetable[idx].data;
                    char *newp = (char *)realloc(*(filesystem->data.filetable[idx].data), allocated * sizeof(char));

                    if (!newp){
                    #ifdef IVMFS_DEBUG
                        fprintf(stderr, "[%s] error re-allocating %ld bytes %s\n", __func__, allocated, (errno==ENOMEM)?"(ENOMEM)":"");
                    #endif
                        errno = EBADF;
                        return  -1;
                    }

                    *p = newp;
                    filesystem->data.filetable[idx].allocated = allocated;
                    filesystem->data.filetable[idx].data = p;

                    #ifdef IVMFS_DEBUG
                        fprintf(stderr, "[%s] re-allocated %ld bytes\n", __func__, allocated);
                    #endif
                }
            }

            if (nbytes > 0 && (start_pos >= start_size)) {
                memset(*(filesystem->data.filetable[idx].data) + start_size, 0, start_pos-start_size);
            }

            long pos = get_position(fid);
            if (pos >= 0 && nbytes > 0) {
                memcpy(*(filesystem->data.filetable[idx].data) + pos, ptr, nbytes);
                filesystem->data.filetable[idx].size = MAX(filesystem->data.filetable[idx].size, pos + nbytes);
                set_position(fid, pos+nbytes);
                return nbytes;
            } else {
                return 0;
            }
        }
    }
}

static int file_stat(long idx, struct stat *st)
{
    struct stat S;

    memset(&S, 0, sizeof(S));

    file_t *f = &filesystem->data.filetable[idx];

    S.st_dev = 1;       /* ID of device containing file */
    S.st_ino = IVMFS_FIRST_INO() + idx; /* Inode number (0 is reserved)*/
    S.st_mode = 0777;   /* File type and mode */
    if (IVMFS_ISDIR(f->type)) {

        S.st_mode |= S_IFDIR;
    } else if (IVMFS_ISLNK(f->type)) {

        S.st_mode |= S_IFLNK;
    } else {

        S.st_mode |= S_IFREG;
    }

    S.st_nlink = 1;     /* Number of hard links */
    S.st_uid = 0;       /* User ID of owner */
    S.st_gid = 0;       /* Group ID of owner */
    S.st_rdev = 0;      /* Device ID (if special file) */
    S.st_size = f->size;    /* Total size, in bytes */
    S.st_blksize = BLKSIZE; /* Block size for filesystem I/O */
    /* Number of 512B blocks allocated */
    S.st_blocks = (MAX(f->size, f->allocated)+(512-1))/512;

    *st = S;
    return 0;
}

static int lstat_nocanon(const char *file, struct stat *st)
{
    long idx;

    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] file='%s'\n", __func__, file);
    #endif

    idx = find_file((char*)file);
    if (idx < 0){
        #ifdef IVMFS_DEBUG
        fprintf(stderr, "[%s] '%s' not in table, trying find_dir \n", __func__, file);
        #endif
        idx = find_dir_nocanon((char*)file);
        if (idx < 0) {
            errno = ENOENT;
            return -1;
        }
    }

    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] found '%s' idx=%ld\n", __func__, file, idx);
    #endif

    return file_stat(idx, st);
}

static int stat0(const char *file, struct stat *st)
{
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] file='%s'\n", __func__, file);
    #endif

    char buff[PATH_MAX];
    char *rl = realpath(file, buff);
    if (!rl) {
        errno = ENOENT;
        return -1;
    }

    return lstat_nocanon(buff, st);

}

static int lstat0(const char *file, struct stat *st)
{
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] file='%s'\n", __func__, file);
    #endif

    char realparentname[PATH_MAX];
    char *rl = realparentpath(file, realparentname);
    if (!rl) {
        errno = ENOENT;
        return -1;
    }

    return lstat_nocanon(realparentname, st);
}

static int device_stat(int fd, struct stat *st)
{
    struct stat S;

    memset(&S, 0, sizeof(S));

    S.st_dev = 2;       /* ID of device containing file */

    if (filesystem->data.openfile[fd].dev == DEVSTDIN) {
        /* Fake inodes for devices below the first disk inode */
        S.st_ino = IVMFS_FIRST_INO() - 1;
        /* Device ID (if special file) */
        S.st_rdev = DEVSTDIN;
    }
    else if (filesystem->data.openfile[fd].dev == DEVSTDOUT) {
        S.st_ino = IVMFS_FIRST_INO() - 2;
        S.st_rdev = DEVSTDOUT;
    }
    else if (filesystem->data.openfile[fd].dev == DEVSTDERR) {
        S.st_ino = IVMFS_FIRST_INO() - 3;
        S.st_rdev = DEVSTDERR;
    }

    S.st_mode = 0777;     /* File type and mode */
    S.st_mode |= S_IFCHR; /* stdin, stdout, stderr as char devices */

    S.st_nlink = 1;     /* Number of hard links */
    S.st_uid = 0;       /* User ID of owner */
    S.st_gid = 0;       /* Group ID of owner */

    S.st_size = 0;    /* Total size, in bytes */
    S.st_blksize = BLKSIZE; /* Block size for filesystem I/O */
    /* Number of 512B blocks allocated */
    S.st_blocks = 0;

    *st = S;
    return 0;
}

static int fstat0(int fid, struct stat *st)
{
    long idx;

    if (!is_valid_fileno(fid)){
        errno = EBADF;
        return -1;
    }

    if ((DEVSTDIN == filesystem->data.openfile[fid].dev)
           || (DEVSTDOUT == filesystem->data.openfile[fid].dev)
           || (DEVSTDERR == filesystem->data.openfile[fid].dev))
    {

        return device_stat(fid, st);
    }

    if ((idx = find_open_file(fid)) < 0) {
        errno = ENOENT;
        return -1;
    }

    return file_stat(idx, st);
}

static int access0(const char *pathname, int mode)
{
   struct stat s;
   return stat(pathname, &s);
}

static int faccessat0(int dirfd, const char *pathname, int mode, int flags)
{
    struct stat s;
    return fstatat(dirfd, pathname, &s, flags);
}

static int fstatat0(int dirfd, const char *pathname, struct stat *statbuf,
                   int flags)
{

    if (pathname && !*pathname && (flags && AT_EMPTY_PATH)){

        if (dirfd != AT_FDCWD) {
            return fstat(dirfd, statbuf);
        } else {
            char pwd[PATH_MAX];
            if (getcwd(pwd, PATH_MAX-1)) {
                return fstatat(AT_FDCWD, pwd, statbuf, flags);
            }
            else {
                errno = ENOENT;
                return -1;
            }
        }
    }

    char filenamebuff[PATH_MAX];
    int err = pathat(dirfd, pathname, filenamebuff, PATH_MAX);

    if (!err) {
        if (flags & AT_SYMLINK_NOFOLLOW){
            return lstat(filenamebuff, statbuf);
        } else {
            return stat(filenamebuff, statbuf);
        }
    } else {
        errno = ENOENT;
        return -1;
    }
}

static int fsync0(int fd)
{
    return 0;
}

static int fdatasync0(int fd)
{
    return 0;
}

static int utimes0(const char *filename, const struct timeval times[2])
{
    return 0;
}

static char *getcwd0(char *buf, size_t size) {

    if (buf == NULL) {
        if (size == 0) {
            return get_current_dir_name();
        } else {
            errno = EINVAL;
            return NULL;
        }
    }

    char *cwd = filesystem->data.cwd;
    long l = strnlen(cwd, PATH_MAX);
    if (!cwd || size <= l) {
        errno = ERANGE;
        return NULL;
    }

    size_t minsize = MIN(size, PATH_MAX);
    strncpy(buf, filesystem->data.cwd, minsize);
    buf[minsize-1] = '\0';
    return buf;
}

char *get_current_dir_name0(void)
{
	char pwd[PATH_MAX];
	return getcwd(pwd, sizeof(pwd)) == NULL ? NULL : strdup(pwd);
}

static int unlink0(const char *pathname)
{
    #ifdef IVMFS_DEBUG
        fprintf(stderr, "\n===============================\n");
        fprintf(stderr, "[%s] pathname='%s'\n", __func__, pathname);
    #endif

    if (!pathname || !*pathname ) {
        errno = ENOENT;
        return -1;
    }

    if (strlen(pathname) > PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int sn;
    struct stat s;
    sn = lstat(pathname, &s);

    if (sn) {

        errno = ENOENT;
        return -1;
    } else {
        if (S_ISDIR(s.st_mode)){

            errno = EISDIR;
            return -1;
        } else {
            long idx = s.st_ino - IVMFS_FIRST_INO();
            file_t *f = &filesystem->data.filetable[idx];
            if (IVMFS_ISDIR(f->type)) {

                errno = EISDIR;
                return -1;
            } else {

                #ifdef IVMFS_DEBUG
                    fprintf(stderr, "[%s] deleting a regular file or link idx=%ld (name='%s')\n", __func__, idx, f->name);
                #endif
                long nf = delete_file(idx);
                if (nf < 0) {
                    errno = ENOENT;
                    return -1;
                } else {
                    return 0;
                }
            }
        }
    }

    errno = ENOENT;
    return -1;
}

static int unlinkat0(int dirfd, const char *pathname, int flags)
{
    char filenamebuff[PATH_MAX];
    int err = pathat(dirfd, pathname, filenamebuff, PATH_MAX);
    if (!err) {
        if (flags & AT_REMOVEDIR){

            return rmdir(filenamebuff);
        } else {

            return unlink(filenamebuff);
        }
    } else {
        errno = ENOTDIR;
        return -1;
    }
}

static void check_cwd(){
    char buff[PATH_MAX+1];
    getcwd(buff, PATH_MAX); buff[PATH_MAX]='\0';
    #ifdef IVMFS_DEBUG
    printf("[%s] pwd=%s ...\n", __func__, buff);
    #endif

    long idx = find_dir(buff);
    if (idx < 0){
        mkdir("/", 0777);
        chdir("/");
    }
}

#define IVMFS_DENTRY_IS_DOT(pdirent)  ((pdirent) && (!strcmp(".", (pdirent)->d_name) || !strcmp("..", (pdirent)->d_name)))

static int is_empty_dir(char *dirname){
    int empty = 0;
    DIR *dir = opendir(dirname);
    if(dir){

        empty = 1;
        struct dirent *pdirent;
        while ((pdirent = readdir(dir))) {
            if (pdirent && !IVMFS_DENTRY_IS_DOT(pdirent)) {

                empty = 0;
                break;
            }
        }
        closedir(dir);
    }
    return empty;
}

static int rmdir0(const char *pathname)
{
    if (!pathname || !*pathname){
        errno = ENOTDIR;
        return -1;
    }

    struct stat s;
    int serr = lstat(pathname, &s);
    if (serr || ! S_ISDIR(s.st_mode)) {

        errno = ENOTDIR;
        return -1;
    }

    long idx = s.st_ino - IVMFS_FIRST_INO();

    if (idx >= 0) {
        file_t *d = &filesystem->data.filetable[idx];

        if (!strcmp(d->name, "/")){
            return 0;
        }

        long ed = 0;

        if (IVMFS_ISDIR(d->type)) {
            ed = is_empty_dir(d->name);
        }
        #ifdef IVMFS_DEBUG
        fprintf(stderr, "[%s] trying to remove dir '%s' (is empty? = %d)\n",
                         __func__, d->name, ed);
        #endif

        if (!ed) {
            errno = ENOTEMPTY;
            return -1;
        } else {

            delete_file(idx);
            check_cwd();
            return 0;
        }
    }

    errno = ENOTDIR;
    return -1;
}

static int is_dirname_a_dir(char *fullrealpath){
    char dn[PATH_MAX];
    strcpy(dn, fullrealpath);
    dn[PATH_MAX-1] = '\0';
    if (find_dir(dirname(dn)) >= 0) {
        return 1;
    }
    return 0;
}

static long file_in_dir(char *dir) {
    char file_slash[PATH_MAX+1];
    char dir_slash[PATH_MAX+1];

    if (!add_slash(dir_slash, dir)){

        return -1;
    }

    for (long idx=0; idx < filesystem->data.nfiles; idx++){
        file_t f =  filesystem->data.filetable[idx];
        if (! IVMFS_ISDIR(f.type)) {

            char *ff = add_slash(file_slash, f.name);
            #ifdef IVMFS_DEBUG
            fprintf(stderr, "[%s] Checking file is prefix of a dir idx=%ld strncmp(file='%s', dir='%s', len=%ld) = %d\n",
                            __func__, idx, file_slash, dir_slash, strlen(file_slash), strncmp(file_slash, dir_slash, strlen(file_slash)));
            #endif

            if (ff && !strncmp(file_slash, dir_slash, strlen(file_slash))){
                #ifdef IVMFS_DEBUG
                fprintf(stderr,"[%s] Found file prefix of a dir idx=%ld file=%s dir=%s\n", __func__,idx, file_slash, dir_slash);
                #endif
                return idx;
            }
        }
    }
    return -1;
}

static int mkdir0(const char *pathname, mode_t mode)
{
    if (!pathname || !*pathname) {
        errno = ENOENT;
        return -1;
    }
    if (strnlen(pathname,PATH_MAX+1) > PATH_MAX){
        errno = ENAMETOOLONG;
        return -1;
    }

    long idx = find_file((char*)pathname);
    if (idx >= 0){
        errno = EEXIST;
        return -1;
    }

    int fid = open((char*)pathname, O_WRONLY | O_CREAT | O_TRUNC);
    if (fid >= 0) {
        write(fid, "", 0);

        idx = filesystem->data.openfile[fid].idx;
        close(fid);
        filesystem->data.filetable[idx].type = IVMFS_DIR;
        return 0;
    }

    errno = ENOENT;
    return -1;
}

static int mkdirat0(int dirfd, const char *pathname, mode_t mode)
{
    char filenamebuff[PATH_MAX];
    int err = pathat(dirfd, pathname, filenamebuff, PATH_MAX);
    if (err){
        errno = EBADF;
        return -1;
    } else {
        return mkdir(filenamebuff, mode);
    }
}

static int chdir0(const char *path)
{
    static int cwdallocated = 0;

    if (!path || !*path) {
        errno = ENOENT;
        return -1;
    }

    if (!strcmp(path, "/")) {
        if (cwdallocated) {
            free(filesystem->data.cwd);
        } else {
            cwdallocated = 1;
        }
        filesystem->data.cwd = strdup("/");
        return 0;
    }

    char fullpath[PATH_MAX+1], *rl;

    if (path[strlen(path)-1] == '/'){
        #ifdef IVMFS_DEBUG
        printf("[%s] path='%s' ending in '/'\n", __func__, path);
        #endif
    }

    rl = realpath_nocheck(path, fullpath);

    #ifdef IVMFS_DEBUG
    printf("[%s] path='%s' fullpath='%s'\n", __func__, path, rl);
    #endif

    if (rl) {

        long idx = find_dir(rl);
        #ifdef IVMFS_DEBUG
        printf("[%s] path='%s' fullpath='%s' idx=%ld\n", __func__, path, rl, idx);
        #endif
        if (idx>=0) {
            if (cwdallocated) {
                free(filesystem->data.cwd);
            } else {
                cwdallocated = 1;
            }
            filesystem->data.cwd = strdup(rl);
            return 0;
        }
    }

    errno = ENOENT;
    return -1;
}

static int fchdir0(int dirfd)
{
    long idx = find_open_file(dirfd);
    if (idx < 0) {
        errno = EBADF;
        return -1;
    }
    file_t *f = &filesystem->data.filetable[idx];
    if (! IVMFS_ISDIR(f->type)){
        errno = ENOTDIR;
        return -1;
    }
    return chdir(f->name);
}

static char *rename_file(file_t *f, char *newname){
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] old name='%s' new name='%s'\n", __func__, f->name, newname);
    #endif
    if (!newname || !*newname) {
        return NULL;
    }
    if (!f->nameallocated) {
        f->nameallocated = 1;
    } else {
        free(f->name);
    }
    f->name = strdup(newname);
    return f->name;
}

static int do_delete_file(file_t *f){

    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s]  deleting file entry for name=%s\n", __func__, f->name);
    #endif

    if (f->nameallocated) { free(f->name); }
    if (f->allocated) {free(*f->data); free(f->data);}
    f->nameallocated = 0;
    f->allocated = 0;
    f->size = 0;

    f->name = (char*)"*";

    return 0;
}

static long delete_file(long idx){

    if (idx < 0 || idx > filesystem->data.nfiles - 1) {
        return -1;
    }
    file_t *f = &filesystem->data.filetable[idx];

    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s]  deleting file entry idx=%ld\n", __func__, idx);
    #endif

    static long ndel=0;
    if (f->name[0] != '#') {

        if (f->nameallocated) { free(f->name);} else {f->nameallocated = 1;}
        char *tobedeleted = (char*)"##***DELETED%ld***##";
        f->name = (char *)malloc(sizeof(char)*strlen(tobedeleted)+64);
        sprintf(f->name, tobedeleted, ndel++);
    }

    long n = filesystem->data.nfiles;
    if (find_fileno(idx) == -1){
       if (do_delete_file(f)) {
            return -1;
       }
    }
    return n;
}

#define rename0_internal_new rename0_internal

static int rename0_internal_new(const char *oldpath_a, const char *newpath_a)
{
    char *src = (char*)oldpath_a;
    char *dst = (char*)newpath_a;

    #ifdef IVMFS_DEBUG
    #define IVMFS_DEBUG_RENAME0
    #endif

    int src_ok = 0;
    int src_dir = 0;

    struct stat s_src;
    char realparentsrc[PATH_MAX+1];
    if (realparentpath(src, realparentsrc)) {
        src_ok = ! lstat(src, &s_src);

        if (src_ok) src_dir = S_ISDIR(s_src.st_mode);
    }

    #ifdef IVMFS_DEBUG_RENAME0
    fprintf(stderr, "[%s]  src='%s' (exist? %d) dst='%s'\n", __func__,
            src, src_ok, dst);
    #endif

    if (!src_ok) {

        #ifdef IVMFS_DEBUG_RENAME0
        fprintf(stderr, "[%s]  source (old) path '%s' does not exist\n",
                __func__, src);
        #endif
        errno = ENOENT;
        return -1;
    }

    int dst_ok = 0;
    int dst_dir = 0;

    struct stat s_dst;
    dst_ok = ! lstat(dst, &s_dst);

    char realdst[PATH_MAX+1];
    if (dst_ok && (dst_dir = S_ISDIR(s_dst.st_mode))){
        (void) realpath(dst, realdst);
    } else {

        char *rl = realparentpath(dst, realdst);
        if (!rl || !is_dirname_a_dir(rl)){

            errno = ENOTDIR;
            return -1;
        }
    }

    long idx_src = -1;
    long idx_dst = -1;
    file_t *f_src=NULL, *f_dst=NULL;

    if (src_ok)
        idx_src = s_src.st_ino - IVMFS_FIRST_INO();
    if (dst_ok)
        idx_dst = s_dst.st_ino - IVMFS_FIRST_INO();

    if (idx_src >= 0)
        f_src = &filesystem->data.filetable[idx_src];
    if (idx_dst >= 0)
        f_dst = &filesystem->data.filetable[idx_dst];

    if (dst_ok) {

        if (!dst_dir) {

            if (!src_dir) {

                #ifdef IVMFS_DEBUG_RENAME0
                fprintf(stderr, "[%s] FILE -> FILE \n", __func__);
                #endif

                if (idx_dst >= 0 && idx_dst == idx_src) {
                    #ifdef IVMFS_DEBUG_RENAME0
                    fprintf(stderr, "[%s] new and old are the same\n", __func__);
                    #endif
                    return 0;
                }

                if (!f_src || !f_dst || !rename_file(f_src, f_dst->name)){
                    errno = ENOENT;
                    return -1;
                }

                long nf = delete_file(idx_dst);
                if (nf < 0) {
                    errno = ENOENT;
                    return -1;
                }

                return 0;

            }
            else {

                #ifdef IVMFS_DEBUG_RENAME0
                fprintf(stderr, "[%s] DIR -> FILE !! (ENOTDIR) \n", __func__);
                #endif

                errno = ENOTDIR;
                return -1;
            }
        }
        else {

            if (!src_dir) {

                #ifdef IVMFS_DEBUG_RENAME0
                fprintf(stderr, "[%s] FILE -> DIR \n", __func__);
                #endif

                char *new_name = strdup(f_src->name);
                char fullnewname[PATH_MAX+1];
                long n = snprintf(fullnewname, PATH_MAX+1, "%s/%s",
                                  f_dst->name, basename(new_name));
                free(new_name);
                if (n > PATH_MAX) {
                    errno = ENAMETOOLONG;
                    return -1;
                }

                if (0 == rename0_internal_new(f_src->name, fullnewname)){
                    return 0;
                }

                errno = ENOENT;
                return -1;
            }
            else {

                #ifdef IVMFS_DEBUG_RENAME0
                fprintf(stderr, "[%s] DIR -> DIR \n", __func__);
                #endif

                if (idx_dst >= 0 && idx_dst == idx_src) {
                    #ifdef IVMFS_DEBUG_RENAME0
                    fprintf(stderr, "[%s] new and old are the same\n", __func__);
                    #endif
                    return 0;
                }

                if (is_prefix_or_equal(f_src->name, f_dst->name)) {
                    errno = EINVAL;
                    return -1;
                }

                #define IVMFS_RENAME_DIR_POSIX

                #ifdef IVMFS_RENAME_DIR_AS_MOVE

                char fullnewname[PATH_MAX+1];
                char *src_name_copy = strdup(f_src->name);
                long n = snprintf(fullnewname, PATH_MAX+1, "%s/%s",
                                  f_dst->name, basename(src_name_copy));
                free(src_name_copy);
                if (n > PATH_MAX) {
                    errno = ENAMETOOLONG;
                    return -1;
                }

                #ifdef IVMFS_DEBUG_RENAME0
                fprintf(stderr, "[%s] trying to move '%s' -> fullnewname='%s'\n",
                                 __func__, f_src->name, fullnewname);
                #endif

                if (find_dir(fullnewname) >= 0){
                    #ifdef IVMFS_DEBUG_RENAME0
                    fprintf(stderr, "[%s] fullnewname='%s' already exists\n",
                                     __func__, fullnewname);
                    #endif
                    errno = EEXIST;
                    return -1;
                }

                if (0 == rename0_internal_new(f_src->name, fullnewname)) {
                    return 0;
                }
                #endif

                #ifdef IVMFS_RENAME_DIR_POSIX

                if (!is_empty_dir(f_dst->name)){
                    errno = ENOTEMPTY;
                    return -1;
                }

                char dst_copy[PATH_MAX];
                strcpy(dst_copy, f_dst->name);
                rmdir(f_dst->name);

                #ifdef IVMFS_DEBUG_RENAME0
                fprintf(stderr, "[%s] %s empty and removed; trying to move '%s' -> dst_copy='%s'\n",
                                 __func__, f_dst->name, f_src->name, dst_copy);
                #endif

                if (0 == rename0_internal_new(f_src->name, dst_copy)) {
                    return 0;
                }
                #endif

                errno = ENOTEMPTY;
                return -1;
            }
        }
    }
    else {

        if (!src_dir) {

            #ifdef IVMFS_DEBUG_RENAME0
            fprintf(stderr, "[%s] FILE -> NEWFILE \n", __func__);
            #endif

            #ifdef IVMFS_DEBUG_RENAME0
            fprintf(stderr, "[%s] newpath '%s' does NOT exist\n", __func__, dst);
            #endif

            if (rename_file(f_src, realdst)){
                return 0;
            } else {
                #ifdef IVMFS_DEBUG_RENAME0
                fprintf(stderr, "[%s] failed '%s' -> '%s'\n", __func__, f_src->name, realdst);
                #endif
                errno = ENOENT;
                return -1;
            }

        }
        else {

            #ifdef IVMFS_DEBUG_RENAME0
            fprintf(stderr, "[%s] DIR -> NEWDIR \n", __func__);
            #endif

            long n;

            char *fullnewname = realdst;
            if (!fullnewname) {

                 errno = EFAULT;
                 return -1;
            }

            if (file_in_dir(fullnewname) >= 0){

                #ifdef IVMFS_DEBUG_RENAME0
                fprintf(stderr, "[%s] Moving directory to file not allowed \n", __func__);
                #endif
                errno = EEXIST;
                return -1;
            }

            if (!is_dirname_a_dir(fullnewname)){
                 errno = ENOTDIR;
                 return -1;
            }

            if (is_prefix_or_equal(f_src->name, fullnewname)) {
                errno = EINVAL;
                return -1;
            }

            #ifdef IVMFS_DEBUG_RENAME0
            fprintf(stderr, "[%s] (canonicalized) oldpath='%s' newpath='%s' fullnewname='%s'\n",
                      __func__, f_src->name, dst, fullnewname);
            #endif

            char *src_copy = strdup(f_src->name);

            for (long idxi=0; idxi < filesystem->data.nfiles; idxi++){
                file_t *fn =  &filesystem->data.filetable[idxi];
                #ifdef IVMFS_DEBUG_RENAME0
                fprintf(stderr,"[%s] Checking if entry '%s' has prefix '%s'?\n", __func__,fn->name, src_copy);
                #endif
                if (is_prefix_or_equal(src_copy, fn->name)) {
                    #ifdef IVMFS_DEBUG_RENAME0
                    fprintf(stderr,"[%s] Entry '%s' has prefix '%s'\n", __func__,fn->name, src_copy);
                    #endif
                    char *entryname =  fn->name;
                    char buff[PATH_MAX+1];

                    if ('\0' == entryname[strlen(src_copy)]){

                        #ifdef IVMFS_DEBUG_RENAME0
                        fprintf(stderr,"[%s] Replacing old dirname by '%s' \n", __func__, fullnewname);
                        #endif
                        n = snprintf(buff, PATH_MAX+1, "%s", fullnewname);
                    } else {

                        int start = 1;

                        if (strlen(src_copy)==1) start = 0;
                        #ifdef IVMFS_DEBUG_RENAME0
                        fprintf(stderr,"[%s] Concatenating '%s' + '/%s' \n", __func__, fullnewname, &entryname[strlen(src_copy)+start]);
                        #endif

                        n = snprintf(buff, PATH_MAX+1, "%s/%s", fullnewname, &entryname[strlen(src_copy)+start]);
                    }
                    if (n > PATH_MAX)
                    {
                        free(src_copy);
                        errno = ENAMETOOLONG;
                        return -1;
                    }
                    if (!rename_file(fn, buff)) {
                        free(src_copy);
                        errno = ENOENT;
                        return -1;
                    }
                }
            }
            free(src_copy);
            return 0;
        }
    }

    #ifdef IVMFS_DEBUG_RENAME0
    #undef IVMFS_DEBUG_RENAME0
    #endif
}

static int rename0(const char *oldpath, const char *newpath) {
    int ret = rename0_internal(oldpath, newpath);
    if (-1 != ret) {

        char realnewpath[PATH_MAX], linknewpath[PATH_MAX];
        char *rl = realpath(newpath, realnewpath);
        if (!rl) {

            long l = readlink(newpath, linknewpath, PATH_MAX);
            if (l<0) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    return ret;
}

int renameat0(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    char oldfilenamebuff[PATH_MAX];
    int err1 = pathat(olddirfd, oldpath, oldfilenamebuff, PATH_MAX);

    if (!err1) {
        char newfilenamebuff[PATH_MAX];
        int err2 = pathat(newdirfd, newpath, newfilenamebuff, PATH_MAX);

        if (!err2) {
            return rename(oldfilenamebuff, newfilenamebuff);
        }
    }

    errno = ENOENT;
    return -1;
}

static int truncate_internal(long idx, off_t length){

    if (idx < 0 || idx >= filesystem->data.nfiles) {
        errno = ENOENT;
        return -1;
    }

    file_t *f = &filesystem->data.filetable[idx];
    if (IVMFS_ISDIR(f->type)){
        errno = EISDIR;
        return -1;
    }

    #ifdef IVMFS_DEBUG
    fprintf(stderr,"[%s] idx=%ld ('%s') new length=%ld\n", __func__, idx, f->name, length);
    #endif

    if (length < f->size){
        f->size = length;
    } else {

        int fd, alreadyopen = 0, cur_pos;
        fd = find_fileno(idx);

        if (fd >=0) {

            #ifdef IVMFS_DEBUG
            fprintf(stderr,"[%s] marked as already open idx=%ld('%s') fd=%d new length=%ld\n", __func__, idx, f->name, fd, length);
            #endif
            if (fd < 0) {
                errno = ENOENT;
                return -1;
            }
            alreadyopen = 1;
            cur_pos = get_position(fd);
            set_position(fd, f->size);
        } else {
            fd = open(f->name, O_WRONLY | O_APPEND);
        }

        if (fd >= 0){

            long delta = length - f->size;
            long nw = 0;

            char *zeros = (char*)calloc(delta, sizeof(char));
            if (zeros) {
                nw = write(fd, zeros, delta);
                free(zeros);
            }

            if (alreadyopen) {

                set_position(fd, cur_pos);
            } else {
                close(fd);
            }

            if (nw < delta){
                errno = EFBIG;
                return -1;
            }
        } else {
            errno = EACCES;
            return -1;
        }
    }
    return 0;
}

static int truncate0(const char *path, off_t length)
{

    if (has_trail((char*)path)){
        errno = ENOENT;
        return -1;
    }

    #ifdef IVMFS_DEBUG
    fprintf(stderr,"[%s] path='%s' length=%ld\n", __func__, path, length);
    #endif

    long idx = find_file((char *)path);

    if (idx < 0 || IVMFS_ISLNK(filesystem->data.filetable[idx].type)){

        static long trylink = 0;
        if (!trylink) {

            char linkname[PATH_MAX];
            char *rl = realpath(path, linkname);
            if (rl) {

                trylink = 1;
                int err = truncate(rl, length);
                trylink = 0;
                return err;
            } else {
                errno = ENOENT;
                return -1;
            }
        }
    }

    return truncate_internal(idx, length);
}

static int ftruncate0(int fd, off_t length)
{
    #ifdef IVMFS_DEBUG
    fprintf(stderr,"[%s] fd=%d length=%ld\n", __func__, fd, length);
    #endif

    long idx = find_open_file(fd);
    return truncate_internal(idx, length);
}

static int is_subdir(char *dirname, char* fullpath){

    #ifdef IVMFS_DEBUG

    #endif

    if (!dirname || !*dirname || !fullpath || !*fullpath){
        return 0;
    }

    #ifdef IVMFS_DEBUG_IS_SUBDIR
    fprintf(stderr, "[%s] dirname='%s' fullpath='%s'\n", __func__, dirname, fullpath);
    #endif

    char dirname_copy[PATH_MAX+1];
    strcpy(dirname_copy, dirname);

    if (strlen(fullpath) <= strlen(dirname_copy) ){
        return 0;
    }

    #ifdef IVMFS_DEBUG_IS_SUBDIR
    fprintf(stderr, "[%s] dirname_copy='%s' \n", __func__, dirname_copy);
    #endif

    long l = strlen(dirname_copy) + 1;
    char *p = &fullpath[l];

    #ifdef IVMFS_DEBUG_IS_SUBDIR
    fprintf(stderr, "[%s] p='%s' \n", __func__, p);
    #endif

    while (*p && (*p != '/')){ p++;}

    #ifdef IVMFS_DEBUG_IS_SUBDIR
    fprintf(stderr, "[%s] p='%s' \n", __func__, p);
    #endif

    if (!*p){

        return 1;
    }

    #ifdef IVMFS_DEBUG_IS_SUBDIR
    fprintf(stderr, "[%s] p='%s': '%s' no immediate subdir of '%s'\n\n",
                    __func__, p, fullpath, dirname);
    #endif

    return 0;
}

static long getdents0(unsigned int fd, struct dirent *dirp, unsigned int count){
    /* IVM64 struct dirent is defined in newlib/libc/include/sys/dirent.h*/

    struct dirent newdirent;

    long idx = find_open_file(fd);
    if (-1 == idx) {
        errno = ENOENT;
        return -1;
    }

    long pos = get_position(fd);

    file_t *d = &filesystem->data.filetable[idx];
    char *dname = d->name;

    #ifdef IVMFS_GETDENTS_RETURNS_DOT_DIRS

    if ((0 == pos) || (1 == pos)) {
        dirp[0].d_off = pos;
        dirp[0].d_reclen = sizeof(struct dirent);
        dirp[0].d_type = DT_DIR;
        if (0 == pos) {

            strcpy(dirp[0].d_name, ".");

            dirp[0].d_ino = IVMFS_FIRST_INO() + idx;
        } else if (1 == pos){

            strcpy(dirp[0].d_name, "..");

            char parentdir[PATH_MAX];
            strcpy(parentdir, dname);
            long idxp = find_dir_nocanon(dirname(parentdir));

            if (idxp >=0)
                dirp[0].d_ino = IVMFS_FIRST_INO() + idxp;
            else
                dirp[0].d_ino = -1;
        }
        set_position(fd, ++pos);
        return sizeof(struct dirent);
    }
    #endif

    long i = pos;
    #ifdef IVMFS_GETDENTS_RETURNS_DOT_DIRS
        i -=2;
    #endif

    unsigned long *n = &filesystem->data.nfiles;

    if (i < *n) {

        for (; i < *n; i++){
            char *filename =  filesystem->data.filetable[i].name;

            #ifdef IVMFS_DEBUG_DELETED
            if (!strncmp(dname, filename, strlen(dname)) || filename[0]=='*') break;
            #else

            if (is_prefix(dname, filename) && is_subdir(dname, filename)){
                #ifdef IVMFS_DEBUG
                long ldname = strlen(dname);
                fprintf(stderr,"[%s] i=%ld dname='%s' ldname='%ld'\n", __func__, i, dname, ldname);
                #endif
                break;
            }
            #endif
        }
        if (i < *n) {
            file_t *f = &filesystem->data.filetable[i];

            newdirent.d_ino = IVMFS_FIRST_INO() + i;
            newdirent.d_off = pos;
            newdirent.d_reclen = sizeof(struct dirent);

            newdirent.d_type = DT_REG;
            if (IVMFS_ISDIR(f->type))
                newdirent.d_type = DT_DIR;
            if (IVMFS_ISLNK(f->type))
                newdirent.d_type = DT_LNK;

            char name_copy[PATH_MAX];

            strcpy(name_copy, f->name); name_copy[PATH_MAX-1]='\0';

            if (name_copy[strlen(name_copy)-1] == '/') { name_copy[strlen(name_copy)-1] = '\0';}

            strcpy(newdirent.d_name, basename(name_copy));
            newdirent.d_name[NAME_MAX-1]='\0';

            #ifdef IVMFS_DEBUG
            fprintf(stderr,"[%s] fullname='%s' name_copy='%s' dirent.d_name='%s'\n",
                           __func__, f->name, name_copy, newdirent.d_name);
            #endif

            i++;

            pos = i;
            #ifdef IVMFS_GETDENTS_RETURNS_DOT_DIRS
                pos +=2;
            #endif
            set_position(fd, pos);

            dirp[0] = newdirent;
            return 1*sizeof(newdirent);
        }
    }

    pos = i;
    #ifdef IVMFS_GETDENTS_RETURNS_DOT_DIRS
        pos +=2;
    #endif
    set_position(fd, pos);

    return 0;
}

static void _seekdir0(DIR *dirp, long loc)
{

    fid_t fd = dirfd(dirp);
    long idx = find_open_file(fd);
    if (-1 == idx) {
        return;
    }

    lseek(fd, loc, SEEK_SET);
}

long telldir(DIR *dirp)
{
    fid_t fd = dirfd(dirp);

    return lseek(fd, 0, SEEK_CUR);
}

void _cleanupdir(DIR *dirp)
{
    return;
}

/* Functions resolve_path_internal() and realpath_internal() based on the
 * newlib routines by Werner Almesberger */
/* This internal version does stat the file names or not (only expand the path
 * syntactically, in order to avoid infinite recursions) depending on argument
 * 'nocheck' */
static int resolve_path_internal(char *path,char *result,char *pos, int nocheck)
{
    long max_link_length = PATH_MAX;

    if (*path == '/') {
        *result = '/';
        pos = result+1;
        path++;
    }
    *pos = 0;
    if (!*path) return 0;
    while (1) {
        char *slash;
        struct stat st;

        slash = *path ? strchr(path,'/') : NULL;
        if (slash) *slash = 0;

        if (!path[0] || (path[0] == '.' &&
          (!path[1] || (path[1] == '.' && !path[2])))) {
            pos--;
            if (pos != result && path[0] && path[1])
                while (*--pos != '/');
        }
        else {
            strcpy(pos,path);
            if (!nocheck) {
                if (lstat_nocanon(result,&st) < 0) return -1;
                if (S_ISLNK(st.st_mode)) {
                    char buf[PATH_MAX];
                    if (readlink(result,buf,sizeof(buf)) < 0) return -1;
                    max_link_length -= strnlen(buf, sizeof(buf)) + 2;
                    if (max_link_length <= 0) {
                        errno = ELOOP;
                        return -1;
                    }
                    *pos = 0;
                    if (slash) {
                        *slash = '/';
                        strcat(buf,slash);
                    }
                    strcpy(path,buf);
                    if (*path == '/') result[1] = 0;
                    pos = strchr(result,0);
                    continue;
                }
            }
            pos = strchr(result,0);
        }
        if (slash) {
            *pos++ = '/';
            path = slash+1;
        }
        *pos = 0;
        if (!slash) break;
    }
    return 0;
}

static char *realpath_internal(const char *__restrict path, char *__restrict resolved_path, int nocheck)
{
    char cwd[PATH_MAX];
    char path_copy[PATH_MAX];
    int res;

    if (!path) {
        errno = ENOENT;
        return NULL;
    }

    if (strnlen(path,PATH_MAX+1) > PATH_MAX){
        errno = ENAMETOOLONG;
        return NULL;
    }

    if (!*path) {
        errno = ENOENT; /* SUSv2 */
        return NULL;
    }

    int allocated = 0;
    if (resolved_path == NULL) {

        allocated = 1;
        resolved_path = (char * __restrict)malloc(PATH_MAX*sizeof(char));
        if (!resolved_path) return NULL;
    }

    #ifndef __ivm64__
        if (!getcwd(cwd,sizeof(cwd))) {
            if (allocated) free(resolved_path);
            return NULL;
        }
        strcpy(resolved_path,"/");
        if (resolve_path_internal(cwd,resolved_path,resolved_path, nocheck)) {
            if (allocated) free(resolved_path);
            return NULL;
        }
        strcat(resolved_path,"/");
    #else
        if ('/' == path[0]) {

            strcpy(cwd, "/");
        } else {
            if (!getcwd(cwd,sizeof(cwd))) {
                if (allocated) free(resolved_path);
                return NULL;
            }
            strcpy(resolved_path,"/");
            if (resolve_path_internal(cwd,resolved_path,resolved_path, nocheck)) {
                if (allocated) free(resolved_path);
                return NULL;
            }

            if (resolved_path[strlen(resolved_path)-1] != '/'){
                strcat(resolved_path,"/");
            }
        }
    #endif

    strncpy(path_copy, path, PATH_MAX); path_copy[PATH_MAX-1]='\0';
    res = resolve_path_internal(path_copy,resolved_path,strchr(resolved_path,0), nocheck);
    if (res) {
        if (allocated) free(resolved_path);
        return NULL;
    }

    #ifdef __ivm64__
    if (!strcmp(resolved_path, "")){
        strcpy(resolved_path, "/");
    }
    #endif

    return resolved_path;
}

static char *realpath_nocheck(const char *path,char *resolved_path)
{
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] path='%s'\n",__func__, path);
    #endif
    return realpath_internal(path, resolved_path, 1);
}

static char *realpath0(const char * __restrict path, char * __restrict resolved_path)
{
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] path='%s'\n",__func__, path);
    #endif

    return realpath_internal(path, resolved_path, 0);
}

static char *realparentpath(const char *path, char *resolved_path)
{
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] path='%s'\n",__func__, path);
    #endif

    if (!path || !*path){
        #ifdef IVMFS_DEBUG
        fprintf(stderr, "[%s] path='%s' (null or empty string)\n",__func__, path);
        #endif
        errno = EINVAL;
        return NULL;
    }

    char path_notrail[PATH_MAX], trail[PATH_MAX];
    remove_trail2((char*)path, path_notrail, trail);

    char *pd, parent[PATH_MAX], parentrealpath[PATH_MAX], *rl;
    strcpy(parent, path_notrail);
    pd = dirname(parent);

    rl = realpath(pd, parentrealpath);

    if (!rl){
        errno = EINVAL;
        return NULL;
    }

    char *bn, buff2[PATH_MAX], buff3[PATH_MAX];
    strcpy(buff2, path_notrail);
    bn = basename(buff2);

    strcpy(buff3, parentrealpath);
    strcat(buff3, "/");
    strcat(buff3, bn);

    if (!*trail) {

        rl = realpath_nocheck(buff3, resolved_path);

    } else {

        strcat(buff3, "/");
        strcat(buff3, trail);
        rl = realpath(buff3, resolved_path);
    }

    if (!rl){
        errno = EINVAL;
        return NULL;
    }

    return resolved_path;
}

static ssize_t readlink0(const char *pathname, char *buf, size_t bufsiz) {
    #ifdef IVMFS_DEBUG
    fprintf(stderr, "[%s] pathname='%s'\n",__func__, pathname);
    #endif

    if (!pathname || !*pathname){
        #ifdef IVMFS_DEBUG
        fprintf(stderr, "[%s] path='%s' (null or empty string)\n",__func__, pathname);
        #endif
        errno = EINVAL;
        return -1;
    }

    if (bufsiz <= 0){
        errno = EINVAL;
        return -1;
    }

    char pathname2[PATH_MAX], buff[PATH_MAX], *rl;
    rl = realparentpath(pathname, pathname2);
    if (!rl) {
        errno = EINVAL;
        return -1;
    }

    rl = realpath_nocheck(pathname2, buff);

    if (rl) {
        long idx = find_file(rl);
        if (idx >= 0 && IVMFS_ISLNK(filesystem->data.filetable[idx].type)) {
            char *p = strncpy(buf, *(filesystem->data.filetable[idx].data), bufsiz);
            return strlen(p);
        }
    }

    errno = EINVAL;
    return -1;
}

static ssize_t readlinkat0(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    char filenamebuff[PATH_MAX];
    int err = pathat(dirfd, pathname, filenamebuff, PATH_MAX);

    if (!err) {
        return readlink(filenamebuff, buf, bufsiz);
    } else {
        errno = ENOENT;
        return -1;
    }
}

static int dup0(int oldfd)
{

    fid_t newfd = open("/", O_RDONLY | O_DIRECTORY);
    if (newfd >= 0) close(newfd);

    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[%s] dup(%d) -> dup2(%d,%d)\n", __func__, oldfd, oldfd, newfd);
    #endif

    if (newfd >=0){
        return dup2(oldfd, newfd);
    }

    errno = EBADF;
    return -1;
}

static int dup2_0(int oldfd, int newfd)
{
    #ifdef IVMFS_DEBUG
        fprintf(stderr, "[%s] dup2(%d, %d)\n", __func__, oldfd, newfd);
    #endif

    if (newfd < 0
        || !is_valid_fileno(oldfd)){
        errno = EBADF;
        return -1;
    }

    long idx;
    if (filesystem->data.openfile[oldfd].dev == DEVDISK) {
        idx = find_open_file(oldfd) ;
        if (idx < 0){

            errno = EBADF;
            return -1;
        }

    }

    if (newfd == oldfd){
        return oldfd;
    }

    if ((unsigned long)newfd >= filesystem->data.openfile_size) {
        openfile_t *of = reallocate_openfile(newfd);
        if (!of) {
            errno = EBADF;
            return -1;
        }
    }

    close(newfd);

    filesystem->data.openfile[newfd] =
      filesystem->data.openfile[oldfd];

    return newfd;
}

static int symlink0(const char *target, const char *linkpath)
{
    if (!target || !*target || !linkpath || !*linkpath) {
        errno = ENOENT;
        return -1;
    }

    if ((strnlen(target,PATH_MAX+1) > PATH_MAX) || (strnlen(linkpath,PATH_MAX+1) > PATH_MAX)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    long idx = find_file((char*)linkpath);
    if (idx >= 0){
        errno = EEXIST;
        return -1;
    }

    int fid = open((char*)linkpath, O_WRONLY | O_CREAT | O_TRUNC);
    if (fid >= 0) {

        write(fid, target, strlen(target)+1);

        idx = filesystem->data.openfile[fid].idx;
        close(fid);
        filesystem->data.filetable[idx].type = IVMFS_LNK;
        return 0;
    }

    errno = ENOENT;
    return -1;
}

static int symlinkat0(const char *target, int newdirfd, const char *linkpath)
{
    char newpathbuff[PATH_MAX];
    int err = pathat(newdirfd, linkpath, newpathbuff, PATH_MAX);

    if (!err) {
        return symlink(target, newpathbuff);
    }

    errno = ENOENT;
    return -1;
}

static int isatty0(int fd)
{
    if (!is_valid_fileno(fd)) {
        errno=EBADF;
        return 0;
    }
    if (filesystem->data.openfile[fd].open
        && (filesystem->data.openfile[fd].dev == DEVSTDIN
            || filesystem->data.openfile[fd].dev == DEVSTDOUT
            || filesystem->data.openfile[fd].dev == DEVSTDERR))
    {
        return 1;
    }
    errno=ENOTTY;
    return 0;
}

ssize_t getdents64(int fd, void *dirp, size_t count)
{
    return getdents(fd, (struct dirent*)dirp, count);
}

int newfstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    return fstatat(dirfd, pathname, statbuf, flags);
}

static int fcntl0(int fd, int cmd, ... /* arg */ )
{
    return 0;
}

int link(const char *oldpath, const char *newpath)
{
    errno = ENOSYS;
    return -1;
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
    errno = ENOSYS;
    return -1;
}

void debug_print_file_table(){
    for (long idx=0; idx < filesystem->data.nfiles; idx++){
        file_t *f = &filesystem->data.filetable[idx];
        printf("idx=%ld [%c], filename='%s'\n", idx, (f->type==IVMFS_REG)?'r':(f->type==IVMFS_DIR)?'d':'l', f->name);
    }
}

void debug_print_open_file_table(){
    for (int fid = 0; fid < filesystem->data.openfile_size; fid++) {
        openfile_t *fo = &filesystem->data.openfile[fid];
        if (fo->open){
            const char *name = "n/a";
            long size= -1;
            long allocated = 0;
            long idx = filesystem->data.openfile[fid].idx;
            if (idx >= 0){
                file_t *f = &filesystem->data.filetable[idx];
                name = f->name;
                size = f->size;
                allocated = f->allocated;
            }
            fprintf(stdout, "fid=%d idx=%ld name='%s' pos=%ld size=%ld allocated=%ld\n", fid, idx, name, fo->pos_p?(*fo->pos_p):-1, size, allocated);
        }
    }
}

int debug_has_trail(char *a){
    return has_trail(a);
}

char *debug_remove_trail2(char *a, char *b, char *c){
    return remove_trail2(a, b, c);
}

char *debug_realpath_nocheck(const char *a, char *b){
    return realpath_nocheck(a,b);
}

char *debug_realparentpath(const char *a, char *b){
    return realparentpath(a,b);
}

long debug_get_spawnlevel(){
    return filesystem->data.spawn_level;
}

#ifdef __cplusplus
}
#endif

#endif /*__ivm64__*/
EEOOFF
}

#--------------------
print_header
print_preamble
print_files "$@"
print_structure
print_functions
