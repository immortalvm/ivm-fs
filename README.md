# IVM Filesystem

## Introduction
This static filesystem generator allows to recreate a read/write
in-ram file system for testing the ivm64 ecosystem.

By invoking the script with the list of files to include in the filesystem,
it will print to stdout a C code with the file contents and some primitives
(open, read, lseek, ...) to access the files:

```ivmfs-gen.sh file1.c file2.c ... > ivmfs.c```

Note that files or directories are added individually to the filesystem and, therefore, to add  a folder recursively you may wish to do:

```ivmfs-gen.sh $(find folder_name) ... > ivmfs.c```


## Compiling
 
Once the filesystem is generate, you can link a program with the generated C containing the filesystem, so that the primitives included in it will replace those of newlib, therefore enabling to access the
files in a stardard way:

```ivm64-gcc ivmfs.c main.c ```   ```    #compile ivmfs.c before libraries```

 where main.c can be like this:
```
   main(){
     FILE *f = fopen("file1.txt", "r");
     int n = fread(buff, 1, 5, f);
     ...
    }
```
## Directories 

By default the current work directory of the generated ivm filesystem is ```/work```. In this way, when it is invoked ```ivmfs-gen.sh filename```, with ```filename``` a file in the current work directory, it will be mapped in the ivm filesystem with the path ```/work/filename```.

The initial working directory is therefore ```/work```, except when there are no files coming from the current directory in which case the working directory is ```/```.

On the other hand, if the file name is an absolute path, the path is  considered part of the name, and the corresponding directories are (re)created. So when you use ```ivmfs-gen.sh /path/to/file```, the file can be opened  as ```open("/path/to/file",...)```, or alternatively, you can do ```chdir("/path/to"); open("file", ...)```.

## Standard input

The stdin can be simulated using the file defined by
 the macro STDIN_FILE ("stdin" by default). If
 a program requires STDIN, it will use the content of
 "stdin". To this end, this script should be invoked as:

  ```ivmfs-gen.sh stdin file1.c file2.c ... > ivmfs.c ```


## Compilation options:

```ivm64-gcc -DIVMFS_DEBUG ivmfs.c ...             # print information for each file operation ```

```ivm64-gcc -DIVMFS_DUMPFILES ivmfs.c ...         # dump a list of files when the program exits ```

```ivm64-gcc -DIVMFS_DUMPFILECONTENTS ivmfs.c ...  # dump the contents of all files when the program exits ```



## Coverage

This is a list of low-level primitives that are supported:
```
open openat close read write lseek
stat fstat lstat fstatat access faccessat
getcwd get_current_dir_name
truncate ftruncate
mkdir mkdirat chdir fchdir getdents
unlink unlinkat rmdir
rename renameat dup dup2
readlink realpath
```

In addition to these, common higher filesystem functions from the C standard
library implemented by newlib can be used, such as:

```
fopen fclose fread fwrite fileno feof
printf scanf fscanf fprintf
opendir readdir scandir dirfd, ...
```

Developers need keep in mind that this filesystem provides a **relaxed** implementation of the primitives, so all the potential described in POSIX manuals may not be available. 

Soft/hard links and special file types are not yet supported. File permissions and ownership are not available either.


Date: Jun 2023
