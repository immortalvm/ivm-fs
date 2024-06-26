# IVM Filesystem

## Introduction
This static filesystem generator allows to recreate a read/write
in-ram file system for testing the ivm64 ecosystem.

By invoking the script ```ivm64-fsgen``` with the list of files to include in the filesystem,
it will print to stdout a C code with the file contents and some primitives
(open, read, lseek, ...) with the API to access the files:

```ivm64-fsgen file1 file2 ... > ivmfs.c```

Note that files or directories are added individually to the filesystem and, therefore, to add  a folder recursively you may wish to do:

```ivm64-fsgen $(find folder_name) ... > ivmfs.c```


As an alternative to the C code, the assembly object (```.o```) can be generated directly, with the advantage that it is not necessary to compile it (only link). This is specially useful for large filesystem.
To generate the object directly use the flag ```-o``` as the first argument of the script, followed by the name of the output object and the list of files to be included in the filesystem:

```ivm64-fsgen -o ivmfs.o file1 file2 ...```

Note that the object does not include the primitives to work with the files, so it may be needed to link with an empty filesystem in C format
(see [Compiling](#compiling) and [About very large filesystems](#about-very-large-filesystems))

## Compiling
 
Once the filesystem is generated, you can link a program with the generated C containing the filesystem, so that the primitives included in it will replace those of newlib, therefore enabling to access the
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

Alternative, if an assembly object has been generated instead of the C output, you can link it with the rest of the project:

```ivm64-gcc ivmfs.o main.c ```   ```    #link ivmfs.o before libraries```

Note that the primitives to use the filesystem are not included in the object, but they should be included in the newlib library provided by the compiler by default.
Nevertheless you could generate an additional empty filesystem including those primitives:

```
  ivm64-fsgen -o ivmfs.o file1 file2 ... # fs data in ivmfs.o (object)
  ivm64-fsgen > ivmfs-empty.c            # empty fs with primitives (C)
  ivm64-gcc ivmfs.o ivmfs-empty.c main.c # link all together, .o first
```

## Directories 

By default the current work directory of the generated ivm filesystem is ```/work```. In this way, when it is invoked ```ivm64-fsgen filename```, with ```filename``` a file in the current work directory, it will be mapped in the ivm filesystem with the path ```/work/filename```.

The initial working directory is therefore ```/work``` (except when there are no files coming from the current directory in which case the working directory may be ```/```).

On the other hand, if the file name is an absolute path, the path is  considered part of the name, and the corresponding directories are (re)created. So when you use ```ivm64-fsgen /path/to/file```, the file can be opened  as ```open("/path/to/file",...)```, or alternatively, you can do ```chdir("/path/to"); open("file", ...)```.

Here is an example of the mapping:
```sh
  # The following code generates this ivmfs tree:
  #  /
  #  ├── etc
  #  │   └── services
  #  └── work
  #      ├── d
  #      │   └── file2
  #      └── file1
   cd /tmp/
   touch file1
   mkdir d
   touch d/file2
  # Let's include some files in the current directory and another absolute path:
  #    file1, d/file2 are relative to the working directory: mapped to /work
  #    /etc/services is absolute 
   ivm64-fsgen file1 d/file2 /etc/services > ivmfs.c
  
```

## Standard input

By default, the operations on the _standard input_ proceed with the current standard input of the console where the simulator is executed. The same happens with _standard_ and _error output_ streams.

Nevertheless, the stdin can be simulated using the file defined by  the macro STDIN_FILE ("stdin" by default). In this case, if a program requires the _standard input_, it will use the content of  "stdin". Basically the file STDIN_FILE is redirected to the standard input (if included in the filesystem). To this end, this script should be invoked as:

  ```ivm64-fsgen stdin file1.c file2.c ... > ivmfs.c ```


## About very large filesystems

In case of very large filesystem (>1GB), it is recommended to generate data in assembly object format (using ```-o``` flags, see [Introduction](#introduction)), and link it directly with the rest of the project:
```
  # Directly, generate the assembly object with the files of interest:
      ivm64-fsgen -o ivmfs-large.o $(find folder_name_with_files)
  # Optionally, generate an empty filesystem
  # (in C, containing fs API): 
      ivm64-fsgen > ivmfs-empty.c
  # Link ivmfs-large.o with the rest of the project
  # (optionally with an empty fs).
  # Do not forget to place the object with the FS in the first place 
      ivm64-gcc ivmfs-large.o ivmfs-empty.c main.c ....
```

## Debugging options

```ivm64-gcc -DIVMFS_DEBUG ivmfs.c ...             # print information for each file operation ```

```ivm64-gcc -DIVMFS_DUMPFILES ivmfs.c ...         # dump a list of files when the program exits ```

```ivm64-gcc -DIVMFS_DUMPFILECONTENTS ivmfs.c ...  # dump the contents of all files when the program exits ```

## Coverage

This is a list of low-level primitives that are supported:
```
open openat close read write lseek
stat fstat lstat fstatat access faccessat
getcwd get_current_dir_name isatty
truncate ftruncate
mkdir mkdirat chdir fchdir getdents
unlink unlinkat rmdir
rename renameat symlink symlinkat dup dup2
readlink readlinkat realpath
```

In addition to these, common higher filesystem functions from the C standard
library implemented by newlib can be used in your C codes, such as:

```
fopen fclose fread fwrite fileno feof
printf scanf fscanf fprintf
opendir readdir scandir dirfd, ...
```

Developers need keep in mind that this filesystem provides a **relaxed** implementation of the primitives, so all the potential described in POSIX manuals may not be available. 

Hard links and special file types are not yet supported. File permissions and ownership are not available either.


Date: Apr 2024
