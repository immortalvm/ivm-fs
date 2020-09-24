 This static filesystem generator allows to recreate a read/write folderless 
 static filesystem for testing the ivm64 ecosystem.

 **It is required at least compiler version ivm64-gcc 1.0rc5**.
 
 By invoking the script with the list of files to include in the filesystem,
 it will print to stdout a C code with the file contents and some primitives
 (open, read, lseek, ...) to access the files:

```ivmfs-gen.sh file1.c file2.c ... > ivmfs.c```
 
 Note: if the file name includes paths to directories they are
 considered part of the name (i.e. if you use "ivmfs-gen.sh /path/to/file"
 you need to open it as 'open("/path/to/file"...)'
 
 Then you can link a program with the generated C file, so that the primitives
 included in it will replace those of newlib, therefore enabling to access the
 files in a stardard way:
 
```ivm64-gcc ivmfs.c main.c ```   ```    #always compile ivmfs.c before libraries```
 
 where main.c can be like this:
```
   main(){
     FILE *f = fopen("file1.txt", "r");
     int n = fread(buff, 1, 5, f);
     ...
    }
```

 The stdin can be simulated using the file defined by 
 the macro STDIN_FILE ("stdin" by default). If
 a program requires STDIN, it will use the content of
 "stdin". To this end, this script should be invoked as:

  ```ivmfs-gen.sh stdin file1.c file2.c ... > ivmfs.c ```


 Compilation options:

```ivm64-gcc -DIVMFS_DEBUG ivmfs.c ...  # print information for each file operation ```

```ivm64-gcc -DIVMFS_DUMPFILES ivmfs.c ...  # dump a list of files when the program exits ```

```ivm64-gcc -DIVMFS_DUMPFILECONTENTS ivmfs.c ...  # dump the contents of all files when the program exits ``` 


Date: Sep 2020


