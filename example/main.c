#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static int test_open(char *name){
    int fid;
    fid = open(name, O_RDWR);
    if (fid < 0) 
        printf("%s NOT found in filesystem\n", name);
    else 
        printf("%s FOUND in filesystem\n", name);
    return fid;
}

// Dump the contents of a file to stdout
static void test_put_contents(char *name, int maxbufsize){
    printf("+------------------+\nContents of %s ", name); 
    int fid = open(name, O_RDONLY);
    if (fid > 0){
        char buff[maxbufsize];
        long n = read(fid, buff, maxbufsize-1);
        buff[n] = 0;
        printf("[%ld bytes]\n+------------------+\n%s\n+------------------+ \n", n, buff); 
        if (n == maxbufsize-1)
            printf("+----- Perhaps more than %d bytes in the file\n", maxbufsize);
        close(fid);
    } else {
        printf(" .. FAILED\n"); 
    }
}

int main(){
    FILE* fd;
    #define BUFSZ 256 
    char buff[BUFSZ], *msg;
    int fid;

    /* Low level primitives: open, read, close*/
    printf("=============== Low level fs primitives: open, read, close\n");
    test_open("cow.txt");
    test_open("hello1.txt");
    test_open("foo.txt");
    test_open("hello2.txt");

    printf("\n");
    fid = open("hello1.txt", 0);

    memset(buff, 0, BUFSZ);
    int n = read(fid, buff, 2);
    printf("(1) Read %d bytes:'%s' from fid=%d\n", n, buff, fid); 

    memset(buff, 0, BUFSZ);
    n = read(fid, buff, 18);
    printf("(2) Read %d bytes:'%s' from fid=%d\n", n, buff, fid); 

    memset(buff, 0, BUFSZ);
    n = read(fid, buff, 18);
    printf("(3) Read %d bytes:'%s' from fid=%d\n", n, buff, fid); 

    close(fid);

    fid = open("hello1.txt", 0);
    memset(buff, 0, BUFSZ);
    n = read(fid, buff, 18);
    printf("(4) Read %d bytes:'%s' from fid=%d\n", n, buff, fid); 

    lseek(fid, 3, SEEK_SET);
    memset(buff, 0, BUFSZ);
    n = read(fid, buff, 18);
    printf("(5) Read %d bytes:'%s' from fid=%d\n", n, buff, fid); 

    close(fid);

    printf("\n");
    fid = open("hello2.txt", 0);
    memset(buff, 0, BUFSZ);
    n = read(fid, buff, 1);
    printf("(6) Read %d bytes:'%s' from fid=%d\n", n, buff, fid); 
    memset(buff, 0, BUFSZ);
    n = read(fid, buff, 1);
    printf("(7) Read %d bytes:'%s' from fid=%d\n", n, buff, fid); 

    close(fid);

    fid = open("hello2.txt", 0);
    memset(buff, 0, BUFSZ);
    n = read(fid, buff, BUFSZ);
    printf("(8) Read %d bytes:'%s' from fid=%d\n", n, buff, fid); 

    printf("\n");
    close(fid);

    printf("Closing not existing files ...\n");
    close(4000);
    perror("??");
    close(-4000);
    perror("??");

    printf("\n");
    printf("Opening several times the same file ...\n");
    fid = open("hello2.txt", 0);
    printf("fid=%d\n", fid);
    fid = open("hello2.txt", 1);
    printf("fid=%d\n", fid);
    fid = open("hello3.txt", 1);
    printf("fid=%d\n", fid);
    fid = open("hello3.txt", 1);
    printf("fid=%d\n", fid);
    printf("Opening not existing file ...\n");
    fid = open("abc.txt", 0);
    printf("fid=%d\n", fid);

    printf("\n\n");

    /* High level primitives: fopen, fread, fclose*/
    printf("=============== High level fs primitives: fopen, fread, fclose\n\n");

    fd = fopen("hello1.txt", "r");
    if (fd) 
        printf("hello1.txt correctly open\n"); 
    else
        printf("opening hello1.txt failed\n");
    do { 
        memset(buff, 0, BUFSZ);
        n = fread(buff, 1, 6, fd);
        printf("- Read %d bytes:'%s' from stream=%p\n", n, buff, fd); 
        printf("   - EOF = %d\n", feof(fd));
    } while (n>0);
    fclose(fd);

    // Reading from a closed file
    printf("\n");
    printf("-------------- Reading a closed file\n");
    fd = fopen("hello2.txt", "r");
    fclose(fd);
    n = fread(buff, 1, 5, fd);
    if (0 == n) perror("reading a closed file");

    // Formatted input 
    printf("\n");
    printf("-------------- Formatted input\n");
    fd = fopen("hello3.txt", "r");
    if (fd){ 
        printf("hello3.txt correctly open\n"); 
        int a;
        float b;
        char c, s[16];
        n = fscanf(fd, "%d %f %c %s", &a, &b, &c, s);
        printf("Read a=%d, b=%f, c=%c, s=%s\n", a, b, c, s);

        rewind(fd);
        a=0; b=0.0; c='|'; memset(buff, 0, 16);
        n = fscanf(fd, "%d %f %c %s", &a, &b, &c, s);
        printf("Rewind ... and read again a=%d, b=%f, c=%c, s=%s\n", a, b, c, s);
    } else {
        printf("opening hello3.txt failed\n");
    }
    fclose(fd);


    /* Writing files */
    printf("\n");
    printf("=============== Writing files\n\n");
    test_put_contents("hello1.txt", 1024);

    printf("\n");
    fd = fopen("hello1.txt", "w"); 
    if (fd) { 
        fprintf(stderr, "hello1.txt 'w' (trunc) mode OK, writing '12345' ...\n");
        fprintf(fd, "12345");
        fclose(fd);
    } else { 
        fprintf(stderr, "hello1.txt 'w' (trunc) FAILED!\n");
    }

    printf("\n");
    test_put_contents("hello1.txt", 1024);

    printf("\n");
    fd = fopen("hello1.txt", "a"); 
    if (fd) { 
        fprintf(stderr, "hello1.txt 'a' (append) mode OK, appending '.000.000'\n");
        fprintf(fd, ".000.000");
        fclose(fd);
    } else {
        fprintf(stderr, "hello1.txt 'a' (append) mode FAILED!'\n");
    }

    printf("\n");
    test_put_contents("hello1.txt", 1024);

    printf("\n");
    fd = fopen("hello1.txt", "r"); 
    if (fd) fprintf(stderr, "hello1.txt 'r' (read only) mode OK, trying to write ... \n");
    fprintf(fd, "if you read this, read only mode failed !!");
    fclose(fd);

    printf("\n");
    test_put_contents("hello1.txt", 1024);

    printf("\n");
    fd = fopen("hello1.txt", "r+"); 
    if (fd) fprintf(stderr, "hello1.txt 'r+' mode OK, writing 'www' ... \n");
    fprintf(fd, "www");
    fclose(fd);

    printf("\n");
    test_put_contents("hello1.txt", 1024);

    printf("\n");
    fd = fopen("hello1.txt", "w+"); 
    int rep = 513;
    if (fd) fprintf(stderr, "hello1.txt 'w+' mode OK, writing %d times '+++' ... \n", rep);
    for (int i=0; i<rep; i++)
        fprintf(fd, "%3i%s %s", (i%10)?(i%10):i, "+++", ((i-9)%10)?"":"\n");
    fclose(fd);

    printf("\n");
    test_put_contents("hello1.txt", 1024*16);

    printf("\n");
    fd = fopen("new.txt", "w"); 
    if (fd) fprintf(stderr, "Creating a newfile 'new.txt' OK , writing 'hello!, hello new World!' ... \n");
    fprintf(fd, "hello! hello new World!");
    if (fd) fclose(fd);

    printf("\n");
    test_put_contents("new.txt", 64);

    printf("\n");
    fprintf(stderr, "Overwritting 'new.txt'... \n");
    fd = fopen("new.txt", "r+"); 

    int mpos = 3;
    fseek(fd, mpos, SEEK_CUR);
    n = fread(buff, 1, 2, fd);
    buff[n]=0;
    printf("Read %d chars at position %d: '%s'\n", n, mpos, buff);
    
    msg="<OVERWRITE>";
    //if (fseek(fd, mpos, SEEK_SET) != -1) printf("fseek OK\n");
    if (fseek(fd, -5, SEEK_END) != -1) printf("fseek OK\n");
    fprintf(fd, "%s", msg);
    //fwrite(msg, 1, strlen(msg)+1, fd);
    fclose(fd);
    
    printf("\n");
    test_put_contents("new.txt", 1024);

    /* Testing file stat*/
    printf("\n");
    printf("=============== Testing stat\n\n");

    struct stat S;
    char *t[4] = {"baz.txt", "hello1.txt", "hello2.txt", "new.txt"};
    for (int i=0; i<4; i++){
        if (stat(t[i], &S) < 0){
            printf("Can't stat %s\n", t[i]);
        } else {
            printf("%s: inode=%ld, size=%ld, blksz=%ld, size512=%ld\n",
                   t[i], S.st_ino, S.st_size, S.st_blksize, S.st_blocks);
        } 
    }
    printf("\n");

    for (int i=0; i<4; i++){
        fd = fopen(t[i], "r");
        if (fd) {
            if (fstat(fileno(fd), &S) < 0){
                printf("Can't stat %s\n", t[i]);
            } else {
                printf("%s: inode=%ld, size=%ld, blksz=%ld, size512=%ld\n",
                       t[i], S.st_ino, S.st_size, S.st_blksize, S.st_blocks);
            } 
            fclose(fd);
        }
    }
    printf("\n");

    /* Testing readin from STDIN (do not forget
       addin a file called "stdin"*/
    printf("\n");
    printf("=============== Testing STDIN\n\n");

    memset(buff, 0, BUFSZ);
    n = read(STDIN_FILENO, buff, BUFSZ-1);
    printf("Read from STDIN: '%s'\n", buff);

    /* Creating many files */  
    printf("\n");
    printf("=============== Creating many files\n\n");
    printf("Creating new files: \n");
    n = 10;
    for (int i=0; i<n; i++){
        sprintf(buff, "new%03d", i);
        if (fd = fopen(buff, "w")) {
            printf("+");  
            fclose(fd);
        } else {
            printf("-");  
        }

    }
    printf("\n");

    return 0;
}
