/*
 * This is a simple program that makes a series of random modifications to an arbitrarily large specified file
 * designed as part of a test for file-ptrace and merkle tree generation and updating for hotpocket
 * Originally from: https://github.com/codetsunami/file-ptracer/blob/master/rnd_contract.c
 */

// Compile with: gcc rnd_contract.c -o rnd_contract -g

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3)
        return fprintf(stderr, "usage %s <file path to randomly edit> <max no. of block modifications>\n", argv[0]);

    // Read from input ts
    char buf[128];
    read(STDIN_FILENO, buf, 128);

    // Read timestamp mentioned in contract args json.
    char tsbuf[14];
    memcpy(tsbuf, &buf[100], 13);
    tsbuf[13] = '\0';
    int ts = atoi(tsbuf);
    //printf("args input: %.13s\n", tsbuf);

    // Use contract args timestamp to initialize random seed.
    srand(ts);

    FILE *f = fopen(argv[1], "rb+");
    if (!f)
        return fprintf(stderr, "could not open file %s\n", argv[1]);

    int max_mod = strtol(argv[2], NULL, 10);

    int fd = fileno(f);

    fseek(f, 0L, SEEK_END);
    size_t len = ftell(f);

    // we don't need to rewind because now we'll use pwrite

    // pick a random number of modications to make between 1 and 50
    int mods = rand() % max_mod + 1;

    pid_t pid = getpid();

    for (int i = 0; i < mods; ++i)
    {
        // pick a random file offset
        size_t offset = rand() % len;

        // pick a random number of bytes to write, up to 100
        size_t bytestowrite = rand() % 100;

        char buf[100];

        // write the bytes to a buffer
        for (int n = 0; n < bytestowrite; ++n)
            buf[n] = rand() % 0xff;

        // write the buffer to the random file location
        int n = pwrite(fd, buf, bytestowrite, offset);
        if (!n)
            continue;
        int start_block = offset / (4 * 1024 * 1024);
        int end_block = (offset + bytestowrite) / (4 * 1024 * 1024);
        for (int i = start_block; i <= end_block; ++i)
        {
            // printf("@@@ pid %d wrote to block %d ... %d bytes\n", pid, i, n);
            fflush(stdout);
        }
    }

    // done!

    fclose(f);
    return 0;
}
