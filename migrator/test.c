#include <stdio.h>
#include <fcntl.h>
#include "mapalloc_migrator.h"

int main(int argc, char* argv[]) {
    int fd, rc;

    if (!has_migrated()) {
        if (argc < 2) {
            fprintf(stderr, "Please provide the path to an allocation file as the first argument\n");
            return -1;
        }

        fd = open(argv[1], O_RDWR);
        if (fd < 0) {
            perror("open");
            return -1;
        }

        rc = migrate_all(fd, 0);
        if (rc < 0) {
            fprintf(stderr, "Migration failed\n");
            return -1;
        }
    }

    puts("Hello world");
    return 0;
}
