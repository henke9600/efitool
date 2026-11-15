#include "file.h"
#include "util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void file_init(struct file *self) {
    self->handle = NULL;
}

int file_open(struct file *self, const char *file, int mode) {
    if (file == NULL) return 0;

    const char *mode_string;
    switch (mode) {
        case 0:               mode_string = "rb"; break;
        case FILE_MODE_WRITE: mode_string = "wb"; break;
        default: abort();
    }

    self->handle = util_fopen(file, mode_string);
    if (self->handle == NULL) return -1;
    return 0;
}

int file_read(const struct file *self, unsigned char *buffer, size_t size, size_t *out_num_read) {
    if (self->handle == NULL) return -1;

    *out_num_read = fread(buffer, 1, size, self->handle);
    if (ferror(self->handle) != 0) return -1;
    if (feof(self->handle) != 0) return 0;
    if (*out_num_read != size) return -1;
    return 1;
}

int file_write(const struct file *self, const unsigned char *buffer, size_t size) {
    if (self->handle == NULL || size == 0) return 0;

    if (fwrite(buffer, 1, size, self->handle) != size) return -1;
    return 0;
}

int file_close(const struct file *self) {
    if (self->handle == NULL) return 0;

    return fclose(self->handle);
}
