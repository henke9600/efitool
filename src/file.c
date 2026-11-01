#include "file.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

void file_init(struct file *self) {
    self->handle = NULL;
}

int file_open(struct file *self, const char *file, int mode) {
    if (file == NULL) return 0;

    const char *mode_string;
    switch (mode) {
        case 0:                                mode_string = "rb"; break;
        case FILE_MODE_TEXT:                   mode_string = "r";  break;
        case FILE_MODE_WRITE:                  mode_string = "wb"; break;
        case FILE_MODE_WRITE | FILE_MODE_TEXT: mode_string = "w";  break;
        default: abort();
    }

    errno = 0;
    if (strcmp(file, "-") == 0) {
        if (mode & FILE_MODE_WRITE) self->handle = stdout;
        else self->handle = stdin;

        bool text_mode = mode & FILE_MODE_TEXT;
        if (!text_mode) {
            // Make sure the stream is in binary mode
            self->handle = freopen(NULL, mode_string, self->handle);
            if (self->handle == NULL) goto err;
        }
        return 0;
    }

    self->handle = fopen(file, mode_string);
    if (self->handle == NULL) goto err;
    return 0;

    err:;
    // fopen and freopen are not guaranteed to set errno
    const char *error = "Unknown error";
    if (errno != 0) error = strerror(errno);
    (void)fprintf(stderr, "ERROR: Failed to open '%s': %s\n", file, error);
    return -1;
}

int file_read(const struct file *self, void *buffer, size_t size, size_t *out_num_read) {
    if (self->handle == NULL) return -1;

    *out_num_read = fread(buffer, 1, size, self->handle);
    if (ferror(self->handle) != 0) return -1;
    if (feof(self->handle) != 0) return 0;
    if (*out_num_read != size) return -1;
    return 1;
}

int file_gets(const struct file *self, char *buffer, int num_to_read) {
    if (self->handle == NULL) return -1;

    const char *res = fgets(buffer, num_to_read, self->handle);
    if (ferror(self->handle) != 0) return -1;
    if (feof(self->handle) != 0) {
        if (res == NULL) buffer[0] = '\0'; // Make sure a valid string is always written on success
        return 0;
    }
    if (res == NULL) return -1;
    return 1;
}

int file_write(const struct file *self, const void *buffer, size_t size) {
    if (self->handle == NULL || size == 0) return 0;

    if (fwrite(buffer, 1, size, self->handle) != size) return -1;
    return 0;
}

int file_puts(const struct file *self, const char *string) {
    if (self->handle == NULL) return 0;

    if (fputs(string, self->handle) == EOF) return -1;
    return 0;
}

int file_close(const struct file *self) {
    if (self->handle == NULL) return 0;

    return fclose(self->handle);
}
