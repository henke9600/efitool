#ifndef FILE_H
#define FILE_H

#include <stdio.h>

#define FILE_MODE_WRITE 1
#define FILE_MODE_TEXT 2

struct file {
    FILE *handle;
};

void file_init(struct file *self);

// A file of "-" refers to stdin or stdout, depending on mode. This takes
// ownership of the stdin/stdout handle, so it can't be used after
int file_open(struct file *self, char *file, int mode);
int file_read(struct file *self, void *buffer, size_t size, size_t *out_num_read);
int file_gets(struct file *self, char *buffer, int num_to_read);
int file_write(struct file *self, void *buffer, size_t size);
int file_puts(struct file *self, char *string);
int file_close(struct file *self);

#endif
