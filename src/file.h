#ifndef FILE_H
#define FILE_H

#include <stdio.h>

#define FILE_MODE_WRITE 1

struct file {
    FILE *handle;
};

void file_init(struct file *self);
int file_open(struct file *self, const char *file, int mode);
int file_read(const struct file *self, unsigned char *buffer, size_t size, size_t *out_num_read);
int file_write(const struct file *self, const unsigned char *buffer, size_t size);
int file_close(const struct file *self);

#endif
