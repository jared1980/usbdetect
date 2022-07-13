#ifndef __LIBINOTIFY_H__
#define __LIBINOTIFY_H__

#include <stdint.h>
#include <sys/inotify.h>

void inotify_add_watch_path_loop(const char *path, uint32_t mask);

#endif
