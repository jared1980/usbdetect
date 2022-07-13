#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <unistd.h>

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + 16))


void inotify_add_watch_path_loop(const char *path, uint32_t mask)
{
  char buffer[BUF_LEN];
  int length, i = 0;
  int fd, wd;

  /* https://man7.org/linux/man-pages/man2/inotify_init.2.html */
  fd = inotify_init();
  if (fd < 0)
  {
    perror("inotify_init");
    return;
  }

  wd = inotify_add_watch(fd, path, mask);

  while(wd > 0)
  {
    length = read(fd, buffer, BUF_LEN);
    printf("[Event] The file length = %d\n", length);

    if (length < 0)
    {
      perror("read");
    }

    i = 0;
    while (i < length)
    {
#if 0
           struct inotify_event {
               int      wd;       /* Watch descriptor */
               uint32_t mask;     /* Mask describing event */
               uint32_t cookie;   /* Unique cookie associating related
                                     events (for rename(2)) */
               uint32_t len;      /* Size of name field */
               char     name[];   /* Optional null-terminated name */
           };
#endif
        struct inotify_event *event = (struct inotify_event *) &buffer[i];

        if(event->wd != wd)
          continue;

        /* for event types, refer to https://man7.org/linux/man-pages/man7/inotify.7.html */
        if (event->len) {
            if (event->mask & IN_CREATE) {
                printf("[Event IN_CREATE] The file %s/%s was created.\n", watch_path.c_str(), event->name);
            } else if (event->mask & IN_DELETE) {
                printf("[Event IN_DELETE] The file %s/%s was deleted.\n", watch_path.c_str(), event->name);
            } else if (event->mask & IN_MODIFY) {
                printf("[Event IN_MODIFY] The file %s/%s was modified.\n", watch_path.c_str(), event->name);
            } else if (event->mask & IN_ATTRIB) {
                printf("[Event IN_ATTRIB] The file %s/%s was IN_ATTRIB.\n", watch_path.c_str(), event->name);
            }
        }
        i += EVENT_SIZE + event->len;
    }
  }


  (void) inotify_rm_watch(fd, wd);
  (void) close(fd);
}

