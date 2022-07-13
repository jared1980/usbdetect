#include "libinotify.h"

int main(int argc, char **argv)
{
  uint32_t mask = IN_CREATE | IN_DELETE;

  inotify_add_watch_path_loop("/sys/class/net", uint32_t mask);


  return 0;
}
