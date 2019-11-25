#ifndef _FUSE_FS_
#define _FUSE_FS_

namespace fusefs
{
int start(const char *arg0, const char *source, const char *mountpoint, const char *deltadir);
}

#endif