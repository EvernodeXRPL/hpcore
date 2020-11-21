#include "../pchheader.hpp"
#include "buffer_store.hpp"

namespace util
{
    int buffer_store::init()
    {
        int fd = memfd_create("buffer_store", MFD_CLOEXEC);
        if (fd == -1)
        {
            LOG_ERROR << errno << ": Error creating buffer store memfd.";
            return -1;
        }

        this->fd = fd;
        return 0;
    }

    const buffer_view buffer_store::write_buf(const void *buf, const uint32_t size)
    {
        buffer_view view = {0, 0};
        int res = write(fd, buf, size);
        if (res < size)
        {
            LOG_ERROR << errno << ": Error writing to buffer store fd " << fd;
            return view;
        }
        else
        {
            view.offset = current_pos;
            view.size = size;
            current_pos += size;
            return view;
        }
    }

    int buffer_store::purge(const buffer_view buf)
    {
        if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, buf.offset, buf.size) == -1)
        {
            LOG_ERROR << errno << ": Error when purging buffer store fd " << fd;
            return -1;
        }
        return 0;
    }

    void buffer_store::deinit()
    {
        if (fd > 0)
            close(fd);
    }

} // namespace util