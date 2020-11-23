#include "../pchheader.hpp"
#include "buffer_store.hpp"

#define BLOCK_ALIGN(offset) ((off_t)ceil((double)offset / (double)BLOCK_SIZE)) * BLOCK_SIZE;

namespace util
{
    // memfd block size to have clean hole punch so that allocated blocks are released properly.
    constexpr size_t BLOCK_SIZE = 4096;

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
        int res = pwrite(fd, buf, size, next_write_pos);
        if (res < size)
        {
            LOG_ERROR << errno << ": Error writing to buffer store fd " << fd;
            return view;
        }
        else
        {
            view.offset = next_write_pos;
            view.size = size;

            // Get nearest block offset that occurs after the just-written buffer.
            next_write_pos += size;
            next_write_pos = BLOCK_ALIGN(next_write_pos);

            return view;
        }
    }

    int buffer_store::purge(const buffer_view &buf)
    {
        const size_t purge_size = BLOCK_ALIGN(buf.size);
        if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, buf.offset, purge_size) == -1)
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