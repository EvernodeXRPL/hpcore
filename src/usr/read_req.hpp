#ifndef _HP_CONS_READ_REQ_
#define _HP_CONS_READ_REQ_

namespace read_req
{
    int init();

    void deinit();
    
    void read_request_processor();

} // namespace read_req

#endif