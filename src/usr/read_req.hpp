#ifndef _HP_CONS_READ_REQ_
#define _HP_CONS_READ_REQ_

namespace read_req
{
    int init();

    void deinit();
    
    void read_request_processor();

    int execute_contract(std::unordered_map<std::string, std::list<std::string>> &read_requests);

} // namespace read_req

#endif