#ifndef _HP_CONS_READ_REQ_
#define _HP_CONS_READ_REQ_

#include "../sc.hpp"

namespace read_req
{
    struct user_read_req
    {
        std::string pubkey;
        std::string content;
    };

    int init();

    void deinit();

    void read_request_processor();

    int execute_contract(std::unordered_map<std::string, std::list<std::string>> &read_requests);

    int populate_read_req_queue(const std::string &pubkey, const std::string &content);

    int initialize_contract(sc::execution_context &contract_ctx);
} // namespace read_req

#endif