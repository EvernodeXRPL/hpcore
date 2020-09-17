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

    void manage_thread_pool();

    void read_request_processor();

    int execute_contract(std::unordered_map<std::string, std::list<std::string>> &read_requests);

    int populate_read_req_queue(const std::string &pubkey, const std::string &content);

    bool initialize_execution_context(sc::execution_context &contract_ctx, const pthread_t thread_id);

    void remove_thread(const pthread_t id);

} // namespace read_req

#endif