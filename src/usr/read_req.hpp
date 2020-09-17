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

    int populate_read_req_queue(const std::string &pubkey, const std::string &content);

    void initialize_execution_context(const user_read_req &read_request, const pthread_t thread_id, sc::execution_context &contract_ctx);

    void remove_thread(const pthread_t id);

} // namespace read_req

#endif