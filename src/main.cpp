/**
    Entry point for HP Core
**/

#include "pchheader.hpp"
#include "util/version.hpp"
#include "util/util.hpp"
#include "conf.hpp"
#include "crypto.hpp"
#include "./sc/sc.hpp"
#include "hplog.hpp"
#include "usr/usr.hpp"
#include "usr/read_req.hpp"
#include "p2p/p2p.hpp"
#include "consensus.hpp"
#include "ledger/ledger.hpp"
#include "unl.hpp"
#include "killswitch/killswitch.h"

/**
 * Parses CLI args and extracts hot pocket command and parameters given.
 * HP command line accepts command and the contract directory(optional)
 */
int parse_cmd(int argc, char **argv)
{
    if (argc > 1) //We get working dir as an arg anyway. So we need to check for >1 args.
    {
        // We populate the global contract ctx with the detected command.
        conf::ctx.command = argv[1];

        // For run/new/rekey, contract directory argument must be specified.

        if (conf::ctx.command == "run" || conf::ctx.command == "new" || conf::ctx.command == "rekey")
        {
            if (argc != 3)
            {
                std::cerr << "Contract directory not specified.\n";
            }
            else
            {
                // We inform the conf subsystem to populate the contract directory context values
                // based on the directory argument from the command line.
                conf::set_contract_dir_paths(argv[0], argv[2]);

                return 0;
            }
        }
        else if (conf::ctx.command == "version")
        {
            if (argc == 2)
                return 0;
        }
    }

    // If all extractions fail display help message.

    std::cerr << "Arguments mismatch.\n";
    std::cout << "Usage:\n";
    std::cout << "hpcore version\n";
    std::cout << "hpcore <command> <contract dir> (command = run | new | rekey)\n";
    std::cout << "Example: hpcore run ~/mycontract\n";

    return -1;
}

/**
 * Performs any cleanup on graceful application termination.
 */
void deinit()
{
    usr::deinit();
    p2p::deinit();
    read_req::deinit();
    consensus::deinit();
    sc::deinit();
    ledger::deinit();
    conf::deinit();
}

void sig_exit_handler(int signum)
{
    LOG_WARNING << "Interrupt signal (" << signum << ") received.";
    deinit();
    LOG_WARNING << "hpcore exited due to signal.";
    exit(signum);
}

void segfault_handler(int signum)
{
    std::cerr << boost::stacktrace::stacktrace() << "\n";
    exit(SIGABRT);
}

/**
 * Global exception handler for std exceptions.
 */
void std_terminate() noexcept
{
    std::exception_ptr exptr = std::current_exception();
    if (exptr != 0)
    {
        try
        {
            std::rethrow_exception(exptr);
        }
        catch (std::exception &ex)
        {
            LOG_ERROR << "std error: " << ex.what();
        }
        catch (...)
        {
            LOG_ERROR << "std error: Terminated due to unknown exception";
        }
    }
    else
    {
        LOG_ERROR << "std error: Terminated due to unknown reason";
    }

    LOG_ERROR << boost::stacktrace::stacktrace();

    exit(1);
}

int main(int argc, char **argv)
{
    // Register exception and segfault handlers.
    std::set_terminate(&std_terminate);
    signal(SIGSEGV, &segfault_handler);
    signal(SIGABRT, &segfault_handler);

    // Become a sub-reaper so we can gracefully reap hpws child processes via hpws.hpp.
    // (Otherwise they will get reaped by OS init process and we'll end up with race conditions with gracefull kills)
    prctl(PR_SET_CHILD_SUBREAPER, 1);

    // seed rand
    srand(util::get_epoch_milliseconds());

    // Disable SIGPIPE to avoid crashing on broken pipe IO.
    {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &mask, NULL);
    }

    if (version::init() == -1)
        return -1;

    // Extract the CLI args
    // This call will populate conf::ctx
    if (parse_cmd(argc, argv) != 0)
        return -1;

    if (conf::ctx.command == "version")
    {
        // Print the version
        std::cout << "HotPocket " << version::HP_VERSION << " (ledger version " << version::LEDGER_VERSION << ")" << std::endl;
    }
    else
    {
        if (kill_switch(util::get_epoch_milliseconds()))
        {
            std::cerr << "Hot Pocket usage limit failure.\n";
            return -1;
        }

        // This block is about contract operations (new/rekey/run)
        // All the contract operations will be executed on the contract directory specified
        // in the command line args. 'parse_cmd()' above takes care of populating the contexual directory paths.

        // For any contract opreation to execute, we should init the crypto subsystem.
        if (crypto::init() != 0)
            return -1;

        if (conf::ctx.command == "new")
        {
            // This will create a new contract with all the required files.
            if (conf::create_contract() != 0)
                return -1;
        }
        else
        {
            if (conf::ctx.command == "rekey")
            {
                // This will generate new signing keys for the contract.
                if (conf::rekey() != 0)
                    return -1;
            }
            else if (conf::ctx.command == "run")
            {
                // In order to host the contract we should init some required sub systems.

                if (conf::init() != 0)
                    return -1;

                // Set HP process cwd to the contract directory. This will make both HP and contract process
                // both have the same cwd.
                chdir(conf::ctx.contract_dir.c_str());

                hplog::init();

                LOG_INFO << "Hot Pocket " << version::HP_VERSION;
                LOG_INFO << "Role: " << (conf::cfg.node.role == conf::ROLE::OBSERVER ? "Observer" : "Validator");
                LOG_INFO << "Public key: " << conf::cfg.node.public_key_hex;
                LOG_INFO << "Contract: " << conf::cfg.contract.id << " (" << conf::cfg.contract.version << ")";

                if (sc::init() == -1 ||
                    ledger::init() == -1 ||
                    unl::init() == -1 ||
                    consensus::init() == -1 ||
                    read_req::init() == -1 ||
                    p2p::init() == -1 ||
                    usr::init() == -1)
                {
                    deinit();
                    return -1;
                }

                // After initializing primary subsystems, register the exit handler.
                signal(SIGINT, &sig_exit_handler);
                signal(SIGTERM, &sig_exit_handler);

                // Wait until consensus thread finishes.
                consensus::wait();

                // deinit() here only gets called when there is an error in consensus.
                // If not deinit in the sigint handler is called when a SIGINT is received.
                deinit();
            }
        }
    }

    std::cout << "hpcore exited normally.\n";
    return 0;
}
