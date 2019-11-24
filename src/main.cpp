/**
    Entry point for HP Core
**/

#include "pchheader.hpp"
#include "util.hpp"
#include "conf.hpp"
#include "crypto.hpp"
#include "proc/proc.hpp"
#include "hplog.hpp"
#include "usr/usr.hpp"
#include "p2p/p2p.hpp"
#include "cons/cons.hpp"

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
                conf::set_contract_dir_paths(argv[2]);

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
    hplog::deinit();
}

void signal_handler(int signum)
{
    LOG_WARN << "Interrupt signal (" << signum << ") received.";
    deinit();
    exit(signum);
}

/**
 * Global exception handler for boost exceptions.
 */
void boost::throw_exception(std::exception const &e)
{
    LOG_ERR << "Boost error:" << e.what();
    exit(1);
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
            LOG_ERR << "std error: " << ex.what();
        }
        catch (...)
        {
            LOG_ERR << "std error: Terminated due to unknown exception";
        }
    }
    else
    {
        LOG_ERR << "std error: Terminated due to unknown reason";
    }

    exit(1);
}

int main(int argc, char **argv)
{
    //seed rand
    srand(time(0));   

    // Register exception handler for std exceptions.
    std::set_terminate(&std_terminate);

    // Extract the CLI args
    // This call will populate conf::ctx
    if (parse_cmd(argc, argv) != 0)
        return -1;

    if (conf::ctx.command == "version")
    {
        // Print the version
        std::cout << util::HP_VERSION << std::endl;
    }
    else
    {
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
                chdir(conf::ctx.contractdir.c_str());

                hplog::init();

                LOG_INFO << "Operating mode: "
                         << (conf::cfg.mode == conf::OPERATING_MODE::PASSIVE ? "Passive" : "Active");

                if (p2p::init() != 0 || usr::init() != 0 || cons::init() != 0)
                    return -1;

                // After initializing primary subsystems, register the SIGINT handler.
                signal(SIGINT, signal_handler);

                //we are waiting for peer to estasblish peer connections.
                //otherwise we'll run into not enough peers propsing/stage desync deadlock directly now.
                sleep(10);

                while (true)
                {
                    cons::consensus();
                }

                // Free resources.
                deinit();
            }
        }
    }

    std::cout << "exited normally\n";
    return 0;
}
