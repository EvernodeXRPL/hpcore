#include <cstdio>
#include <iostream>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <rapidjson/document.h>
#include <rapidjson/schema.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <sodium.h>
#include <boost/thread/thread.hpp>
#include "../sock/socket_server.hpp"
#include "../sock/socket_session_handler.hpp"
#include "../util.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "usr.hpp"
#include "user_session_handler.hpp"

using namespace std;
using namespace util;
using namespace rapidjson;

namespace usr
{

/**
 * Global user list. (Exposed to other sub systems)
 * Map key: User socket session id (<ip:port>)
 */
map<string, contract_user> users;

/**
 * Keep track of verification-pending challenges issued to newly connected users.
 * Map key: User socket session id (<ip:port>)
 */
map<string, string> pending_challenges;

/**
 * Json schema doc used for user challenge-response json validation.
 */
Document challenge_response_schemadoc;

/**
 * User session handler instance. This instance's methods will be fired for any user socket activity.
 */
user_session_handler global_usr_session_handler;

// The IO context used by the websocket listener.
net::io_context ioc;

// The thread the websocket lsitener is running on.
thread listener_thread;

/**
 * Initializes the usr subsystem. Must be called once during application startup.
 * @return 0 for successful initialization. -1 for failure.
 */
int init()
{
    //We initialize the response schema doc from this json string so we can
    //use the schema repeatedly for all challenge-response validations.

    const char *challenge_response_schema =
        "{"
        "\"type\": \"object\","
        "\"required\": [ \"type\", \"challenge\", \"sig\", \"pubkey\" ],"
        "\"properties\": {"
        "\"type\": { \"type\": \"string\" },"
        "\"challenge\": { \"type\": \"string\" },"
        "\"sig\": { \"type\": \"string\" },"
        "\"pubkey\": { \"type\": \"string\" }"
        "}"
        "}";
    challenge_response_schemadoc.Parse(challenge_response_schema);

    // Start listening for incoming user connections.
    start_listening();

    return 0;
}

/**
 * Constructs user challenge message json and the challenge string required for
 * initial user challenge handshake. This gets called when a user gets establishes
 * a web sockets connection to HP.
 * 
 * @param msg String reference to copy the generated json message string into.
 *            Message format:
 *            {
 *              "version": "<HP version>",
 *              "type": "public_challenge",
 *              "challenge": "<base64 challenge string>"
 *            }
 * @param challenge String reference to copy the generated base64 challenge string into.
 */
void create_user_challenge(string &msg, string &challengeb64)
{
    //Use libsodium to generate the random challenge bytes.
    unsigned char challenge_bytes[user_challenge_len];
    randombytes_buf(challenge_bytes, user_challenge_len);

    //We pass the b64 challenge string separately to the caller even though
    //we also include it in the challenge msg as well.

    base64_encode(challenge_bytes, user_challenge_len, challengeb64);

    //Construct the challenge msg json.
    Document d;
    d.SetObject();
    Document::AllocatorType &allocator = d.GetAllocator();
    d.AddMember("version", StringRef(util::hp_version), allocator);
    d.AddMember("type", StringRef(msg_public_challenge), allocator);
    d.AddMember("challenge", StringRef(challengeb64.data()), allocator);

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    d.Accept(writer);
    msg = buffer.GetString();
}

/**
 * Verifies the user challenge response with the original challenge issued to the user
 * and the user public contained in the response.
 * 
 * @param response The response bytes to verify. This will be parsed as json.
 *                 Accepted response format:
 *                 {
 *                   "type": "challenge_response",
 *                   "challenge": "<original base64 challenge the user received>",
 *                   "sig": "<Base64 signature of the challenge>",
 *                   "pubkey": "<Base64 public key of the user>"
 *                 }
 * @param original_challenge The original base64 challenge string issued to the user.
 * @return 0 if challenge response is verified. -1 if challenge not met or an error occurs.
 */
int verify_user_challenge_response(const string &response, const string &original_challenge, string &extracted_pubkeyb64)
{
    //We load response raw bytes into json document and validate the schema.
    Document d;
    d.Parse(response.data());

    //Validate json scheme.
    //This has a cost. But we have to do this first. Otherwise field value
    //extraction will fail in subsequent steps if the message is malformed.
    SchemaDocument schema(challenge_response_schemadoc);
    SchemaValidator validator(schema);
    if (!d.Accept(validator))
    {
        cerr << "User challenge resposne schema invalid.\n";
        return -1;
    }

    //Validate msg type.
    if (d["type"] != msg_challenge_resp)
    {
        cerr << "User challenge response type invalid. 'challenge_response' expeced.\n";
        return -1;
    }

    //Compare the response challenge string with the original issued challenge.
    if (d["challenge"] != original_challenge.data())
    {
        cerr << "User challenge resposne: challenge mismatch.\n";
        return -1;
    }

    //Verify the challenge signature. We do this last due to signature verification cost.
    string sigb64 = d["sig"].GetString();
    extracted_pubkeyb64 = d["pubkey"].GetString();
    if (crypto::verify_b64(original_challenge, sigb64, extracted_pubkeyb64) != 0)
    {
        cerr << "User challenge response signature verification failed.\n";
        return -1;
    }

    return 0;
}

/**
 * Adds the user denoted by specified session id and public key to the global authed user list.
 * This should get called after the challenge handshake is verified.
 * 
 * @param sessionid User socket session id.
 * @param pubkeyb64 User's base64 public key.
 * @return 0 on successful additions. -1 on failure.
 */
int add_user(const string &sessionid, const string &pubkeyb64)
{
    if (users.count(sessionid) == 1)
    {
        cerr << sessionid << " already exist. Cannot add user.\n";
        return -1;
    }

    //Establish the I/O pipes for [User <--> SC] channel.

    //inpipe: User will write input to this and contract will read user-input from this.
    int inpipe[2];
    if (pipe(inpipe) != 0)
    {
        cerr << "User in pipe creation failed. sessionid:" << sessionid << endl;
        return -1;
    }

    //outpipe: Contract will write output for the user to this and user will read from this.
    int outpipe[2];
    if (pipe(outpipe) != 0)
    {
        cerr << "User out pipe creation failed. sessionid:" << sessionid << endl;

        //We need to close 'inpipe' in case outpipe failed.
        close(inpipe[0]);
        close(inpipe[1]);

        return -1;
    }

    users.emplace(sessionid, contract_user(pubkeyb64, inpipe, outpipe));
    return 0;
}

/**
 * Removes the specified public key from the global user list.
 * This must get called when a user disconnects from HP.
 * 
 * @return 0 on successful removals. -1 on failure.
 */
int remove_user(const string &sessionid)
{
    auto itr = users.find(sessionid);

    if (itr == users.end())
    {
        cerr << sessionid << " does not exist. Cannot remove user.\n";
        return -1;
    }

    const contract_user &user = itr->second;

    //Close the User <--> SC I/O pipes.
    close(user.inpipe[0]);
    close(user.inpipe[1]);
    close(user.outpipe[0]);
    close(user.outpipe[1]);

    users.erase(itr);
    return 0;
}

/**
 * Read all per-user outputs produced by the contract process and store them in
 * the user buffer for later processing.
 * 
 * @return 0 on success. -1 on failure.
 */
int read_contract_user_outputs()
{
    //Read any outputs that has been written by the contract process
    //from all the user outpipes and store in the outbuffer of each user.
    //User outbuffer will be read by the consensus process later when it wishes so.

    //Future optmization: Read and populate user buffers parallely.
    //Currently this is sequential for simplicity which will not scale well
    //when there are large number of users connected to the same HP node.

    for (auto &[sid, user] : users)
    {
        int fdout = user.outpipe[0];
        int bytes_available = 0;
        ioctl(fdout, FIONREAD, &bytes_available);

        if (bytes_available > 0)
        {
            char data[bytes_available];
            read(fdout, data, bytes_available);

            //Populate the user output buffer with new data
            user.outbuffer = string(data, bytes_available);

            cout << "Read " + to_string(bytes_available) << " bytes into user output buffer. user:" + user.pubkeyb64 << endl;
        }
    }

    return 0;
}

/**
 * Starts listening for incoming user websocket connections.
 */
void start_listening()
{
    

    auto address = net::ip::make_address(conf::cfg.listenip);
    make_shared<sock::socket_server>(
        ioc,
        tcp::endpoint{address, conf::cfg.pubport},
        global_usr_session_handler)
        ->run();

    listener_thread = thread([&] { ioc.run(); });
}

} // namespace usr