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
#include "../util.hpp"
#include "../conf.hpp"
#include "../crypto.hpp"
#include "usr.hpp"

using namespace std;
using namespace util;
using namespace rapidjson;

namespace usr
{

/**
 * Global user list. (Exposed to other sub systems)
 */
map<string, contract_user> users;

/**
 * Json schema doc used for user challenge-response json validation.
 */
Document challenge_response_schemadoc;

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

    return 0;
}

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

int add_user(const string &pubkeyb64)
{
    if (users.count(pubkeyb64) == 1)
    {
        cerr << pubkeyb64 << " already exist. Cannot add user.\n";
        return -1;
    }

    //Establish the I/O pipes for [User <--> SC] channel.

    //inpipe: User will write input to this and contract will read user-input from this.
    int inpipe[2];
    if (pipe(inpipe) != 0)
    {
        cerr << "User in pipe creation failed. pubkey:" << pubkeyb64 << endl;
        return -1;
    }

    //outpipe: Contract will write output for the user to this and user will read from this.
    int outpipe[2];
    if (pipe(outpipe) != 0)
    {
        cerr << "User out pipe creation failed. pubkey:" << pubkeyb64 << endl;

        //We need to close 'inpipe' in case outpipe failed.
        close(inpipe[0]);
        close(inpipe[1]);

        return -1;
    }

    users.insert(pair<string, contract_user>(pubkeyb64, contract_user(pubkeyb64, inpipe, outpipe)));
    return 0;
}

int remove_user(const string &pubkeyb64)
{
    if (users.count(pubkeyb64) == 0)
    {
        cerr << pubkeyb64 << " does not exist. Cannot remove user.\n";
        return -1;
    }

    auto itr = users.find(pubkeyb64);
    contract_user user = itr->second;

    //Close the User <--> SC I/O pipes.
    close(user.inpipe[0]);
    close(user.inpipe[1]);
    close(user.outpipe[0]);
    close(user.outpipe[1]);

    users.erase(itr);
    return 0;
}

int read_contract_user_outputs()
{
    //Read any outputs that has been written by the contract process
    //from all the user outpipes and store in the outbuffer of each user.
    //User outbuffer will be read by the consensus process later when it wishes so.

    //Future optmization: Read and populate user buffers parallely.
    //Currently this is sequential for simplicity which will not scale well
    //when there are large number of users connected to the same HP node.

    for (auto &[pk, user] : users)
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

} // namespace usr