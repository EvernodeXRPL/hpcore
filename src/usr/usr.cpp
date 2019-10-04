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
#include "../shared.h"
#include "../conf.h"
#include "../crypto.h"
#include "usr.h"

using namespace std;
using namespace shared;
using namespace rapidjson;

namespace usr
{

map<string, ContractUser> users;
Document challenge_response_schemadoc;

void create_user_challenge(string &msg, string &challenge)
{
    unsigned char challenge_bytes[USER_CHALLENGE_LEN];
    randombytes_buf(challenge_bytes, USER_CHALLENGE_LEN);

    base64_encode(challenge_bytes, USER_CHALLENGE_LEN, challenge);

    Document d;
    d.SetObject();
    Document::AllocatorType &allocator = d.GetAllocator();
    d.AddMember("version", StringRef(_HP_VERSION_), allocator);
    d.AddMember("type", "public_challenge", allocator);
    d.AddMember("challenge", StringRef(challenge.data()), allocator);

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    d.Accept(writer);
    msg = buffer.GetString();
}

bool verify_user_challenge_response(string &response, string &original_challenge, string &extracted_pubkeyb64)
{
    Document d;
    d.Parse(response.data());

    SchemaDocument schema(challenge_response_schemadoc);
    SchemaValidator validator(schema);
    if (!d.Accept(validator))
    {
        cerr << "User challenge resposne schema invalid.\n";
        return false;
    }

    string type = d["type"].GetString();
    if (type != "challenge_response")
    {
        cerr << "User challenge response type invalid. 'challenge_response' expeced.\n";
        return false;
    }

    string challenge = d["challenge"].GetString();
    string sigb64 = d["sig"].GetString();
    string pubkeyb64 = d["pubkey"].GetString();

    if (challenge != original_challenge)
    {
        cerr << "User challenge resposne: challenge mismatch.\n";
        return false;
    }

    if (!crypto::verify_b64(original_challenge, sigb64, pubkeyb64))
    {
        cerr << "User challenge response signature verification failed.\n";
        return false;
    }

    extracted_pubkeyb64 = pubkeyb64;
    return true;
}

void add_user(string &pubkeyb64)
{
    if (users.count(pubkeyb64) == 1)
    {
        cerr << pubkeyb64 << " already exist. Cannot add user.\n";
        return;
    }

    int inpipe[2];
    int outpipe[2];
    if (pipe(inpipe) != 0 || pipe(outpipe) != 0)
    {
        cerr << "User pipe creation failed. pubkey:" << pubkeyb64 << endl;
        return;
    }

    users.insert(pair<string, ContractUser>(pubkeyb64, ContractUser(pubkeyb64, inpipe, outpipe)));
}

void remove_user(string &pubkeyb64)
{
    if (users.count(pubkeyb64) == 0)
    {
        cerr << pubkeyb64 << " does not exist. Cannot remove user.\n";
        return;
    }

    auto itr = users.find(pubkeyb64);
    ContractUser user = itr->second;
    close(user.inpipe[0]);
    close(user.inpipe[1]);
    close(user.outpipe[0]);
    close(user.outpipe[1]);

    users.erase(itr);
}

//Read per-user outputs produced by the contract process.
int read_contract_user_outputs()
{
    for (auto &[pk, user] : users)
    {
        int fdout = user.outpipe[0];
        int bytes_available = 0;
        ioctl(fdout, FIONREAD, &bytes_available);

        if (bytes_available > 0)
        {
            unsigned char data[bytes_available];
            read(fdout, data, bytes_available);

            //Replace the existing user buffer with new buffer
            vector<unsigned char> buffer(data, data + bytes_available);
            user.outbuffer.swap(buffer);

            cout << "Read " + to_string(bytes_available) << " bytes into user output buffer. user:" + user.pubkeyb64 << endl;
        }
    }

    return 0;
}

int init()
{
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

} // namespace usr