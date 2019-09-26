#include <cstdio>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include "lib/rapidjson/document.h"
#include "lib/rapidjson/istreamwrapper.h"
#include "lib/rapidjson/ostreamwrapper.h"
#include "lib/rapidjson/writer.h"

using namespace std;
using namespace rapidjson;

namespace conf
{

static const char * configPath;

string get_full_path(const char *filename)
{
    string fullpath = configPath;
    fullpath += filename;
    return fullpath;
}

void load(const char *filename, Document &d)
{
    ifstream ifs(get_full_path(filename));
    IStreamWrapper isw(ifs);

    d.ParseStream(isw);
}

void save(const char *filename, Document &d)
{
    ofstream ofs(get_full_path(filename));
    OStreamWrapper osw(ofs);

    Writer<OStreamWrapper> writer(osw);
    d.Accept(writer);
}

string get_exec_path()
{
    char buf[PATH_MAX + 1];
    if (readlink("/proc/self/exe", buf, sizeof(buf) - 1) == -1)
        throw string("readlink() failed");
    string str(buf);
    return str.substr(0, str.rfind('/') + 1);
}

int init()
{
    string execPath = get_exec_path();
    char * confPathChar = (char *)malloc(execPath.size() + 1);
    strcpy(confPathChar, &execPath[0]);
    configPath = confPathChar;
    return 1;
}

} // namespace conf