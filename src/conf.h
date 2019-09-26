#ifndef _HP_CONF_H_
#define _HP_CONF_H_

#include "lib/rapidjson/document.h"

using namespace std;
using namespace rapidjson;

namespace conf
{
int init();
void load(const char *filename, Document &d);
void save(const char *filename, Document &d);
} // namespace conf

#endif