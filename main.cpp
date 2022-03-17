#include "network.hpp"
#include "color.hpp"
#include <log-console-defs>

#include <iostream>
#include <getopt.h>

#define HELP COLOR_RESET "Usage: " COLOR_MAGENTA "\"%s\"" COLOR_RESET " -m " COLOR_BLUE "<mode>" COLOR_RESET "\n" COLOR_RESET COLOR_YELLOW \
             "Options:\n"                                                                                                                  \
             " --mode|-m        CLIENT/SERVER    client or server mode\n"                                                                  \
             " For CLIENT mode\n"                                                                                                          \
             "  --login|-l         <login>     login\n"                                                                                    \
             "  --password|-p      <password>  password\n"                                                                                 \
             " For SERVER mode\n"                                                                                                          \
             " For both\n"                                                                                                                 \
             " --version|-v                   print application version\n" COLOR_RESET "\n"

static const char* appname = nullptr;
static constexpr const char* s_options = "m:l:p:v";
const option l_options[]{
		{"mode",     required_argument, nullptr, 'm'},
		{"login",    required_argument, nullptr, 'l'},
		{"password", required_argument, nullptr, 'p'},
		{"version",  required_argument, nullptr, 'v'},
		{nullptr}
};

int main(int argc, char** argv)
{
	appname = argv[0];
	char* login, * password;
	
	int opt, longid;
	while ((opt = ::getopt_long(argc, argv, s_options, l_options, &longid)) >= 0)
	{
		switch (opt)
		{
			case 'm':
			{
				/// TODO: Method parsing
				break;
			}
			
			case 'l':
			{
				login = ::strdup(optarg);
				break;
			}
			
			case 'p':
			{
				password = ::strdup(optarg);
				break;
			}
			
			case 'v':
			{
				::printf("Version: " COLOR_MAGENTA VERSION COLOR_RESET ".\nBinary file path: \"%s\".\n", appname);
				::exit(0);
			}
			
			default: // '?'
			{
				::printf(HELP, appname);
				::exit(-2);
			}
		}
	}
	
	return 0;
}
