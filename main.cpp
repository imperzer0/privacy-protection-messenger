#include "network.hpp"
#include "color.hpp"
#include <log-console-defs>

#include <iostream>
#include <getopt.h>

#define TOSTR(val) #val
#define TO_STR(val) TOSTR(val)
#define STDOUT_REDIRECTION_FILE VAR_DIRECTORY "/.stdout"
#define STDERR_REDIRECTION_FILE VAR_DIRECTORY "/.stderr"

static bool debug = false;
static char* appname = nullptr;
static char* server_address = "0.0.0.0:" TO_STR(DEFAULT_PORT);
static int max_clients = 10;
static constexpr const char* s_options = "m:l:p:a:c:dv";
const option l_options[]{
		{"mode",        required_argument, nullptr, 'm'},
		{"login",       required_argument, nullptr, 'l'},
		{"password",    required_argument, nullptr, 'p'},
		{"address",     required_argument, nullptr, 'a'},
		{"max-clients", required_argument, nullptr, 'c'},
		{"debug",       required_argument, nullptr, 'd'},
		{"version",     required_argument, nullptr, 'v'},
		{"help",        required_argument, nullptr, '?'},
		{nullptr}
};

inline static void help(int code)
{
	::printf(COLOR_RESET "Usage: " COLOR_MAGENTA "\"%s\"" COLOR_RESET " -m " COLOR_BLUE "<mode>" COLOR_RESET "\n" COLOR_YELLOW, appname);
	::printf("Options:\n");
	::printf("m  --mode|-m         CLIENT/SERVER  client or server mode\n");
	::printf(" For CLIENT mode\n");
	::printf("m  --address|-a      <IP>           server ip address\n");
	::printf("m  --login|-l        <login>        login\n");
	::printf("m  --password|-p     <password>     password\n");
	::printf(" For SERVER mode\n");
	::printf("o  --address|-a      <IP>           server ip address\n");
	::printf("o  --max-clients|-c  <amount>       maximum clients to process at once\n");
	::printf(" General\n");
	::printf("o  --debug|-d                       enable debug mode\n");
	::printf("o  --version|-v                     print application version\n");
	::printf("o  --help|-?                        print help\n");
	::printf(COLOR_CYAN "Designation 'm' for mandatory and 'o' for optional\n" COLOR_RESET "\n");
	
	::exit(code);
}

inline static void daemonize_application()
{
	/* Set new file permissions */
	::umask(0);
	
	/* Close all open file descriptors */
	for (int fd = ::sysconf(_SC_OPEN_MAX); fd > 0; --fd)
		::close(fd);
	
	/* Redirect stdout and stderr */
	stdout = ::fopen(STDOUT_REDIRECTION_FILE, "wb");
	stderr = ::fopen(STDERR_REDIRECTION_FILE, "wb");
	
	/* Open syslog */
	::openlog(appname, LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
}

inline static void run_server()
{
	auto address = inet::inet_address::from_ipv4(server_address, DEFAULT_PORT);
	auto serv = msg::server::create_server(max_clients, address);
	if (serv->run())
		::syslog(LOG_INFO, "Server is running on %s:%hu.", address.get_address(), address.get_port());
}

int main(int argc, char** argv)
{
	appname = argv[0];
	char* login, * password;
	bool is_server = true;
	
	int opt, longid;
	while ((opt = ::getopt_long(argc, argv, s_options, l_options, &longid)) >= 0)
	{
		switch (opt)
		{
			case 'm':
			{
				if (!::strcasecmp(optarg, "client"))
					is_server = false;
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
			
			case 'a':
			{
				::server_address = ::strdup(optarg);
				break;
			}
			
			case 'c':
			{
				::max_clients = ::strtol(optarg, nullptr, 10);
				break;
			}
			
			case 'd':
			{
				::debug = true;
				break;
			}
			
			case 'v':
			{
				::printf("Version: " COLOR_MAGENTA VERSION COLOR_RESET ".\nBinary file path: \"%s\".\n", appname);
				::exit(0);
			}
			
			case '?':
			{
				::help(0);
			}
			
			default:
			{
				::help(-2);
			}
		}
	}
	
	SSL_library_init();
	
	if (is_server)
	{
		if (!::debug) daemonize_application();
		run_server();
	}
	else
	{
	
	}
	
	return 0;
}
