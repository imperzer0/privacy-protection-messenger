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

static int max_clients = 10;

static inet::inet_address address = inet::inet_address(in_addr{INADDR_ANY}, DEFAULT_PORT);

static msg::HEADER::signal operation_signal = msg::HEADER::s_zero;
static char* login;
static char* password;
static char* metadata;
static int datapipe = -1;

static constexpr const char* s_options = "m:a:o:l:p:M:P:c:dv?";
const option l_options[]{
		{"mode",        required_argument, nullptr, 'm'},
		
		{"address",     required_argument, nullptr, 'a'},
		
		{"operation",   required_argument, nullptr, 'o'},
		{"login",       required_argument, nullptr, 'l'},
		{"password",    required_argument, nullptr, 'p'},
		{"metadata",    required_argument, nullptr, 'M'},
		{"datapipe",    required_argument, nullptr, 'P'},
		
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
	
	::printf("\n For CLIENT mode\n");
	::printf("m  --address|-a      <IP>         server ip address\n");
	::printf("m  --operation|-o    <operation>  perform operation\n");
	::printf("m  --login|-l        <login>      login\n");
	::printf("m  --password|-p     <password>   password\n");
	::printf("o  --metadata|-M     <data>       undefined purpose data\n");
	::printf("o  --datapipe|-P     <pipedes>    message data transfer pipe\n");
	
	::printf("\n For SERVER mode\n");
	::printf("o  --address|-a      <IP>      server ip address\n");
	::printf("o  --max-clients|-c  <amount>  maximum clients to process at once\n");
	
	::printf("\n General\n");
	::printf("o  --debug|-D    enable debug mode\n");
	::printf("o  --version|-v  print application version\n");
	::printf("o  --help|-?     print help\n");
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

inline static void sighandle_close_port(int sig)
{
	::syslog(LOG_DEBUG, "Closing port %hu in iptables...", address.get_port());
	inet::close_port_in_iptables(address.get_port());
	::syslog(LOG_ERR, "SIG%s happened!\n  What: %s", ::sigabbrev_np(sig), ::sigdescr_np(sig));
	::exit(sig);
}

inline static void run_server()
{
	::signal(SIGPIPE, sighandle_close_port);
	::signal(SIGTERM, sighandle_close_port);
	
	::syslog(LOG_DEBUG, "Opening port %hu in iptables...", address.get_port());
	inet::open_port_in_iptables(address.get_port());
	
	auto serv = msg::server::create_server(max_clients, address);
	
	if (serv == nullptr)
	{
		::syslog(LOG_ERR, "Failed to create certificates.");
		::exit(-3);
	}
	
	::syslog(LOG_INFO, "Starting server on %s:%hu...", address.get_address(), address.get_port());
	if (!serv->run())
	{
		::syslog(LOG_ERR, "An error occurred in server loop on %s:%hu.", address.get_address(), address.get_port());
		::exit(-1);
	}
}

int main(int argc, char** argv)
{
	appname = argv[0];
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
			
			case 'a':
			{
				::address = inet::inet_address::from_ipv4(optarg, DEFAULT_PORT);
				break;
			}
			
			case 'l':
			{
				::login = ::strdup(optarg);
				break;
			}
			
			case 'p':
			{
				::password = ::strdup(optarg);
				break;
			}
			
			case 'M':
			{
				::metadata = ::strdup(optarg);
				break;
			}
			
			case 'P':
			{
				::datapipe = ::strtol(optarg, nullptr, 10);
				break;
			}
			
			case 'o':
			{
				::operation_signal = msg::HEADER::signal_from_name(optarg);
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
		msg::client cli(::address);
		std::string status;
		switch (::operation_signal)
		{
			case msg::HEADER::s_register_user:
				cli.register_user(::login, ::password, ::metadata, status);
				break;
			case msg::HEADER::s_set_password:
				cli.set_password(::login, ::password, ::metadata, status);
				break;
			case msg::HEADER::s_set_display_name:
				cli.set_display_name(::login, ::password, ::metadata, status);
				break;
			case msg::HEADER::s_get_display_name:
			{
				std::string result;
				cli.get_display_name(::login, ::password, result, status);
				std::cout << result << "\n";
			}
				break;
			case msg::HEADER::s_begin_session:
				cli.begin_session(::login, ::password, status);
				break;
			case msg::HEADER::s_end_session:
				cli.end_session(::login, ::password, status);
				break;
			case msg::HEADER::s_send_message:
			{
				msg::MESSAGE msg;
				msg.destination = std::make_unique<std::string>(::metadata);
				msg.destination_size = msg.destination->size();
				
				::read(::datapipe, &msg.data_size, sizeof msg.data_size);
				msg.data = std::make_unique<std::vector<char>>(msg.data_size, 0);
				if (msg.data_size > 0)::read(::datapipe, msg.data->data(), msg.data_size);
				
				cli.send_message(::login, ::password, msg, status);
			}
				break;
			case msg::HEADER::s_query_incoming:
			{
				msg::MESSAGE msg;
				cli.query_incoming(::login, ::password, msg, status);
				if (msg.source && !msg.source->empty())
					std::cout << msg.source->size() << " " << msg.source << "\n";
				else
					std::cout << "0\n";
				::write(::datapipe, &msg.data_size, sizeof msg.data_size);
				if (msg.data && !msg.data->empty()) ::write(::datapipe, msg.data->data(), sizeof msg.data_size);
			}
				break;
			case msg::HEADER::s_check_online_status:
			{
				bool online = false;
				cli.check_online_status(::login, ::password, ::metadata, online, status);
				std::cout << online << "\n";
			}
				break;
			case msg::HEADER::s_find_users_by_display_name:
			{
				std::list<std::string> list;
				cli.find_users_by_display_name(::login, ::password, ::metadata, list, status);
				std::cout << list.size() << "\n";
				for (auto&& i: list)
					std::cout << i << "\n";
			}
				break;
			case msg::HEADER::s_find_users_by_login:
			{
				std::list<std::string> list;
				cli.find_users_by_login(::login, ::password, ::metadata, list, status);
				std::cout << list.size() << "\n";
				for (auto&& i: list)
					std::cout << i << "\n";
			}
				break;
			default:
				std::clog << "Invalid operation!\n";
				::exit(-4);
		}
		std::clog << status << "\n";
	}
	
	return 0;
}
