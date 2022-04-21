#include "messenger.hpp"
#include "color.hpp"
#include <log-console-defs>

#include <iostream>
#include <getopt.h>

#include <themispp/secure_message.hpp>

#define TOSTR(val) #val
#define TO_STR(val) TOSTR(val)
#define STDOUT_REDIRECTION_FILE VAR_DIRECTORY "/.stdout"
#define STDERR_REDIRECTION_FILE VAR_DIRECTORY "/.stderr"

static bool debug = false;
static char* appname = nullptr;
static bool is_server = true;

static int max_clients = 10;
static const char* mariadb_login = "ppmadmin";
static const char* mariadb_password = COLOR_CYAN "uIaBycFQyYRDOXbXo.JyM0" COLOR_RESET;
static const char* setup_mariadb_table = nullptr;

static inet::inet_address address = inet::inet_address(in_addr{INADDR_ANY}, DEFAULT_PORT);

static msg::HEADER::signal operation_signal = msg::HEADER::s_zero;
static char* login;
static char* password;
static char* metadata;
static int idatapipe = -1;
static int odatapipe = -1;

static constexpr const char* s_options = "m:a:o:l:p:M:I:O:c:dv?";
const option l_options[]{
		{"mode",        required_argument, nullptr, 'm'},
		
		{"address",     required_argument, nullptr, 'a'},
		
		{"operation",   required_argument, nullptr, 'o'},
		{"login",       required_argument, nullptr, 'l'},
		{"password",    required_argument, nullptr, 'p'},
		{"metadata",    required_argument, nullptr, 'M'},
		{"idatapipe",   required_argument, nullptr, 'I'},
		{"odatapipe",   required_argument, nullptr, 'O'},
		
		{"max-clients", required_argument, nullptr, 'c'},
		{"dblogin",     required_argument, nullptr, 2},
		{"dbpassword",  required_argument, nullptr, 3},
		
		{"setup-db",    required_argument, nullptr, 1},
		{"constant",       optional_argument, nullptr, 10},
		{"debug",       no_argument,       nullptr, 'd'},
		{"version",     no_argument,       nullptr, 'v'},
		{"help",        no_argument,       nullptr, '?'},
		{nullptr}
};

inline static void help(int code);

inline static void daemonize_application();

inline static void sighandle_close_port(int sig);

inline static void run_server();

template <typename T>
inline static void wr_pipe(const T& val)
{
	::write(odatapipe, &val, sizeof val);
}

template <typename T>
inline static void rd_pipe(T& val)
{
	::read(idatapipe, &val, sizeof val);
}

template <typename Container, typename T>
inline static void wr_pipe(const Container& cont)
{
	size_t size = cont.size();
	::write(odatapipe, &size, sizeof size);
	if (size > 0) ::write(odatapipe, cont.data(), size);
}

template <typename Container, typename T>
inline static void rd_pipe(Container& cont)
{
	size_t size = 0;
	::read(idatapipe, &size, sizeof size);
	if (size)
	{
		cont.resize(size, 0);
		::read(idatapipe, cont.data(), size);
	}
}

inline static void parse_args(int argc, char** argv);

int main(int argc, char** argv)
{
	appname = argv[0];
	if (argc <= 1) help(0);
	
	parse_args(argc, argv);
	
	if (::setup_mariadb_table)
	{
		int exit_code;
		{
			msg::server::mariadb_manager manager(::mariadb_login, ::mariadb_password, ::setup_mariadb_table);
			exit_code = manager.setup();
		}
		::exit(exit_code);
	}
	
	SSL_library_init();
	
	if (is_server)
	{
		if (!::debug) daemonize_application();
		run_server();
	}
	else
	{
		auto cli = *msg::client::create_client(::address);
		std::string status;
		switch (::operation_signal)
		{
			case msg::HEADER::s_register_user:
			{
				auto res = cli.register_user(::login, ::password, ::metadata, status);
				wr_pipe(res);
			}
				break;
			case msg::HEADER::s_set_password:
			{
				auto res = cli.set_password(::login, ::password, ::metadata, status);
				wr_pipe(res);
			}
				break;
			case msg::HEADER::s_set_display_name:
			{
				auto res = cli.set_display_name(::login, ::password, ::metadata, status);
				wr_pipe(res);
			}
				break;
			case msg::HEADER::s_get_display_name:
			{
				std::string result;
				auto res = cli.get_display_name(::login, ::password, result, status);
				wr_pipe(res);
				wr_pipe(result);
			}
				break;
			case msg::HEADER::s_begin_session:
			{
				themispp::secure_key_pair_generator_t<themispp::EC> keypair;
				auto res = cli.begin_session(::login, ::password, keypair.get_pub(), status);
				wr_pipe(res);
				if (res) wr_pipe(keypair.get_priv());
			}
				break;
			case msg::HEADER::s_end_session:
			{
				auto res = cli.end_session(::login, ::password, status);
				wr_pipe(res);
			}
				break;
			case msg::HEADER::s_send_message:
			{
				msg::MESSAGE msg;
				msg.destination = new std::string(::metadata);
				msg.destination_size = msg.destination->size();
				
				msg.data = new std::vector<uint8_t>();
				rd_pipe(*msg.data);
				
				std::vector<uint8_t> prikey;
				rd_pipe(prikey);
				
				std::vector<uint8_t> pubkey;
				auto res = cli.get_pubkey(::login, ::password, ::metadata, pubkey, status);
				
				std::cerr << "PubKey=\"";
				for (auto&& c: pubkey)
					std::cerr << c;
				std::cerr << "\"\n";
				
				auto message = themispp::secure_message_t(prikey, pubkey);
				*msg.data = message.encrypt(*msg.data);
				msg.data_size = msg.data->size();
				
				res = cli.send_message(::login, ::password, msg, status) && res;
				wr_pipe(res);
			}
				break;
			case msg::HEADER::s_query_incoming:
			{
				msg::MESSAGE msg;
				std::vector<uint8_t> prikey;
				rd_pipe(prikey);
				
				auto res = cli.query_incoming(::login, ::password, msg, status);
				
				std::vector<uint8_t> pubkey;
				res = cli.get_pubkey(::login, ::password, *msg.source, pubkey, status) && res;
				
				wr_pipe(res);
				
				auto message = themispp::secure_message_t(prikey, pubkey);
				*msg.data = message.decrypt(*msg.data);
				
				wr_pipe(*msg.source);
				wr_pipe(*msg.data);
			}
				break;
			case msg::HEADER::s_check_online_status:
			{
				bool online = false;
				auto res = cli.check_online_status(::login, ::password, ::metadata, online, status);
				wr_pipe(res);
				wr_pipe(online);
			}
				break;
			case msg::HEADER::s_find_users_by_display_name:
			{
				std::list<std::string> list;
				auto res = cli.find_users_by_display_name(::login, ::password, ::metadata, list, status);
				wr_pipe(res);
				wr_pipe(list.size());
				for (auto&& i: list)
					wr_pipe(i);
			}
				break;
			case msg::HEADER::s_find_users_by_login:
			{
				std::list<std::string> list;
				auto res = cli.find_users_by_login(::login, ::password, ::metadata, list, status);
				wr_pipe(res);
				wr_pipe(list.size());
				for (auto&& i: list)
					wr_pipe(i);
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


void help(int code)
{
	::printf(COLOR_RESET "Usage: " COLOR_MAGENTA "\"%s\"" COLOR_RESET " -m " COLOR_BLUE "<mode>" COLOR_RESET " [OPTIONS]\n" COLOR_YELLOW, appname);
	
	::printf("\nOptions:\n");
	::printf("m  --mode|-m         CLIENT/SERVER  client or server mode\n");
	
	::printf("\n For CLIENT mode\n");
	::printf("m  --address|-a      <IP>         server ip address\n");
	::printf("m  --operation|-o    <operation>  perform operation\n");
	::printf("m  --login|-l        <login>      login\n");
	::printf("m  --password|-p     <password>   password\n");
	::printf("o  --metadata|-M     <data>       undefined purpose data\n");
	::printf("o  --idatapipe|-I    <pipedes>    message data transfer pipe - input\n");
	::printf("o  --odatapipe|-O    <pipedes>    message data transfer pipe - output\n");
	
	::printf("\n For SERVER mode\n");
	::printf("o  --address|-a      <IP>        server ip address\n");
	::printf("o  --max-clients|-c  <amount>    maximum clients to process at once\n");
	::printf("o  --setup-db                    create table for users in mariadb database\n");
	::printf("o  --dblogin         <login>     database user login\n");
	::printf("o  --dbpassword      <password>  database user password\n");
	
	::printf("\n General\n");
	::printf("o  --constant    (<CONSTANT>)  print CONSTANT value or list available\n");
	::printf("o  --debug|-d                  enable debug mode\n");
	::printf("o  --version|-v                print application version\n");
	::printf("o  --help|-?                   print help\n");
	::printf(COLOR_CYAN "\nDesignation 'm' is for mandatory and 'o' - for optional.\n" COLOR_RESET "\n");
	
	::exit(code);
}


void daemonize_application()
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

void sighandle_close_port(int sig)
{
	::syslog(LOG_DEBUG, "Closing port %hu in iptables...", address.get_port());
	inet::close_port_in_iptables(address.get_port());
	::syslog(LOG_ERR, "SIG%s happened!\n  What: %s", ::sigabbrev_np(sig), ::sigdescr_np(sig));
	::exit(sig);
}

void run_server()
{
	::signal(SIGPIPE, sighandle_close_port);
	::signal(SIGTERM, sighandle_close_port);
	
	::syslog(LOG_DEBUG, "Opening port %hu in iptables...", address.get_port());
	inet::open_port_in_iptables(address.get_port());
	
	auto serv = msg::server::create_server(max_clients, address, mariadb_login, mariadb_password);
	
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

void parse_args(int argc, char** argv)
{
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
			
			case 'I':
			{
				::idatapipe = ::strtol(optarg, nullptr, 10);
				break;
			}
			
			case 'O':
			{
				::odatapipe = ::strtol(optarg, nullptr, 10);
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
			
			case 1:
			{
				::setup_mariadb_table = ::strdup(optarg);
				break;
			}
			
			case 2:
			{
				::mariadb_login = ::strdup(optarg);
				break;
			}
			
			case 3:
			{
				::mariadb_password = ::strdup(optarg);
				break;
			}
			
			case 10:
			{
				CONSTANT constant((optarg ? optarg : ""));
				constant.print_self(std::cout);
				::exit(0);
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
}
