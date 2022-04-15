//
// Created by imper on 2/14/22.
//

#ifndef PRIVACY_PROTECTION_MESSENGER_NETWORK_HPP
# define PRIVACY_PROTECTION_MESSENGER_NETWORK_HPP

# include <inet-comm>
# include <deque>
# include <sys/syslog.h>
# include <md5.h>
# include <sys/stat.h>
# include <memory>
# include <sys/wait.h>
# include <vector>
# include <mariadb/conncpp.hpp>

#define ERR_COLOR color::red

# ifndef MESSENGER_NAME
#  define MESSENGER_NAME "privacy-protection-messenger"
# endif

# ifndef CERTIFICATE_DIR
#  define CERTIFICATE_DIR "cert/"
# endif

# ifndef CERTIFICATE_PATH
#  define CERTIFICATE_PATH CERTIFICATE_DIR"certificate.pem"
# endif

# ifndef PRIVATE_KEY_PATH
#  define PRIVATE_KEY_PATH CERTIFICATE_DIR"key.pem"
# endif

# ifndef COUNTRY
#  define COUNTRY "UA"
# endif

# ifndef ORGANIZATION
#  define ORGANIZATION "imper"
# endif

# ifndef CERTIFICATE_NAME
#  define CERTIFICATE_NAME "imper"
# endif

# ifndef MAX_LOGIN
#  define MAX_LOGIN 63
# endif

# ifndef MAX_PASSWORD
#  define MAX_PASSWORD 127
# endif

# ifndef MAX_DISPLAY_NAME
#  define MAX_DISPLAY_NAME 127
# endif

# ifndef CONFIG_DIR
#  define CONFIG_DIR "/etc/" MESSENGER_NAME
# endif

# ifndef DEFAULT_USERS_FILE
#  define DEFAULT_USERS_FILE CONFIG_DIR "/users"
# endif

# ifndef DEFAULT_WORK_DIR
#  define DEFAULT_WORK_DIR "/tmp/" MESSENGER_NAME
# endif

# ifndef PASSWD_HASH_TYPE
#  define PASSWD_HASH_TYPE passwd_sha512
# endif

# ifndef DEFAULT_PORT
#  define DEFAULT_PORT 14882
# endif

# ifndef DEFAULT_SERVER_ADDRESS
#  define DEFAULT_SERVER_ADDRESS INADDR_ANY
# endif

# ifndef MAX_USER_ENTRIES_AMOUNT
#  define MAX_USER_ENTRIES_AMOUNT 100ul
# endif

# define E_DERANGED "Server is deranged. This is a bug report it!"
# define E_SUCCESS "Success."
# define E_USER_ALREADY_EXISTS "This user already exists."
# define E_INCORRECT_LOGIN "Incorrect login."
# define E_INCORRECT_PASSWORD "Incorrect password."
# define E_TOO_LONG_LOGIN "Too long login string."
# define E_TOO_LONG_PASSWORD "Too long password string."
# define E_TOO_SHORT_PASSWORD "Too short password."
# define E_TOO_LONG_DISPLAY_NAME "Too long display name."
# define E_USER_NOT_FOUND "User not found."
# define E_MESSAGE_NOT_FOUND "Message not found."
# define E_NO_PERMISSION "No permission."


# undef LOG
# undef ERR
# define LOG (inet::__detail__::_log_ << LOG_PREFIX)
# define ERR (inet::__detail__::_err_ << ERR_PREFIX)

namespace msg
{
	static const char* users_file = DEFAULT_USERS_FILE;
	static const char* work_dir = DEFAULT_WORK_DIR;
	static bool verbose = false;
	
	namespace __detail__ __attribute__((visibility("hidden")))
	{
		static const unsigned char cov_2char[64] = {
				/* from crypto/des/fcrypt.c */
				0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
				0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44,
				0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
				0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54,
				0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62,
				0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
				0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
				0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A
		};
		
		static const char ascii_dollar[] = {0x24, 0x00};
		
		typedef enum : int
		{
			passwd_unset = 0,
			passwd_md5,
			passwd_apr1,
			passwd_sha256,
			passwd_sha512,
			passwd_aixmd5
		} passwd_modes;
		
		inline static int random_bytes(char** data, size_t size);
		
		inline static char* md5crypt(const char* passwd, const char* magic, const char* salt);
		
		inline static char* shacrypt(const char* passwd, const char* magic, const char* salt);
		
		inline static bool contains(const char* str, const char* substr);
	}

#define SIGNAL_NAME(sig) #sig
	
	struct HEADER
	{
		enum signal : int
		{
			s_zero = 0,
			s_register_user,
			s_set_password,
			s_set_display_name,
			s_get_display_name,
			s_begin_session,
			s_end_session,
			s_get_pubkey,
			s_send_message,
			s_query_incoming,
			s_check_online_status,
			s_find_users_by_display_name,
			s_find_users_by_login
		};
		signal sig = s_zero;
		
		inline static const char* signal_to_name(signal sig)
		{
			if (sig == s_register_user)
				return SIGNAL_NAME(s_register_user);
			else if (sig == s_set_password)
				return SIGNAL_NAME(s_set_password);
			else if (sig == s_set_display_name)
				return SIGNAL_NAME(s_set_display_name);
			else if (sig == s_get_display_name)
				return SIGNAL_NAME(s_get_display_name);
			else if (sig == s_begin_session)
				return SIGNAL_NAME(s_begin_session);
			else if (sig == s_end_session)
				return SIGNAL_NAME(s_end_session);
			else if (sig == s_get_pubkey)
				return SIGNAL_NAME(s_get_pubkey);
			else if (sig == s_send_message)
				return SIGNAL_NAME(s_send_message);
			else if (sig == s_query_incoming)
				return SIGNAL_NAME(s_query_incoming);
			else if (sig == s_check_online_status)
				return SIGNAL_NAME(s_check_online_status);
			else if (sig == s_find_users_by_display_name)
				return SIGNAL_NAME(s_find_users_by_display_name);
			else if (sig == s_find_users_by_login)
				return SIGNAL_NAME(s_find_users_by_login);
			else return SIGNAL_NAME(s_zero);
		}
		
		inline static signal signal_from_name(const std::string& name)
		{
			if (name == SIGNAL_NAME(s_register_user))
				return s_register_user;
			else if (name == SIGNAL_NAME(s_set_password))
				return s_set_password;
			else if (name == SIGNAL_NAME(s_set_display_name))
				return s_set_display_name;
			else if (name == SIGNAL_NAME(s_get_display_name))
				return s_get_display_name;
			else if (name == SIGNAL_NAME(s_begin_session))
				return s_begin_session;
			else if (name == SIGNAL_NAME(s_end_session))
				return s_end_session;
			else if (name == SIGNAL_NAME(s_get_pubkey))
				return s_get_pubkey;
			else if (name == SIGNAL_NAME(s_send_message))
				return s_send_message;
			else if (name == SIGNAL_NAME(s_query_incoming))
				return s_query_incoming;
			else if (name == SIGNAL_NAME(s_check_online_status))
				return s_check_online_status;
			else if (name == SIGNAL_NAME(s_find_users_by_display_name))
				return s_find_users_by_display_name;
			else if (name == SIGNAL_NAME(s_find_users_by_login))
				return s_find_users_by_login;
			else return s_zero;
		}
		
		size_t login_size = 0;
		size_t password_size = 0;
		size_t display_name_size = 0;
		size_t data_size = 0;
		
		enum error : int
		{
			e_deranged = 0,
			e_success,
			e_user_already_exists,
			e_incorrect_login,
			e_incorrect_password,
			e_too_long_login,
			e_too_long_password,
			e_too_short_password,
			e_too_long_display_name,
			e_user_not_found,
			e_message_not_found,
			e_no_permission
		};
		error err = e_deranged;
	};
	
	struct MESSAGE
	{
		std::string* source = nullptr;
		std::string* destination = nullptr;
		std::vector<uint8_t>* data = nullptr;
		
		size_t source_size = 0;
		size_t destination_size = 0;
		size_t data_size = 0;
		
		MESSAGE() = default;
		
		MESSAGE(const MESSAGE& msg)
				: source(msg.source ? new std::remove_pointer_t<decltype(source)>(*msg.source) : nullptr),
				  destination(msg.destination ? new std::remove_pointer_t<decltype(destination)>(*msg.destination) : nullptr),
				  data(msg.data ? new std::remove_pointer_t<decltype(data)>(*msg.data) : nullptr),
				  source_size(msg.source->size()),
				  destination_size(msg.destination->size()),
				  data_size(msg.data->size())
		{ }
		
		~MESSAGE()
		{
			delete source;
			delete destination;
			delete data;
		}
	};
	
	class messenger_io : public inet::inet_io
	{
	public:
		explicit messenger_io(const inet::inet_io& io) : inet::inet_io(io)
		{ }
		
		inline bool read(HEADER& header)
		{
			return read(&header, sizeof header) == sizeof header;
		}
		
		inline bool read(MESSAGE& message)
		{
			if (read(&message, sizeof message) == sizeof message && message.data_size > 0)
			{
				if (message.source_size > 0)
				{
					message.source = new std::string(message.source_size, 0);
					if (read(message.source->data(), message.source_size) != message.source_size)
						return false;
				}
				if (message.destination_size)
				{
					message.destination = new std::string(message.destination_size, 0);
					if (read(message.destination->data(), message.destination_size) != message.destination_size)
						return false;
				}
				message.data = new std::vector<uint8_t>(message.data_size, 0);
				return read(message.data->data(), message.data_size) == message.data_size;
			}
			return false;
		}
		
		template <template <typename> typename Container, typename T>
		inline bool read(Container<T>& cont)
		{
			size_t size;
			if (read(&size, sizeof size) != sizeof size) return false;
			if (size > 0)
			{
				cont.resize(size, 0);
				return read(cont.data(), size) == size;
			}
			return true;
		}
		
		inline ssize_t read(void* data, size_t size) override
		{
			return inet_io::read(data, size);
		}
		
		inline bool write(const HEADER& header)
		{
			return write(&header, sizeof header) == sizeof header;
		}
		
		inline bool write(MESSAGE& message)
		{
			if (message.source) message.source_size = message.source->size();
			if (message.destination) message.destination_size = message.destination->size();
			if (message.data && !message.data->empty())
			{
				message.data_size = message.data->size();
				write(&message, sizeof message);
				if (message.source_size > 0) write(message.source->data(), message.source_size);
				if (message.destination_size > 0) write(message.destination->data(), message.destination_size);
				write(message.data->data(), message.data_size);
				return true;
			}
			return false;
		}
		
		template <template <typename> typename Container, typename T>
		inline void write(const Container<T>& cont)
		{
			size_t size = cont.size();
			write(&size, sizeof size);
			if (size > 0) write(cont.data(), size);
		}
		
		template <template <typename> typename Container, typename T>
		inline void write_raw(const Container<T>& cont)
		{
			if (cont.size() > 0) write(cont.data(), cont.size());
		}
		
		template <typename T>
		inline bool write(const T& obj)
		{
			return write(&obj, sizeof obj);
		}
		
		inline ssize_t write(const void* data, int size) override
		{
			return inet_io::write(data, size);
		}
	};

#define HANDLE_ERRORS    case HEADER::e_incorrect_login: \
                        {                                \
                            status = E_INCORRECT_LOGIN;  \
                            return false;                \
                        }                                \
                        case HEADER::e_incorrect_password: \
                        {                                \
                            status = E_INCORRECT_PASSWORD; \
                            return false;                \
                        }                                \
                        case HEADER::e_too_long_login:   \
                        {                                \
                            status = E_TOO_LONG_LOGIN;   \
                            return false;                \
                        }                                \
                        case HEADER::e_too_long_password:\
                        {                                \
                            status = E_TOO_LONG_PASSWORD;\
                            return false;                \
                        }                                \
                        case HEADER::e_too_short_password: \
                        {                                \
                            status = E_TOO_SHORT_PASSWORD; \
                            return false;                \
                        }                                \
                        case HEADER::e_too_long_display_name: \
                        {                                \
                            status = E_TOO_LONG_DISPLAY_NAME; \
                            return false;                \
                        }                                \
                        case HEADER::e_no_permission:    \
                        {                                \
                            status = E_NO_PERMISSION;    \
                            return false;                \
                        }                                \
                        case HEADER::e_user_already_exists:\
                        {                                \
                            status = E_USER_ALREADY_EXISTS;\
                            return false;                \
                        }                                \
                        case HEADER::e_user_not_found:   \
                        {                                \
                            status = E_USER_NOT_FOUND;   \
                            return false;                \
                        }                                \
                        case HEADER::e_message_not_found:\
                        {                                \
                            status = E_MESSAGE_NOT_FOUND;\
                            return false;                \
                        }                                \
                        default:                         \
                        {                                \
                            LOG << E_DERANGED "\n" << ENDENTLN;  \
                            status = E_DERANGED;            \
                            return false;                   \
                        }
	
	template <bool do_fork = true>
	inline static bool generate_certs()
	{
		bool generate_certs = true;
		pid_t pid;
		if constexpr(do_fork)
		{
			pid = ::fork();
			if (pid < 0)
			{
				generate_certs = false;
				ERROR("Fork failed.");
			}
			else if (pid > 0)
				generate_certs = false;
			else
				generate_certs = true;
		}
		
		if (generate_certs)
		{
			std::string error;
			
			auto key = inet::generate_key(error);
			if (!key)
			{
				LOG << LOG_COLOR << "An error occurred while generating key: " << error << ENDENTLN;
				return false;
			}
			
			auto x509 = inet::generate_x509(error, key, COUNTRY, ORGANIZATION, CERTIFICATE_NAME);
			if (!x509)
			{
				LOG << LOG_COLOR << "An error occurred while generating certificate: " << error << ENDENTLN;
				return false;
			}
			
			::system("mkdir -p \"" CERTIFICATE_DIR "\"");
			
			if (!inet::write_certificate_to_disk(error, key, x509, PRIVATE_KEY_PATH, CERTIFICATE_PATH))
			{
				LOG << LOG_COLOR << "An error occurred while writing certificate and key: " << error << ENDENTLN;
				return false;
			}
			
			if constexpr(do_fork) ::exit(EXIT_SUCCESS);
		}
		else if constexpr(do_fork)
		{
			int loc;
			::waitpid(pid, &loc, 0);
			if (WEXITSTATUS(loc))
			{
				return false;
			}
		}
		
		return true;
	}
	
	class client : public inet::client, private messenger_io
	{
	public:
		template <bool do_fork = true>
		inline static client* create_client(const inet::inet_address& server_address)
		{
			if (!generate_certs<do_fork>())
				return nullptr;
			
			return new client(server_address, CERTIFICATE_PATH, PRIVATE_KEY_PATH);
		}
		
		inline bool register_user(const std::string& login, const std::string& password, const std::string& display_name, std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_register_user, login.size(), password.size(), display_name.size()});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			messenger_io::write_raw(display_name);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						status = E_SUCCESS;
						return true;
					}
					HANDLE_ERRORS
				}
			}
			
			return false;
		}
		
		inline bool set_password(const std::string& login, const std::string& password, const std::string& new_password, std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_set_password, login.size(), password.size(), 0, new_password.size()});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			messenger_io::write_raw(new_password);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						status = E_SUCCESS;
						return true;
					}
					HANDLE_ERRORS
				}
			}
			
			return false;
		}
		
		inline bool set_display_name(const std::string& login, const std::string& password, const std::string& display_name, std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_set_display_name, login.size(), password.size(), display_name.size()});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			messenger_io::write_raw(display_name);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						status = E_SUCCESS;
						return true;
					}
					HANDLE_ERRORS
				}
			}
			return false;
		}
		
		inline bool get_display_name(const std::string& login, const std::string& password, std::string& display_name, std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_get_display_name, login.size(), password.size()});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						status = E_SUCCESS;
						messenger_io::read(display_name);
						return true;
					}
					HANDLE_ERRORS
				}
			}
			
			return false;
		}
		
		inline bool begin_session(const std::string& login, const std::string& password, const std::vector<uint8_t>& pubkey, std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_begin_session, login.size(), password.size()});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			messenger_io::write(pubkey);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						status = E_SUCCESS;
						return true;
					}
					HANDLE_ERRORS
				}
			}
			
			return false;
		}
		
		inline bool end_session(const std::string& login, const std::string& password, std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_end_session, login.size(), password.size()});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						status = E_SUCCESS;
						return true;
					}
					HANDLE_ERRORS
				}
			}
			return false;
		}
		
		inline bool get_pubkey(
				const std::string& login, const std::string& password, const std::string& target, std::vector<uint8_t>& pubkey, std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_get_pubkey, login.size(), password.size(), 0, target.size()});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			messenger_io::write_raw(target);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						messenger_io::read(pubkey);
						status = E_SUCCESS;
						return true;
					}
					HANDLE_ERRORS
				}
			}
			return false;
		}
		
		inline bool send_message(
				const std::string& login, const std::string& password, MESSAGE& message, std::string& status)
		{
			size_t message_size = sizeof message;
			message.source = nullptr;
			if (message.destination) message_size += message.destination->size();
			if (message.data) message_size += message.data->size();
			
			messenger_io::write(HEADER{HEADER::s_send_message, login.size(), password.size(), 0, message_size});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			messenger_io::write(message);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						status = E_SUCCESS;
						return true;
					}
					HANDLE_ERRORS
				}
			}
			return false;
		}
		
		inline bool query_incoming(
				const std::string& login, const std::string& password, MESSAGE& message, std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_query_incoming, login.size(), password.size()});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						status = E_SUCCESS;
						return messenger_io::read(message);
					}
					HANDLE_ERRORS
				}
			}
			return false;
		}
		
		inline bool check_online_status(
				const std::string& login, const std::string& password, const std::string& another_user, bool& online_status, std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_check_online_status, login.size(), password.size(), 0, another_user.size()});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			messenger_io::write_raw(another_user);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						messenger_io::read(&online_status, sizeof online_status);
						status = E_SUCCESS;
						return true;
					}
					HANDLE_ERRORS
				}
			}
			return false;
		}
		
		inline bool find_users_by_display_name(
				const std::string& login, const std::string& password, const std::string& display_name, std::list<std::string>& list,
				std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_find_users_by_display_name, login.size(), password.size(), display_name.size()});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			messenger_io::write_raw(display_name);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						status = E_SUCCESS;
						size_t amount = 0;
						if (messenger_io::read(&amount, sizeof amount) == amount)
						{
							amount = std::min(MAX_USER_ENTRIES_AMOUNT, amount);
							for (size_t i = 0; i < amount; ++i)
							{
								std::string entry;
								if (!messenger_io::read(entry)) return false;
								list.push_back(entry);
							}
							return true;
						}
						return false;
					}
					HANDLE_ERRORS
				}
			}
			return false;
		}
		
		inline bool find_users_by_login(
				const std::string& login, const std::string& password, const std::string& another_user, std::list<std::string>& list,
				std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_find_users_by_login, login.size(), password.size(), 0, another_user.size()});
			messenger_io::write_raw(login);
			messenger_io::write_raw(password);
			messenger_io::write_raw(another_user);
			HEADER res;
			if (messenger_io::read(res))
			{
				switch (res.err)
				{
					case HEADER::e_success:
					{
						status = E_SUCCESS;
						size_t amount = 0;
						if (messenger_io::read(&amount, sizeof amount))
						{
							amount = std::min(MAX_USER_ENTRIES_AMOUNT, amount);
							for (size_t i = 0; i < amount; ++i)
							{
								std::string entry;
								if (!messenger_io::read(entry)) return false;
								list.push_back(entry);
							}
							return true;
						}
						return false;
					}
					HANDLE_ERRORS
				}
			}
			return false;
		}
	
	private:
		inline explicit client(const inet::inet_address& server_address, const std::string& cert_file = "", const std::string& key_file = "")
				: messenger_io(inet::inet_io()), inet::client(server_address, true, cert_file, key_file)
		{
			this->messenger_io::ssl = this->inet::client::ssl;
			this->messenger_io::socket = this->inet::client::socket;
			this->messenger_io::success = this->inet::client::success;
		}
	};
	
	class MESSAGES
	{
	public:
		MESSAGES() = default;
		
		MESSAGES(const MESSAGES&) = delete;
		
		MESSAGES(MESSAGES&&) = delete;
		
		void put_message(const std::string& user, const MESSAGE& message)
		{
			incoming[user].push_back(message);
		}
		
		bool message_available(const std::string& user)
		{
			auto user_it = incoming.find(user);
			if (user_it != incoming.end())
			{
				return !user_it->second.empty();
			}
			return false;
		}
		
		MESSAGE invoke_message(const std::string& user)
		{
			auto res = incoming[user].front();
			incoming[user].pop_front();
			return res;
		}
	
	private:
		std::map<std::string, std::deque<MESSAGE>> incoming;
	};
	
	class server : private inet::server
	{
	public:
		template <bool do_fork = true>
		inline static server* create_server(int max_clients, const inet::inet_address& address)
		{
			if (!generate_certs<do_fork>())
				return nullptr;
			
			load_users();
			
			return new server(max_clients, address);
		}
		
		inline bool run()
		{
			return inet::server::run(true);
		}
	
	private:
		struct USER_DATA
		{
			std::string salt;
			std::string password;
			std::string display_name;
			bool is_session_running = false;
			std::vector<uint8_t> pubkey;
		};
		
		class mariadb_manager
		{
		public:
			inline mariadb_manager(const std::string& login, const std::string& password)
			{
				/// TODO: Connect to localhost mariadb using login and password
			}
			
			inline int setup(const std::string& table_name)
			{
				/// TODO: Create mariadb table with corresponding columns
				/// Must return application exit code
			}
			
			inline bool save_user(const std::string& login, const USER_DATA& userdata)
			{
				/// TODO: Save user into database or overwrite if exists
			}
			
			inline bool load_user(const std::string& login)
			{
				/// TODO: Get user from database by login and save into users map
			}
			
			inline bool unload_user(const std::string& login)
			{
				auto user = users.find(login);
				if (user != users.end())
				{
					users.erase(user);
					return true;
				}
				return false;
			}
			
			inline ~mariadb_manager()
			{
				/// TODO: Disconnect from mariadb
			}
		
		private:
			std::unique_ptr<sql::Connection> connection = nullptr;
		};
		
		
		static std::map<std::string, USER_DATA> users;
		static MESSAGES incoming;
		
		
		inline server(int max_clients, const inet::inet_address& address)
				: inet::server(max_clients, address, client_processing, this, CERTIFICATE_PATH, PRIVATE_KEY_PATH)
		{ }
		
		inline static bool process_request(messenger_io io, const inet::inet_address& address, server* serv)
		{
			HEADER header;
			io.read(header);
			
			HEADER response{header.sig};
			std::string login, password;
			if (read_credentials(io, header, response, login, password))
			{
				switch (header.sig)
				{
					case HEADER::s_zero:
						return false;
					case HEADER::s_register_user:
					{
						std::string display_name;
						if (read_display_name(io, header, response, display_name))
						{
							auto login_str = std::string(login);
							if (users.find(login_str) == users.end())
							{
								::syslog(LOG_DEBUG, "Registering user \"%s\"...", login.c_str());
								auto salt = std::string();
								compute_passwd_hash(password, salt);
								users[login_str] = {salt, password, display_name};
								save_users();
								response.err = HEADER::e_success;
							}
							else
							{
								::syslog(LOG_DEBUG, "User \"%s\" already exists.", login.c_str());
								response.err = HEADER::e_user_already_exists;
							}
						}
						return io.write(response);
					}
					case HEADER::s_set_password:
					{
						std::string data;
						if (read_data(io, header, data))
						{
							decltype(users.end()) user;
							if (check_credentials(response, login, password, user))
							{
								user->second.password = data;
								::syslog(LOG_DEBUG, "User \"%s\" changed password.", login.c_str());
								response.err = HEADER::e_success;
							}
						}
						return io.write(response);
					}
					case HEADER::s_set_display_name:
					{
						std::string data;
						if (read_data(io, header, data))
						{
							decltype(users.end()) user;
							if (check_credentials(response, login, password, user))
							{
								auto new_display_name = std::string(data);
								if (new_display_name.size() > MAX_DISPLAY_NAME)
									new_display_name.resize(MAX_DISPLAY_NAME);
								user->second.display_name = new_display_name;
								::syslog(LOG_DEBUG, R"(User "%s" changed display name to "%s".)", login.c_str(), new_display_name.c_str());
								response.err = HEADER::e_success;
							}
						}
						return io.write(response);
					}
					case HEADER::s_get_display_name:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, user))
						{
							io.write(response);
							response.err = HEADER::e_success;
							io.write(user->second.display_name);
							::syslog(LOG_DEBUG, "User \"%s\" queried display name.", login.c_str());
						}
						return true;
					}
					case HEADER::s_begin_session:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, user))
						{
							std::vector<uint8_t> pubkey;
							io.read(pubkey);
							user->second.pubkey = pubkey;
							user->second.is_session_running = true;
							::syslog(LOG_DEBUG, "User \"%s\" started session.", login.c_str());
							response.err = HEADER::e_success;
						}
						return io.write(response);
					}
					case HEADER::s_end_session:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, user))
						{
							user->second.is_session_running = false;
							::syslog(LOG_DEBUG, "User \"%s\" ended session.", login.c_str());
							response.err = HEADER::e_success;
						}
						return io.write(response);
					}
					case HEADER::s_get_pubkey:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, user))
						{
							std::string target;
							read_data(io, header, target);
							auto target_it = users.find(target);
							if (target_it != users.end())
							{
								response.err = HEADER::e_success;
								io.write(response);
								io.write(target_it->second.pubkey);
								return true;
							}
							response.err = HEADER::e_user_not_found;
						}
						return io.write(response);
					}
					case HEADER::s_send_message:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, user))
						{
							MESSAGE message;
							if (io.read(message))
							{
								if (user->second.is_session_running)
								{
									message.source = new std::string(user->first);
									message.source_size = user->first.size();
									if (users.contains(*message.destination))
									{
										incoming.put_message(*message.destination, message);
										response.err = HEADER::e_success;
									}
									else
										response.err = HEADER::e_user_not_found;
								}
							}
						}
						return io.write(response);
					}
					case HEADER::s_query_incoming:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, user))
						{
							if (user->second.is_session_running)
							{
								if (incoming.message_available(user->first))
								{
									response.data_size = sizeof(MESSAGE);
									response.err = HEADER::e_success;
									io.write(response);
									auto msg = incoming.invoke_message(user->first);
									io.write(msg);
									return true;
								}
								else
									response.err = HEADER::e_message_not_found;
							}
						}
						return io.write(response);
					}
					case HEADER::s_check_online_status:
					{
						decltype(users.end()) user;
						std::string target;
						if (read_data(io, header, target))
						{
							if (check_credentials(response, login, password, user))
							{
								auto target_user = users.find(target);
								if (target_user != users.end())
								{
									response.data_size = sizeof(bool);
									response.err = HEADER::e_success;
									io.write(response);
									io.write(target_user->second.is_session_running);
									return true;
								}
								else
									response.err = HEADER::e_user_not_found;
							}
						}
						return io.write(response);
					}
					case HEADER::s_find_users_by_display_name:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, user))
						{
							std::string key;
							if (read_data(io, header, key))
							{
								response.err = HEADER::e_success;
								io.write(response);
								
								std::list<std::string> matches;
								for (const auto& u: users)
								{
									if (matches.size() > MAX_USER_ENTRIES_AMOUNT) break;
									if (u.second.display_name.size() >= key.size() &&
										__detail__::contains(u.second.display_name.c_str(), key.c_str()))
										matches.push_back(u.first);
								}
								
								io.write(matches.size());
								for (auto& m: matches)
									io.write(m);
								
								return true;
							}
							else return false;
						}
						return true;
					}
					case HEADER::s_find_users_by_login:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, user))
						{
							std::string key;
							if (read_data(io, header, key))
							{
								response.err = HEADER::e_success;
								io.write(response);
								
								std::list<std::string> matches;
								for (const auto& u: users)
								{
									if (matches.size() > MAX_USER_ENTRIES_AMOUNT) break;
									if (u.first.size() >= key.size() &&
										__detail__::contains(u.first.c_str(), key.c_str()))
										matches.push_back(u.first);
								}
								
								io.write(matches.size());
								for (auto& m: matches)
									io.write(m);
								
								return true;
							}
							else return false;
						}
						return true;
					}
					default:
					{
						::syslog(LOG_DEBUG, "Received unknown signal = SIG(%d). Ignoring...", header.sig);
						return io.write(response);
					}
				}
			}
			io.write(response);
			return false;
		}
		
		inline static bool check_credentials(HEADER& response, const std::string& login, std::string& password, decltype(users.end())& user)
		{
			user = users.find(login);
			if (user != users.end())
			{
				compute_passwd_hash(password, user->second.salt);
				if (user->second.password == password)
					return true;
				else
					response.err = HEADER::e_incorrect_password;
			}
			else
				response.err = HEADER::e_incorrect_login;
			return false;
		}
		
		inline static bool assert_credentials(messenger_io& io, const HEADER& header, HEADER& response)
		{
			if (header.login_size > MAX_LOGIN)
			{
				::syslog(LOG_ERR, "HEADER::login_size = %zu which is too long.", header.login_size);
				response.err = HEADER::e_too_short_password;
				return true;
			}
			
			if (header.password_size > MAX_PASSWORD)
			{
				::syslog(LOG_ERR, "HEADER::password_size = %zu which is too long.", header.password_size);
				response.err = HEADER::e_too_long_password;
				return true;
			}
			
			if (header.password_size < 8)
			{
				::syslog(LOG_ERR, "HEADER::password_size = %zu which is too short.", header.password_size);
				response.err = HEADER::e_too_short_password;
				return true;
			}
			
			return false;
		}
		
		inline static bool compute_passwd_hash(std::string& password, std::string& salt)
		{
			char* arr_salt = (salt.empty() ? nullptr : salt.data());
			char* hash = nullptr;
			if (hash_passwd(&arr_salt, &hash, password.data(), __detail__::PASSWD_HASH_TYPE))
			{
				password.clear();
				password = hash;
				salt = arr_salt;
				return true;
			}
			else ::syslog(LOG_ERR, "Failed to compute password hash.");
			return false;
		}
		
		inline static bool read_credentials(messenger_io& io, const HEADER& header, HEADER& response, std::string& login, std::string& password)
		{
			if (assert_credentials(io, header, response))
				return false;
			
			login.resize(header.login_size, 0);
			if (header.login_size)
				io.read(login.data(), header.login_size);
			
			password.resize(header.password_size, 0);
			if (header.password_size)
				io.read(password.data(), header.password_size);
			
			return true;
		}
		
		inline static bool assert_display_name(messenger_io& io, const HEADER& header, HEADER& response)
		{
			if (header.display_name_size > MAX_DISPLAY_NAME)
			{
				::syslog(LOG_ERR, "HEADER::display_name_size = %zu which is too long.", header.display_name_size);
				response.err = HEADER::e_too_long_display_name;
				return true;
			}
			
			return false;
		}
		
		inline static bool read_display_name(messenger_io& io, const HEADER& header, HEADER& response, std::string& display_name)
		{
			if (assert_display_name(io, header, response))
				return false;
			
			display_name.resize(header.display_name_size, 0);
			if (header.display_name_size)
				io.read(display_name.data(), header.display_name_size);
			display_name[header.display_name_size] = 0;
			
			return true;
		}
		
		inline static bool read_data(messenger_io& io, const HEADER& header, std::string& data)
		{
			data.resize(header.data_size, 0);
			if (header.data_size)
				io.read(data.data(), header.data_size);
			data[header.data_size] = 0;
			
			return true;
		}
		
		inline static void load_users()
		{
			auto file = ::fopen(users_file, "rb");
			if (file)
			{
				while (!::feof(file))
				{
					auto* username = new char[MAX_LOGIN + 1]{ };
					auto* sha512password = new char[MAX_PASSWORD]{ };
					::fscanf(file, "%s : %s : \"", username, sha512password);
					std::string display_name;
					char c = 0;
					while (!::feof(file))
					{
						::fread(&c, sizeof c, 1, file);
						if (c == '\"') break;
						display_name += c;
					}
					::fscanf(file, "\n");
					users[username] = {sha512password, display_name};
					delete[] username;
					delete[] sha512password;
				}
				::fclose(file);
			}
		}
		
		inline static void save_users()
		{
			struct stat st;
			int res;
			if (!(res = ::stat(CONFIG_DIR, &st)) && st.st_mode != S_IFDIR) ::system("rm -f \"" CONFIG_DIR "\"");
			if (res < 0) ::system("mkdir -p \"" CONFIG_DIR "\"");
			auto file = ::fopen(users_file, "wb");
			if (file)
			{
				for (auto&& user: users)
				{
					::fprintf(file, "%s : %s : %s\n", user.first.c_str(), user.second.password.c_str(), user.second.display_name.c_str());
				}
				::fclose(file);
			}
		}
		
		inline static bool client_processing(inet::inet_io& io, const inet::inet_address& address, inet::server* serv)
		{
			auto* this_ptr = static_cast<server*>(serv->extra);
			return process_request(messenger_io(io), address, this_ptr);
		}
		
		inline static bool hash_passwd(char** salt_p, char** hash, char* passwd, __detail__::passwd_modes mode)
		{
			*hash = nullptr;
			
			if (salt_p == nullptr)
			{
				if (verbose) ::syslog(LOG_ERR, "Server projected incorrectly: salt_p == nullptr.");
				return false;
			}
			
			/* first make sure we have a salt */
			if (*salt_p == nullptr)
			{
				size_t saltlen = 0;
				size_t i;
				
				if (mode == __detail__::passwd_md5 || mode == __detail__::passwd_apr1 || mode == __detail__::passwd_aixmd5)
					saltlen = 8;
				
				if (mode == __detail__::passwd_sha256 || mode == __detail__::passwd_sha512)
					saltlen = 16;
				
				assert(saltlen != 0);
				
				if (__detail__::random_bytes(salt_p, saltlen) <= 0)
					return false;
				
				for (i = 0; i < saltlen; i++)
				{
					(*salt_p)[i] = __detail__::cov_2char[(*salt_p)[i] & 0x3f]; /* 6 bits */
				}
				(*salt_p)[i] = 0;
# ifdef CHARSET_EBCDIC
				/* The password encryption function will convert back to ASCII */
				ascii2ebcdic(*salt_p, *salt_p, saltlen);
# endif
			}
			
			assert(*salt_p != nullptr);
			if (strlen(passwd) > MAX_PASSWORD)
			{
				if (verbose) ::syslog(LOG_WARNING, "Truncating password to %d characters.", MAX_PASSWORD);
				passwd[MAX_PASSWORD] = 0;
			}
			
			/* now compute password hash */
			
			if (mode == __detail__::passwd_md5 || mode == __detail__::passwd_apr1)
			{
				if (verbose) ::syslog(LOG_DEBUG, "Computing MD5 hash...");
				*hash = __detail__::md5crypt(passwd, (mode == __detail__::passwd_md5 ? "1" : "apr1"), *salt_p);
			}
			
			if (mode == __detail__::passwd_aixmd5)
			{
				if (verbose) ::syslog(LOG_DEBUG, "Computing MD5 hash...");
				*hash = __detail__::md5crypt(passwd, "", *salt_p);
			}
			
			if (mode == __detail__::passwd_sha256 || mode == __detail__::passwd_sha512)
			{
				if (verbose) ::syslog(LOG_DEBUG, "Computing SHA hash...");
				*hash = __detail__::shacrypt(passwd, (mode == __detail__::passwd_sha256 ? "5" : "6"), *salt_p);
			}
			
			return hash != nullptr;
		}
	};
	
	std::map<std::string, server::USER_DATA> server::users;
	MESSAGES server::incoming;
	
	namespace __detail__ __attribute__((visibility("hidden")))
	{
		inline static int random_bytes(char** data, size_t size)
		{
			if (size)
			{
				*data = new char[size];
				::srandom(::time(nullptr));
				for (size_t i = 0; i < size; ++i)
				{
					(*data)[i] = ::random();
				}
				return size;
			}
			return -1;
		}


/*
 * MD5-based password algorithm (should probably be available as a library
 * function; then the static buffer would not be acceptable). For magic
 * string "1", this should be compatible to the MD5-based BSD password
 * algorithm. For 'magic' string "apr1", this is compatible to the MD5-based
 * Apache password algorithm. (Apparently, the Apache password algorithm is
 * identical except that the 'magic' string was changed -- the laziest
 * application of the NIH principle I've ever encountered.)
 */
		inline static char* md5crypt(const char* passwd, const char* magic, const char* salt)
		{
			/* "$apr1$..salt..$.......md5hash..........\0" */
			static char out_buf[6 + 9 + 24 + 2];
			unsigned char buf[MD5_DIGEST_LENGTH];
			char ascii_magic[5];         /* "apr1" plus '\0' */
			char ascii_salt[9];          /* Max 8 chars plus '\0' */
			char* ascii_passwd = nullptr;
			char* salt_out;
			int n;
			unsigned int i;
			EVP_MD_CTX* md = nullptr, * md2 = nullptr;
			size_t passwd_len, salt_len, magic_len;
			
			passwd_len = strlen(passwd);
			
			out_buf[0] = 0;
			magic_len = strlen(magic);
			OPENSSL_strlcpy(ascii_magic, magic, sizeof(ascii_magic));
#ifdef CHARSET_EBCDIC
			if ((magic[0] & 0x80) != 0)    /* High bit is 1 in EBCDIC alnums */
		ebcdic2ascii(ascii_magic, ascii_magic, magic_len);
#endif
			
			/* The salt gets truncated to 8 chars */
			OPENSSL_strlcpy(ascii_salt, salt, sizeof(ascii_salt));
			salt_len = strlen(ascii_salt);
#ifdef CHARSET_EBCDIC
			ebcdic2ascii(ascii_salt, ascii_salt, salt_len);
#endif

#ifdef CHARSET_EBCDIC
			ascii_passwd = OPENSSL_strdup(passwd);
	if (ascii_passwd == nullptr)
		return nullptr;
	ebcdic2ascii(ascii_passwd, ascii_passwd, passwd_len);
	passwd = ascii_passwd;
#endif
			
			if (magic_len > 0)
			{
				OPENSSL_strlcat(out_buf, ascii_dollar, sizeof(out_buf));
				
				if (magic_len > 4)    /* assert it's  "1" or "apr1" */
					goto err;
				
				OPENSSL_strlcat(out_buf, ascii_magic, sizeof(out_buf));
				OPENSSL_strlcat(out_buf, ascii_dollar, sizeof(out_buf));
			}
			
			OPENSSL_strlcat(out_buf, ascii_salt, sizeof(out_buf));
			
			if (strlen(out_buf) > 6 + 8) /* assert "$apr1$..salt.." */
				goto err;
			
			salt_out = out_buf;
			if (magic_len > 0)
				salt_out += 2 + magic_len;
			
			if (salt_len > 8)
				goto err;
			
			md = EVP_MD_CTX_new();
			if (md == nullptr
				|| !EVP_DigestInit_ex(md, EVP_md5(), nullptr)
				|| !EVP_DigestUpdate(md, passwd, passwd_len))
				goto err;
			
			if (magic_len > 0)
				if (!EVP_DigestUpdate(md, ascii_dollar, 1)
					|| !EVP_DigestUpdate(md, ascii_magic, magic_len)
					|| !EVP_DigestUpdate(md, ascii_dollar, 1))
					goto err;
			
			if (!EVP_DigestUpdate(md, ascii_salt, salt_len))
				goto err;
			
			md2 = EVP_MD_CTX_new();
			if (md2 == nullptr
				|| !EVP_DigestInit_ex(md2, EVP_md5(), nullptr)
				|| !EVP_DigestUpdate(md2, passwd, passwd_len)
				|| !EVP_DigestUpdate(md2, ascii_salt, salt_len)
				|| !EVP_DigestUpdate(md2, passwd, passwd_len)
				|| !EVP_DigestFinal_ex(md2, buf, nullptr))
				goto err;
			
			for (i = passwd_len; i > sizeof(buf); i -= sizeof(buf))
			{
				if (!EVP_DigestUpdate(md, buf, sizeof(buf)))
					goto err;
			}
			if (!EVP_DigestUpdate(md, buf, i))
				goto err;
			
			n = passwd_len;
			while (n)
			{
				if (!EVP_DigestUpdate(md, (n & 1) ? "\0" : passwd, 1))
					goto err;
				n >>= 1;
			}
			if (!EVP_DigestFinal_ex(md, buf, nullptr))
				goto err;
			
			for (i = 0; i < 1000; i++)
			{
				if (!EVP_DigestInit_ex(md2, EVP_md5(), nullptr))
					goto err;
				if (!EVP_DigestUpdate(
						md2,
						(i & 1) ? (const unsigned char*)passwd : buf,
						(i & 1) ? passwd_len : sizeof(buf)))
					goto err;
				if (i % 3)
				{
					if (!EVP_DigestUpdate(md2, ascii_salt, salt_len))
						goto err;
				}
				if (i % 7)
				{
					if (!EVP_DigestUpdate(md2, passwd, passwd_len))
						goto err;
				}
				if (!EVP_DigestUpdate(
						md2,
						(i & 1) ? buf : (const unsigned char*)passwd,
						(i & 1) ? sizeof(buf) : passwd_len
				))
					goto err;
				if (!EVP_DigestFinal_ex(md2, buf, nullptr))
					goto err;
			}
			EVP_MD_CTX_free(md2);
			EVP_MD_CTX_free(md);
			md2 = nullptr;
			md = nullptr;
			
			{
				/* transform buf into output string */
				unsigned char buf_perm[sizeof(buf)];
				int dest, source;
				char* output;
				
				/* silly output permutation */
				for (dest = 0, source = 0; dest < 14;
					 dest++, source = (source + 6) % 17)
					buf_perm[dest] = buf[source];
				buf_perm[14] = buf[5];
				buf_perm[15] = buf[11];
# ifndef PEDANTIC              /* Unfortunately, this generates a "no
                                 * effect" warning */
				assert(16 == sizeof(buf_perm));
# endif
				
				output = salt_out + salt_len;
				assert(output == out_buf + strlen(out_buf));
				
				*output++ = ascii_dollar[0];
				
				for (i = 0; i < 15; i += 3)
				{
					*output++ = cov_2char[buf_perm[i + 2] & 0x3f];
					*output++ = cov_2char[((buf_perm[i + 1] & 0xf) << 2) |
										  (buf_perm[i + 2] >> 6)];
					*output++ = cov_2char[((buf_perm[i] & 3) << 4) |
										  (buf_perm[i + 1] >> 4)];
					*output++ = cov_2char[buf_perm[i] >> 2];
				}
				assert(i == 15);
				*output++ = cov_2char[buf_perm[i] & 0x3f];
				*output++ = cov_2char[buf_perm[i] >> 6];
				*output = 0;
				assert(strlen(out_buf) < sizeof(out_buf));
#ifdef CHARSET_EBCDIC
				ascii2ebcdic(out_buf, out_buf, strlen(out_buf));
#endif
			}
			
			return out_buf;

err:
			OPENSSL_free(ascii_passwd);
			EVP_MD_CTX_free(md2);
			EVP_MD_CTX_free(md);
			return nullptr;
		}

/*
 * SHA based password algorithm, describe by Ulrich Drepper here:
 * https://www.akkadia.org/drepper/SHA-crypt.txt
 * (note that it's in the public domain)
 */
		inline static char* shacrypt(const char* passwd, const char* magic, const char* salt)
		{
			/* Prefix for optional rounds specification.  */
			static const char rounds_prefix[] = "rounds=";
			/* Maximum salt string length.  */
# define SALT_LEN_MAX 16
			/* Default number of rounds if not explicitly specified.  */
# define ROUNDS_DEFAULT 5000
			/* Minimum number of rounds.  */
# define ROUNDS_MIN 1000
			/* Maximum number of rounds.  */
# define ROUNDS_MAX 999999999
			
			/* "$6$rounds=<N>$......salt......$...shahash(up to 86 chars)...\0" */
			static char out_buf[3 + 17 + 17 + 86 + 1];
			unsigned char buf[SHA512_DIGEST_LENGTH];
			unsigned char temp_buf[SHA512_DIGEST_LENGTH];
			size_t buf_size = 0;
			char ascii_magic[2];
			char ascii_salt[17];          /* Max 16 chars plus '\0' */
			char* ascii_passwd = nullptr;
			size_t n;
			EVP_MD_CTX* md = nullptr, * md2 = nullptr;
			const EVP_MD* sha = nullptr;
			size_t passwd_len, salt_len, magic_len;
			unsigned int rounds = ROUNDS_DEFAULT;        /* Default */
			char rounds_custom = 0;
			char* p_bytes = nullptr;
			char* s_bytes = nullptr;
			char* cp = nullptr;
			
			passwd_len = strlen(passwd);
			magic_len = strlen(magic);
			
			/* assert it's "5" or "6" */
			if (magic_len != 1)
				return nullptr;
			
			switch (magic[0])
			{
				case '5':
					sha = EVP_sha256();
					buf_size = 32;
					break;
				case '6':
					sha = EVP_sha512();
					buf_size = 64;
					break;
				default:
					return nullptr;
			}
			
			if (strncmp(salt, rounds_prefix, sizeof(rounds_prefix) - 1) == 0)
			{
				const char* num = salt + sizeof(rounds_prefix) - 1;
				char* endp;
				unsigned long int srounds = strtoul(num, &endp, 10);
				if (*endp == '$')
				{
					salt = endp + 1;
					if (srounds > ROUNDS_MAX)
						rounds = ROUNDS_MAX;
					else if (srounds < ROUNDS_MIN)
						rounds = ROUNDS_MIN;
					else
						rounds = (unsigned int)srounds;
					rounds_custom = 1;
				}
				else
				{
					return nullptr;
				}
			}
			
			OPENSSL_strlcpy(ascii_magic, magic, sizeof(ascii_magic));
#ifdef CHARSET_EBCDIC
			if ((magic[0] & 0x80) != 0)    /* High bit is 1 in EBCDIC alnums */
		ebcdic2ascii(ascii_magic, ascii_magic, magic_len);
#endif
			
			/* The salt gets truncated to 16 chars */
			OPENSSL_strlcpy(ascii_salt, salt, sizeof(ascii_salt));
			salt_len = strlen(ascii_salt);
#ifdef CHARSET_EBCDIC
			ebcdic2ascii(ascii_salt, ascii_salt, salt_len);
#endif

#ifdef CHARSET_EBCDIC
			ascii_passwd = OPENSSL_strdup(passwd);
	if (ascii_passwd == nullptr)
		return nullptr;
	ebcdic2ascii(ascii_passwd, ascii_passwd, passwd_len);
	passwd = ascii_passwd;
#endif
			
			out_buf[0] = 0;
			OPENSSL_strlcat(out_buf, ascii_dollar, sizeof(out_buf));
			OPENSSL_strlcat(out_buf, ascii_magic, sizeof(out_buf));
			OPENSSL_strlcat(out_buf, ascii_dollar, sizeof(out_buf));
			if (rounds_custom)
			{
				char tmp_buf[80]; /* "rounds=999999999" */
				sprintf(tmp_buf, "rounds=%u", rounds);
#ifdef CHARSET_EBCDIC
				/* In case we're really on a ASCII based platform and just pretend */
		if (tmp_buf[0] != 0x72)  /* ASCII 'r' */
			ebcdic2ascii(tmp_buf, tmp_buf, strlen(tmp_buf));
#endif
				OPENSSL_strlcat(out_buf, tmp_buf, sizeof(out_buf));
				OPENSSL_strlcat(out_buf, ascii_dollar, sizeof(out_buf));
			}
			OPENSSL_strlcat(out_buf, ascii_salt, sizeof(out_buf));
			
			/* assert "$5$rounds=999999999$......salt......" */
			if (strlen(out_buf) > 3 + 17 * rounds_custom + salt_len)
				goto err;
			
			md = EVP_MD_CTX_new();
			if (md == nullptr
				|| !EVP_DigestInit_ex(md, sha, nullptr)
				|| !EVP_DigestUpdate(md, passwd, passwd_len)
				|| !EVP_DigestUpdate(md, ascii_salt, salt_len))
				goto err;
			
			md2 = EVP_MD_CTX_new();
			if (md2 == nullptr
				|| !EVP_DigestInit_ex(md2, sha, nullptr)
				|| !EVP_DigestUpdate(md2, passwd, passwd_len)
				|| !EVP_DigestUpdate(md2, ascii_salt, salt_len)
				|| !EVP_DigestUpdate(md2, passwd, passwd_len)
				|| !EVP_DigestFinal_ex(md2, buf, nullptr))
				goto err;
			
			for (n = passwd_len; n > buf_size; n -= buf_size)
			{
				if (!EVP_DigestUpdate(md, buf, buf_size))
					goto err;
			}
			if (!EVP_DigestUpdate(md, buf, n))
				goto err;
			
			n = passwd_len;
			while (n)
			{
				if (!EVP_DigestUpdate(
						md,
						(n & 1) ? buf : (const unsigned char*)passwd,
						(n & 1) ? buf_size : passwd_len
				))
					goto err;
				n >>= 1;
			}
			if (!EVP_DigestFinal_ex(md, buf, nullptr))
				goto err;
			
			/* P sequence */
			if (!EVP_DigestInit_ex(md2, sha, nullptr))
				goto err;
			
			for (n = passwd_len; n > 0; n--)
				if (!EVP_DigestUpdate(md2, passwd, passwd_len))
					goto err;
			
			if (!EVP_DigestFinal_ex(md2, temp_buf, nullptr))
				goto err;
			
			if ((p_bytes = static_cast<decltype(p_bytes)>(OPENSSL_zalloc(passwd_len))) == nullptr)
				goto err;
			for (cp = p_bytes, n = passwd_len; n > buf_size; n -= buf_size, cp += buf_size)
				memcpy(cp, temp_buf, buf_size);
			memcpy(cp, temp_buf, n);
			
			/* S sequence */
			if (!EVP_DigestInit_ex(md2, sha, nullptr))
				goto err;
			
			for (n = 16 + buf[0]; n > 0; n--)
				if (!EVP_DigestUpdate(md2, ascii_salt, salt_len))
					goto err;
			
			if (!EVP_DigestFinal_ex(md2, temp_buf, nullptr))
				goto err;
			
			if ((s_bytes = static_cast<decltype(s_bytes)>(OPENSSL_zalloc(salt_len))) == nullptr)
				goto err;
			for (cp = s_bytes, n = salt_len; n > buf_size; n -= buf_size, cp += buf_size)
				memcpy(cp, temp_buf, buf_size);
			memcpy(cp, temp_buf, n);
			
			for (n = 0; n < rounds; n++)
			{
				if (!EVP_DigestInit_ex(md2, sha, nullptr))
					goto err;
				if (!EVP_DigestUpdate(
						md2,
						(n & 1) ? (const unsigned char*)p_bytes : buf,
						(n & 1) ? passwd_len : buf_size
				))
					goto err;
				if (n % 3)
				{
					if (!EVP_DigestUpdate(md2, s_bytes, salt_len))
						goto err;
				}
				if (n % 7)
				{
					if (!EVP_DigestUpdate(md2, p_bytes, passwd_len))
						goto err;
				}
				if (!EVP_DigestUpdate(
						md2,
						(n & 1) ? buf : (const unsigned char*)p_bytes,
						(n & 1) ? buf_size : passwd_len
				))
					goto err;
				if (!EVP_DigestFinal_ex(md2, buf, nullptr))
					goto err;
			}
			EVP_MD_CTX_free(md2);
			EVP_MD_CTX_free(md);
			md2 = nullptr;
			md = nullptr;
			OPENSSL_free(p_bytes);
			OPENSSL_free(s_bytes);
			p_bytes = nullptr;
			s_bytes = nullptr;
			
			cp = out_buf + strlen(out_buf);
			*cp++ = ascii_dollar[0];

# define B_64_FROM_24_BIT(B2, B1, B0, N)                                  \
    do {                                                                \
        unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);             \
        int i = (N);                                                    \
        while (i-- > 0)                                                 \
            {                                                           \
                *cp++ = cov_2char[w & 0x3f];                            \
                w >>= 6;                                                \
            }                                                           \
    } while (0)
			
			switch (magic[0])
			{
				case '5':
					B_64_FROM_24_BIT (buf[0], buf[10], buf[20], 4);
					B_64_FROM_24_BIT (buf[21], buf[1], buf[11], 4);
					B_64_FROM_24_BIT (buf[12], buf[22], buf[2], 4);
					B_64_FROM_24_BIT (buf[3], buf[13], buf[23], 4);
					B_64_FROM_24_BIT (buf[24], buf[4], buf[14], 4);
					B_64_FROM_24_BIT (buf[15], buf[25], buf[5], 4);
					B_64_FROM_24_BIT (buf[6], buf[16], buf[26], 4);
					B_64_FROM_24_BIT (buf[27], buf[7], buf[17], 4);
					B_64_FROM_24_BIT (buf[18], buf[28], buf[8], 4);
					B_64_FROM_24_BIT (buf[9], buf[19], buf[29], 4);
					B_64_FROM_24_BIT (0, buf[31], buf[30], 3);
					break;
				case '6':
					B_64_FROM_24_BIT (buf[0], buf[21], buf[42], 4);
					B_64_FROM_24_BIT (buf[22], buf[43], buf[1], 4);
					B_64_FROM_24_BIT (buf[44], buf[2], buf[23], 4);
					B_64_FROM_24_BIT (buf[3], buf[24], buf[45], 4);
					B_64_FROM_24_BIT (buf[25], buf[46], buf[4], 4);
					B_64_FROM_24_BIT (buf[47], buf[5], buf[26], 4);
					B_64_FROM_24_BIT (buf[6], buf[27], buf[48], 4);
					B_64_FROM_24_BIT (buf[28], buf[49], buf[7], 4);
					B_64_FROM_24_BIT (buf[50], buf[8], buf[29], 4);
					B_64_FROM_24_BIT (buf[9], buf[30], buf[51], 4);
					B_64_FROM_24_BIT (buf[31], buf[52], buf[10], 4);
					B_64_FROM_24_BIT (buf[53], buf[11], buf[32], 4);
					B_64_FROM_24_BIT (buf[12], buf[33], buf[54], 4);
					B_64_FROM_24_BIT (buf[34], buf[55], buf[13], 4);
					B_64_FROM_24_BIT (buf[56], buf[14], buf[35], 4);
					B_64_FROM_24_BIT (buf[15], buf[36], buf[57], 4);
					B_64_FROM_24_BIT (buf[37], buf[58], buf[16], 4);
					B_64_FROM_24_BIT (buf[59], buf[17], buf[38], 4);
					B_64_FROM_24_BIT (buf[18], buf[39], buf[60], 4);
					B_64_FROM_24_BIT (buf[40], buf[61], buf[19], 4);
					B_64_FROM_24_BIT (buf[62], buf[20], buf[41], 4);
					B_64_FROM_24_BIT (0, 0, buf[63], 2);
					break;
				default:
					goto err;
			}
			*cp = '\0';
#ifdef CHARSET_EBCDIC
			ascii2ebcdic(out_buf, out_buf, strlen(out_buf));
#endif
			
			return out_buf;

err:
			EVP_MD_CTX_free(md2);
			EVP_MD_CTX_free(md);
			OPENSSL_free(p_bytes);
			OPENSSL_free(s_bytes);
			OPENSSL_free(ascii_passwd);
			return nullptr;
		}
		
		inline static bool contains(const char* str, const char* substr)
		{
			for (; *str && *substr; ++str)
			{
				if (*str == *substr)
					++substr;
			}
			return *substr == 0;
		}
	}
}

#endif //PRIVACY_PROTECTION_MESSENGER_NETWORK_HPP
