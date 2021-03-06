//
// Created by imper on 2/14/22.
//

#ifndef PRIVACY_PROTECTION_MESSENGER_MESSENGER_HPP
# define PRIVACY_PROTECTION_MESSENGER_MESSENGER_HPP

# include <inet-comm>
# include <deque>
# include <sys/syslog.h>
# include <md5.h>
# include <sys/stat.h>
# include <memory>
# include <sys/wait.h>
# include <utility>
# include <vector>
# include <mariadb/conncpp.hpp>
# include <lua5.3/lua.hpp>

# include "constants.hpp"

# define CONFIG_FILE CONFIG_DIR "/config.lua"
# define LUA_REGISTER_USER_FUNC "permit_register_user"
# define LUA_SET_PASSWORD_FUNC "permit_set_password"
# define LUA_SET_DISPLAY_NAME_FUNC "permit_set_display_name"
# define LUA_GET_DISPLAY_NAME_FUNC "permit_get_display_name"
# define LUA_BEGIN_SESSION_FUNC "permit_begin_session"
# define LUA_GET_PUBKEY_FUNC "permit_get_pubkey"
# define LUA_SEND_MESSAGE_FUNC "permit_send_message"
# define LUA_CHECK_ONLINE_STATUS_FUNC "permit_check_online_status"
# define LUA_FIND_USERS_BY_DISPLAY_NAME_FUNC "permit_find_users_by_display_name"
# define LUA_FIND_USERS_BY_LOGIN_FUNC "permit_find_users_by_login"

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

#define HANDLE_ERRORS_ON_CLIENT case HEADER::e_incorrect_login: \
                        {                                       \
                            status = E_INCORRECT_LOGIN;         \
                            return false;                       \
                        }                                       \
                        case HEADER::e_incorrect_password:      \
                        {                                       \
                            status = E_INCORRECT_PASSWORD;      \
                            return false;                       \
                        }                                       \
                        case HEADER::e_too_long_login:          \
                        {                                       \
                            status = E_TOO_LONG_LOGIN;          \
                            return false;                       \
                        }                                       \
                        case HEADER::e_too_long_password:       \
                        {                                       \
                            status = E_TOO_LONG_PASSWORD;       \
                            return false;                       \
                        }                                       \
                        case HEADER::e_too_short_password:      \
                        {                                       \
                            status = E_TOO_SHORT_PASSWORD;      \
                            return false;                       \
                        }                                       \
                        case HEADER::e_too_long_display_name:   \
                        {                                       \
                            status = E_TOO_LONG_DISPLAY_NAME;   \
                            return false;                       \
                        }                                       \
                        case HEADER::e_no_permission:           \
                        {                                       \
                            status = E_NO_PERMISSION;           \
                            return false;                       \
                        }                                       \
                        case HEADER::e_user_already_exists:     \
                        {                                       \
                            status = E_USER_ALREADY_EXISTS;     \
                            return false;                       \
                        }                                       \
                        case HEADER::e_user_not_found:          \
                        {                                       \
                            status = E_USER_NOT_FOUND;          \
                            return false;                       \
                        }                                       \
                        case HEADER::e_message_not_found:       \
                        {                                       \
                            status = E_MESSAGE_NOT_FOUND;       \
                            return false;                       \
                        }                                       \
                        default:                                \
                        {                                       \
                            LOG << E_DERANGED "\n" << ENDENTLN; \
                            status = E_DERANGED;                \
                            return false;                       \
                        }


# define SUCCESS 0

# undef LOG
# undef ERR
# define LOG (inet::__detail__::_log_ << PRINT_PREFIX)
# define ERR (inet::__detail__::_err_ << PRINT_PREFIX)

namespace msg
{
	static bool verbose = false;
	
	namespace __detail__ __attribute__((visibility("hidden")))
	{
		static const unsigned char cov_2_char[64] = {
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
			passwd_md_5,
			passwd_apr_1,
			passwd_sha_256,
			passwd_sha_512,
			passwd_aix_md_5
		} passwd_modes;
		
		inline static int random_bytes(char** data, int size);
		
		inline static char* md_5_crypt(const char* passwd, const char* magic, const char* salt);
		
		inline static char* sha_crypt(const char* passwd, const char* magic, const char* salt);
		
		inline static bool contains(const char* str, const char* substr);
	}
	
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
			switch (sig)
			{
				CASE_TO_STR(s_register_user)
				CASE_TO_STR(s_set_password)
				CASE_TO_STR(s_set_display_name)
				CASE_TO_STR(s_get_display_name)
				CASE_TO_STR(s_begin_session)
				CASE_TO_STR(s_end_session)
				CASE_TO_STR(s_get_pubkey)
				CASE_TO_STR(s_send_message)
				CASE_TO_STR(s_query_incoming)
				CASE_TO_STR(s_check_online_status)
				CASE_TO_STR(s_find_users_by_display_name)
				CASE_TO_STR(s_find_users_by_login)
				default:
					return _STR(s_zero);
			}
		}
		
		inline static signal signal_from_name(const std::string& name)
		{
			if (name == _STR(s_register_user))
				return s_register_user;
			else if (name == _STR(s_set_password))
				return s_set_password;
			else if (name == _STR(s_set_display_name))
				return s_set_display_name;
			else if (name == _STR(s_get_display_name))
				return s_get_display_name;
			else if (name == _STR(s_begin_session))
				return s_begin_session;
			else if (name == _STR(s_end_session))
				return s_end_session;
			else if (name == _STR(s_get_pubkey))
				return s_get_pubkey;
			else if (name == _STR(s_send_message))
				return s_send_message;
			else if (name == _STR(s_query_incoming))
				return s_query_incoming;
			else if (name == _STR(s_check_online_status))
				return s_check_online_status;
			else if (name == _STR(s_find_users_by_display_name))
				return s_find_users_by_display_name;
			else if (name == _STR(s_find_users_by_login))
				return s_find_users_by_login;
			else return s_zero;
		}
		
		size_t login_size = 0;
		size_t password_size = 0;
		size_t display_name_size = 0;
		size_t data_size = 0;
		
		enum error : int
		{
			e_no_permission = 0,
			e_success,
			e_user_already_exists,
			e_incorrect_login,
			e_incorrect_password,
			e_too_long_login,
			e_too_long_password,
			e_too_short_password,
			e_too_long_display_name,
			e_user_not_found,
			e_message_not_found
		};
		error err = e_no_permission;
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
	
	inline static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_cert()
	{
		std::string error;
		
		auto pkey = inet::generate_pkey(error);
		if (!pkey)
		{
			ERR << "An error occurred while generating public key: " << error << ENDENTLN;
			EVP_PKEY_free(pkey);
			return {{ },
					{ }};
		}
		
		auto cert = inet::generate_cert(error, pkey, COUNTRY, ORGANIZATION, CERTIFICATE_NAME);
		if (!cert)
		{
			ERR << "An error occurred while generating certificate: " << error << ENDENTLN;
			EVP_PKEY_free(pkey);
			X509_free(cert);
			return {{ },
					{ }};
		}
		
		return {inet::convert(cert), inet::convert(pkey)};
	}
	
	class client : public inet::client, private messenger_io
	{
	public:
		inline static client* create_client(const inet::inet_address& server_address)
		{
			auto certpair = generate_cert();
			if (certpair.first.empty() || certpair.second.empty())
				return nullptr;
			
			return new client(
					server_address,
					{inet::input_stream::mkstream(certpair.first), inet::input_stream::mkstream(certpair.second)}
			);
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
					HANDLE_ERRORS_ON_CLIENT
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
					HANDLE_ERRORS_ON_CLIENT
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
					HANDLE_ERRORS_ON_CLIENT
				}
			}
			return false;
		}
		
		inline bool get_display_name(
				const std::string& login, const std::string& password, const std::string& target, std::string& display_name, std::string& status)
		{
			messenger_io::write(HEADER{HEADER::s_get_display_name, login.size(), password.size(), 0, target.size()});
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
						status = E_SUCCESS;
						messenger_io::read(display_name);
						return true;
					}
					HANDLE_ERRORS_ON_CLIENT
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
					HANDLE_ERRORS_ON_CLIENT
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
					HANDLE_ERRORS_ON_CLIENT
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
					HANDLE_ERRORS_ON_CLIENT
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
					HANDLE_ERRORS_ON_CLIENT
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
					HANDLE_ERRORS_ON_CLIENT
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
					HANDLE_ERRORS_ON_CLIENT
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
					HANDLE_ERRORS_ON_CLIENT
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
					HANDLE_ERRORS_ON_CLIENT
				}
			}
			return false;
		}
	
	private:
		inline explicit client(const inet::inet_address& server_address, inet::loader&& crt)
				: messenger_io(inet::inet_io()), inet::client(server_address, std::move(crt))
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
		inline static server* create_server(
				int max_clients, const inet::inet_address& address, const std::string& db_login, const std::string& db_password)
		{
			auto certpair = generate_cert();
			if (certpair.first.empty() || certpair.second.empty())
				return nullptr;
			
			return new server(
					max_clients, address, db_login, db_password,
					{inet::input_stream::mkstream(certpair.first), inet::input_stream::mkstream(certpair.second)}
			);
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
		};
		
		struct USER_STATUS
		{
			bool is_session_running = false;
			std::vector<uint8_t> pubkey;
		};
	
	public:
		class mariadb_user_manager
		{
		public:
			inline mariadb_user_manager(const std::string& login, const std::string& password, std::string table_name)
					: table_name(std::move(table_name))
			{
				try
				{
					sql::Driver* driver = sql::mariadb::get_driver_instance();
					sql::SQLString url("jdbc:mariadb://localhost:3306/" DATABASE_NAME);
					sql::Properties properties(
							{{"user",     login},
							 {"password", password}}
					);
					connection = std::unique_ptr<sql::Connection>(driver->connect(url, properties));
					if (verbose) ::syslog(LOG_DEBUG, "Connected to " DATABASE_NAME " database.");
				}
				catch (sql::SQLException& e)
				{
					ERR << "Error in " _STR(mariadb_user_manager::mariadb_user_manager(login, password, table_name)) ": " << e.what() << ENDENTLN;
					::exit(e.getErrorCode());
				}
			}
			
			inline int32_t create()
			{
				try
				{
					std::unique_ptr<sql::PreparedStatement> statement(
							connection->prepareStatement(
									"create table " + table_name +
									" ( "
									"login varchar(" MACRO_STR(MAX_LOGIN) ") NOT NULL PRIMARY KEY,"
									"display_name varchar(" MACRO_STR(MAX_DISPLAY_NAME) ") NOT NULL,"
									"salt varchar(16) NOT NULL,"
									"password varchar(106) NOT NULL"
									" );"
							)
					);
					statement->executeQuery();
					if (verbose) ::syslog(LOG_DEBUG, "Table \"%s\" created.", table_name.c_str());
					return SUCCESS;
				}
				catch (sql::SQLException& e)
				{
					ERR << "Error in " _STR(mariadb_user_manager::create()) ": " << e.what() << ENDENTLN;
					return e.getErrorCode();
				}
			}
			
			inline int32_t save_user(const std::pair<std::string, USER_DATA>& userpair)
			{
				return save_user(userpair.first, userpair.second);
			}
			
			inline int32_t save_user(const std::string& login, const USER_DATA& userdata)
			{
				try
				{
					std::unique_ptr<sql::PreparedStatement> statement(
							connection->prepareStatement(
									"insert into " + table_name +
									" ( login, display_name, salt, password ) values( '" + login + "','" +
									userdata.display_name + "','"
									+ userdata.salt + "','" + userdata.password + "' );"
							)
					);
					statement->executeQuery();
					if (verbose) ::syslog(LOG_DEBUG, "User \"%s\" saved.", login.c_str());
					return SUCCESS;
				}
				catch (sql::SQLException& e)
				{
					ERR << "Error in " _STR(mariadb_user_manager::save_user(login, userdata)) ": " << e.what() << ENDENTLN;
					return e.getErrorCode();
				}
			}
			
			inline int32_t update_user(const std::pair<std::string, USER_DATA>& userpair)
			{
				return update_user(userpair.first, userpair.second);
			}
			
			inline int32_t update_user(const std::string& login, const USER_DATA& userdata)
			{
				try
				{
					std::unique_ptr<sql::PreparedStatement> statement(
							connection->prepareStatement(
									"update " + table_name + " set display_name='" + userdata.display_name + "', password='"
									+ userdata.password + "', salt='" + userdata.salt + "' where login='" + login + "';"
							)
					);
					statement->executeQuery();
					if (verbose) ::syslog(LOG_DEBUG, "User \"%s\" updated.", login.c_str());
					return SUCCESS;
				}
				catch (sql::SQLException& e)
				{
					ERR << "Error in " _STR(mariadb_user_manager::update_user(login, userdata)) ": " << e.what() << ENDENTLN;
					return e.getErrorCode();
				}
			}
			
			inline int32_t load_user(const std::string& login)
			{
				try
				{
					std::unique_ptr<sql::Statement> statement(connection->createStatement());
					std::unique_ptr<sql::ResultSet> res(
							statement->executeQuery("select * from " + table_name + " where login='" + login + "'")
					);
					res->next();
					
					std::string salt = res->getString(3).c_str();
					std::string password = res->getString(4).c_str();
					std::string display_name = res->getString(2).c_str();
					if (!salt.empty() || !password.empty() || !display_name.empty())
					{
						users.insert({login, USER_DATA{salt, password, display_name}});
						if (verbose) ::syslog(LOG_DEBUG, "User \"%s\" loaded.", login.c_str());
					}
					return SUCCESS;
				}
				catch (sql::SQLException& e)
				{
					ERR << "Error in " _STR(mariadb_user_manager::load_user(login)) ": " << e.what() << ENDENTLN;
					return e.getErrorCode();
				}
			}
			
			static inline bool unload_user(const std::string& login)
			{
				auto user = users.find(login);
				if (user != users.end())
				{
					users.erase(user);
					if (verbose) ::syslog(LOG_DEBUG, "User \"%s\" unloaded.", login.c_str());
					return true;
				}
				return false;
			}
			
			inline ~mariadb_user_manager()
			{
				try
				{
					connection->close();
					if (verbose) ::syslog(LOG_DEBUG, "Disconnected from " DATABASE_NAME " database.");
				}
				catch (sql::SQLException& e)
				{
					ERR << "Error in " _STR(mariadb_user_manager::mariadb_user_manager()) ": " << e.what() << ENDENTLN;
				}
			}
		
		private:
			std::unique_ptr<sql::Connection> connection = nullptr;
			std::string table_name;
		};
	
	private:
		static std::map<std::string, USER_STATUS> statuses;
		static std::map<std::string, USER_DATA> users;
		static MESSAGES incoming;
		static std::recursive_mutex mutex;
		std::unique_ptr<mariadb_user_manager> db_user_manager = nullptr;
		lua_State* lua = luaL_newstate();
		
		class scope_indicator
		{
		public:
			inline explicit scope_indicator(const std::string& scope) : scope(scope)
			{
				if (verbose)
				{
					mutex.lock();
					++spaces_cnt;
					std::string spaces;
					for (int i = 0; i < spaces_cnt; ++i) spaces += " ";
					::syslog(LOG_DEBUG, "%s{>>} Entered scope \"%s\"", spaces.c_str(), scope.c_str());
					mutex.unlock();
				}
			}
			
			inline ~scope_indicator()
			{
				if (verbose)
				{
					mutex.lock();
					std::string spaces;
					for (int i = 0; i < spaces_cnt; ++i) spaces += " ";
					::syslog(LOG_DEBUG, "%s{<<} Exited scope \"%s\"", spaces.c_str(), scope.c_str());
					--spaces_cnt;
					mutex.unlock();
				}
			}
		
		private:
			std::string scope;
			static int spaces_cnt;
			static std::mutex mutex;
		};
		
		template <typename Mutex>
		class mutex_auto_lock
		{
		public:
			inline explicit mutex_auto_lock(Mutex* mutex) : mutex(mutex)
			{ mutex->lock(); }
			
			inline ~mutex_auto_lock()
			{ mutex->unlock(); }
		
		private:
			Mutex* mutex;
		};
		
		
		inline server(
				int max_clients, const inet::inet_address& address,
				const std::string& db_login, const std::string& db_password, inet::loader&& crt)
				: inet::server(max_clients, address, client_processing, this, std::move(crt)),
				  db_user_manager(std::make_unique<mariadb_user_manager>(db_login, db_password, USERS_TABLE_NAME))
		{ }
		
		inline ~server()
		{ lua_close(lua); }
		
		inline static bool process_request(messenger_io io, const inet::inet_address& address, server* serv)
		{
			scope_indicator indicator(_STR(bool process_request(io, address, serv)));
			HEADER header;
			io.read(header);
			
			HEADER response{header.sig};
			std::string login, password;
			if (read_credentials(io, header, response, login, password))
			{
				if (verbose) ::syslog(LOG_DEBUG, "Processing signal \"%s\"...", HEADER::signal_to_name(header.sig));
				switch (header.sig)
				{
					case HEADER::s_zero:
						return false;
					case HEADER::s_register_user:
					{
						std::string display_name;
						if (read_display_name(io, header, response, display_name))
						{
							if (serv->db_user_manager->load_user(login) || users.find(login) == users.end())
							{
								auto salt = std::string();
								compute_passwd_hash(password, salt);
								if (serv->lua_request_permission(LUA_REGISTER_USER_FUNC, login.c_str(), password.c_str(), display_name.c_str()))
								{
									serv->db_user_manager->save_user(login, {salt, password, display_name});
									if (verbose) ::syslog(LOG_DEBUG, "Registered user \"%s\"", login.c_str());
									response.err = HEADER::e_success;
								}
								else if (verbose) ::syslog(LOG_DEBUG, "Lua refused.");
							}
							else
							{
								::syslog(LOG_DEBUG, "User \"%s\" already exists.", login.c_str());
								response.err = HEADER::e_user_already_exists;
							}
						}
						else if (verbose)
							::syslog(
									LOG_DEBUG, "Strange! Display name was not read. User \"%s\", IP = %s:%hu",
									login.c_str(), address.get_address(), address.get_port());
						return io.write(response);
					}
					case HEADER::s_set_password:
					{
						std::string data;
						if (read_data(io, header, data))
						{
							decltype(users.end()) user;
							if (check_credentials(response, login, password, serv, user))
							{
								auto salt = std::string();
								compute_passwd_hash(data, salt);
								if (serv->lua_request_permission(LUA_SET_PASSWORD_FUNC, user, "new_password", data.c_str()))
								{
									user->second.password = data;
									user->second.salt = salt;
									serv->db_user_manager->update_user(*user);
									::syslog(LOG_DEBUG, "User \"%s\" changed password.", login.c_str());
									response.err = HEADER::e_success;
								}
								else if (verbose) ::syslog(LOG_DEBUG, "Lua refused.");
							}
							else if (verbose) ::syslog(LOG_DEBUG, "Invalid credentials for user \"%s\".", login.c_str());
						}
						else if (verbose)
							::syslog(
									LOG_DEBUG, "Strange! Data was not read. User \"%s\", IP = %s:%hu",
									login.c_str(), address.get_address(), address.get_port());
						return io.write(response);
					}
					case HEADER::s_set_display_name:
					{
						std::string display_name;
						if (read_display_name(io, header, response, display_name))
						{
							decltype(users.end()) user;
							if (check_credentials(response, login, password, serv, user))
							{
								if (serv->lua_request_permission(LUA_SET_DISPLAY_NAME_FUNC, user, "new_display_name", display_name.c_str()))
								{
									if (display_name.size() > MAX_DISPLAY_NAME)
										display_name.resize(MAX_DISPLAY_NAME);
									user->second.display_name = display_name;
									serv->db_user_manager->update_user(*user);
									if (verbose)
										::syslog(LOG_DEBUG, R"(User "%s" changed display name to "%s".)", login.c_str(), display_name.c_str());
									response.err = HEADER::e_success;
								}
								else if (verbose) ::syslog(LOG_DEBUG, "Lua refused.");
							}
							else if (verbose) ::syslog(LOG_DEBUG, "Invalid credentials for user \"%s\".", login.c_str());
						}
						else if (verbose)
							::syslog(
									LOG_DEBUG, "Strange! Display name was not read. User \"%s\", IP = %s:%hu",
									login.c_str(), address.get_address(), address.get_port());
						return io.write(response);
					}
					case HEADER::s_get_display_name:
					{
						decltype(users.end()) user;
						std::string data;
						if (read_data(io, header, data))
						{
							if (check_credentials(response, login, password, serv, user))
							{
								if (serv->lua_request_permission(LUA_GET_DISPLAY_NAME_FUNC, user, data.c_str()))
								{
									io.write(response);
									response.err = HEADER::e_success;
									io.write(user->second.display_name);
									if (verbose) ::syslog(LOG_DEBUG, "User \"%s\" queried display name.", login.c_str());
								}
								else if (verbose) ::syslog(LOG_DEBUG, "Lua refused.");
							}
							else if (verbose) ::syslog(LOG_DEBUG, "Invalid credentials for user \"%s\".", login.c_str());
						}
						else if (verbose)
							::syslog(
									LOG_DEBUG, "Strange! Data was not read. User \"%s\", IP = %s:%hu",
									login.c_str(), address.get_address(), address.get_port());
						return true;
					}
					case HEADER::s_begin_session:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, serv, user))
						{
							if (serv->lua_request_permission(LUA_BEGIN_SESSION_FUNC, user))
							{
								std::vector<uint8_t> pubkey;
								io.read(pubkey);
								statuses[user->first].pubkey = pubkey;
								statuses[user->first].is_session_running = true;
								if (verbose) ::syslog(LOG_DEBUG, "User \"%s\" started session.", login.c_str());
								response.err = HEADER::e_success;
							}
							else if (verbose) ::syslog(LOG_DEBUG, "Lua refused.");
						}
						else if (verbose) ::syslog(LOG_DEBUG, "Invalid credentials for user \"%s\".", login.c_str());
						return io.write(response);
					}
					case HEADER::s_end_session:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, serv, user))
						{
							statuses[user->first].is_session_running = false;
							serv->db_user_manager->unload_user(user->first);
							if (verbose) ::syslog(LOG_DEBUG, "User \"%s\" ended session.", login.c_str());
							response.err = HEADER::e_success;
						}
						else if (verbose) ::syslog(LOG_DEBUG, "Invalid credentials for user \"%s\".", login.c_str());
						return io.write(response);
					}
					case HEADER::s_get_pubkey:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, serv, user))
						{
							std::string target;
							if (read_data(io, header, target))
							{
								auto target_it = statuses.find(target);
								if (target_it != statuses.end())
								{
									if (serv->lua_request_permission(LUA_GET_PUBKEY_FUNC, user, target.c_str()))
									{
										response.err = HEADER::e_success;
										io.write(response);
										io.write(target_it->second.pubkey);
										if (verbose) ::syslog(LOG_DEBUG, R"(Gave "%s"'s pubkey to "%s".)", target.c_str(), login.c_str());
										return true;
									}
									else if (verbose) ::syslog(LOG_DEBUG, "Lua refused.");
								}
								else
								{
									if (verbose) ::syslog(LOG_DEBUG, "No target user status loaded \"%s\".", target.c_str());
									response.err = HEADER::e_user_not_found;
								}
							}
							else if (verbose)
								::syslog(
										LOG_DEBUG, "Strange! Data was not read. User \"%s\", IP = %s:%hu",
										login.c_str(), address.get_address(), address.get_port());
						}
						else if (verbose) ::syslog(LOG_DEBUG, "Invalid credentials for user \"%s\".", login.c_str());
						return io.write(response);
					}
					case HEADER::s_send_message:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, serv, user))
						{
							MESSAGE message;
							if (io.read(message))
							{
								if (statuses[user->first].is_session_running)
								{
									message.source = new std::string(user->first);
									message.source_size = user->first.size();
									if (users.contains(*message.destination))
									{
										if (serv->lua_request_permission(LUA_SEND_MESSAGE_FUNC, user, message.destination->c_str()))
										{
											incoming.put_message(*message.destination, message);
											response.err = HEADER::e_success;
										}
										else if (verbose) ::syslog(LOG_DEBUG, "Lua refused.");
									}
									else
									{
										if (verbose) ::syslog(LOG_DEBUG, "No destination user \"%s\" status loaded.", message.destination->c_str());
										response.err = HEADER::e_user_not_found;
									}
								}
								else if (verbose) ::syslog(LOG_DEBUG, "Session ended for user \"%s\".", login.c_str());
							}
							else if (verbose)
								::syslog(
										LOG_DEBUG, "Strange! Message was not read. User \"%s\", IP = %s:%hu",
										login.c_str(), address.get_address(), address.get_port());
						}
						else if (verbose) ::syslog(LOG_DEBUG, "Invalid credentials for user \"%s\".", login.c_str());
						return io.write(response);
					}
					case HEADER::s_query_incoming:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, serv, user))
						{
							if (statuses[user->first].is_session_running)
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
								{
									if (verbose) ::syslog(LOG_DEBUG, "No incoming messages for \"%s\".", login.c_str());
									response.err = HEADER::e_message_not_found;
								}
							}
							else if (verbose) ::syslog(LOG_DEBUG, "Session ended for user \"%s\".", login.c_str());
						}
						else if (verbose) ::syslog(LOG_DEBUG, "Invalid credentials for user \"%s\".", login.c_str());
						return io.write(response);
					}
					case HEADER::s_check_online_status:
					{
						decltype(users.end()) user;
						std::string target;
						if (read_data(io, header, target))
						{
							if (check_credentials(response, login, password, serv, user))
							{
								auto target_user = statuses.find(target);
								if (target_user != statuses.end())
								{
									if (serv->lua_request_permission(LUA_CHECK_ONLINE_STATUS_FUNC, user, target.c_str()))
									{
										response.data_size = sizeof(bool);
										response.err = HEADER::e_success;
										io.write(response);
										io.write(target_user->second.is_session_running);
										return true;
									}
									else if (verbose) ::syslog(LOG_DEBUG, "Lua refused.");
								}
								else
								{
									if (verbose) ::syslog(LOG_DEBUG, "");
									response.err = HEADER::e_user_not_found;
								}
							}
							else if (verbose) ::syslog(LOG_DEBUG, "Invalid credentials for user \"%s\".", login.c_str());
						}
						else if (verbose)
							::syslog(
									LOG_DEBUG, "Strange! Data was not read. User \"%s\", IP = %s:%hu",
									login.c_str(), address.get_address(), address.get_port());
						return io.write(response);
					}
					case HEADER::s_find_users_by_display_name:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, serv, user))
						{
							std::string key;
							if (read_data(io, header, key))
							{
								if (serv->lua_request_permission(LUA_FIND_USERS_BY_DISPLAY_NAME_FUNC, user, key.c_str()))
								{
									response.err = HEADER::e_success;
									io.write(response);
									
									std::list<std::string> matches;
									for (const auto& u: users)
									{
										if (matches.size() >= MAX_USER_ENTRIES_AMOUNT) break;
										if (u.second.display_name.size() >= key.size() &&
											__detail__::contains(u.second.display_name.c_str(), key.c_str()))
											matches.push_back(u.first);
									}
									
									io.write(matches.size());
									for (auto& m: matches)
										io.write(m);
									
									return true;
								}
								else if (verbose) ::syslog(LOG_DEBUG, "Lua refused.");
							}
							else if (verbose)
								::syslog(
										LOG_DEBUG, "Strange! Data was not read. User \"%s\", IP = %s:%hu",
										login.c_str(), address.get_address(), address.get_port());
							else return false;
						}
						else if (verbose) ::syslog(LOG_DEBUG, "Invalid credentials for user \"%s\".", login.c_str());
						return true;
					}
					case HEADER::s_find_users_by_login:
					{
						decltype(users.end()) user;
						if (check_credentials(response, login, password, serv, user))
						{
							std::string key;
							if (read_data(io, header, key))
							{
								if (serv->lua_request_permission(LUA_FIND_USERS_BY_LOGIN_FUNC, user, key.c_str()))
								{
									response.err = HEADER::e_success;
									io.write(response);
									
									std::list<std::string> matches;
									for (const auto& u: statuses)
									{
										if (matches.size() >= MAX_USER_ENTRIES_AMOUNT) break;
										if (u.first.size() >= key.size() &&
											__detail__::contains(u.first.c_str(), key.c_str()))
											matches.push_back(u.first);
									}
									
									io.write(matches.size());
									for (auto& m: matches)
										io.write(m);
								}
								else if (verbose) ::syslog(LOG_DEBUG, "Lua refused.");
								return true;
							}
							else if (verbose)
								::syslog(
										LOG_DEBUG, "Strange! Data was not read. User \"%s\", IP = %s:%hu",
										login.c_str(), address.get_address(), address.get_port());
						}
						else if (verbose) ::syslog(LOG_DEBUG, "Invalid credentials for user \"%s\".", login.c_str());
						return false;
					}
					default:
					{
						::syslog(
								LOG_WARNING, "Received unknown signal = SIG(%d). IP = %s:%hu. Ignoring...",
								header.sig, address.get_address(), address.get_port());
						return io.write(response);
					}
				}
			}
			io.write(response);
			return false;
		}
		
		
		class lua_scope_stack_cleaner
		{
		public:
			inline explicit lua_scope_stack_cleaner(lua_State* lua) : lua(lua)
			{ }
			
			inline ~lua_scope_stack_cleaner()
			{ lua_settop(lua, 0); }
		
		private:
			lua_State* lua;
		};
		
		
		/// Analyze \b r lua call result
		inline static bool check_lua(lua_State* lua, int r)
		{
			if (r != LUA_OK)
			{
				if (verbose) ::syslog(LOG_ERR, "[Lua] reported an error: %s", lua_tostring(lua, -1));
				return false;
			}
			return true;
		}
		
		/// Call lua function from config
		inline bool lua_request_permission(
				const char* function_name, const char* login, const char* password, const char* display_name)
		{
			lua_scope_stack_cleaner cleaner(lua);
			
			if (check_lua(lua, luaL_dofile(lua, CONFIG_FILE)))
			{
				luaL_openlibs(lua);
				lua_getglobal(lua, function_name);
				if (lua_isfunction(lua, -1))
				{
					lua_createtable(lua, 0, 3);
					
					lua_pushstring(lua, login);
					lua_setfield(lua, -2, "login");
					
					lua_pushstring(lua, password);
					lua_setfield(lua, -2, "password");
					
					lua_pushstring(lua, display_name);
					lua_setfield(lua, -2, "display_name");
					if (check_lua(lua, lua_pcall(lua, 1, 1, 0)))
					{
						if (lua_toboolean(lua, -1)) return true;
						else if (verbose) ::syslog(LOG_DEBUG, "[Lua] function %s returned false", function_name);
					}
					else if (verbose) ::syslog(LOG_DEBUG, "[Lua] Unable to call function %s", function_name);
				}
				else if (verbose) ::syslog(LOG_DEBUG, "[Lua] %s is not a function", function_name);
			}
			else if (verbose) ::syslog(LOG_DEBUG, "[Lua] Failed doing file \"" CONFIG_FILE "\"");
			return false;
		}
		
		/// Call lua function from config
		inline bool lua_request_permission(
				const char* function_name, decltype(users.end()) user, const char* dataname, const char* data)
		{
			lua_scope_stack_cleaner cleaner(lua);
			
			if (check_lua(lua, luaL_dofile(lua, CONFIG_FILE)))
			{
				luaL_openlibs(lua);
				lua_getglobal(lua, LUA_SET_PASSWORD_FUNC);
				if (lua_isfunction(lua, -1))
				{
					lua_createtable(lua, 0, 4);
					
					lua_pushstring(lua, user->first.c_str());
					lua_setfield(lua, -2, "login");
					
					lua_pushstring(lua, user->second.password.c_str());
					lua_setfield(lua, -2, "password");
					
					lua_pushstring(lua, user->second.display_name.c_str());
					lua_setfield(lua, -2, "display_name");
					
					lua_pushstring(lua, data);
					lua_setfield(lua, -2, dataname);
					
					if (check_lua(lua, lua_pcall(lua, 1, 1, 0)))
					{
						if (lua_toboolean(lua, -1)) return true;
						else if (verbose) ::syslog(LOG_DEBUG, "[Lua] function %s returned false", function_name);
					}
					else if (verbose) ::syslog(LOG_DEBUG, "[Lua] Unable to call function %s", function_name);
				}
				else if (verbose) ::syslog(LOG_DEBUG, "[Lua] %s is not a function", function_name);
			}
			else if (verbose) ::syslog(LOG_DEBUG, "[Lua] Failed doing file \"" CONFIG_FILE "\"");
			return false;
		}
		
		/// Call lua function from config
		inline bool lua_request_permission(const char* function_name, decltype(users.end()) user, const char* arg)
		{
			lua_scope_stack_cleaner cleaner(lua);
			
			if (check_lua(lua, luaL_dofile(lua, CONFIG_FILE)))
			{
				luaL_openlibs(lua);
				lua_getglobal(lua, LUA_SET_PASSWORD_FUNC);
				if (lua_isfunction(lua, -1))
				{
					lua_createtable(lua, 0, 3);
					
					lua_pushstring(lua, user->first.c_str());
					lua_setfield(lua, -2, "login");
					
					lua_pushstring(lua, user->second.password.c_str());
					lua_setfield(lua, -2, "password");
					
					lua_pushstring(lua, user->second.display_name.c_str());
					lua_setfield(lua, -2, "display_name");
					
					
					lua_pushstring(lua, arg);
					
					
					if (check_lua(lua, lua_pcall(lua, 2, 1, 0)))
					{
						if (lua_toboolean(lua, -1)) return true;
						else if (verbose) ::syslog(LOG_DEBUG, "[Lua] function %s returned false", function_name);
					}
					else if (verbose) ::syslog(LOG_DEBUG, "[Lua] Unable to call function %s", function_name);
				}
				else if (verbose) ::syslog(LOG_DEBUG, "[Lua] %s is not a function", function_name);
			}
			else if (verbose) ::syslog(LOG_DEBUG, "[Lua] Failed doing file \"" CONFIG_FILE "\"");
			return false;
		}
		
		/// Call lua function from config
		inline bool lua_request_permission(const char* function_name, decltype(users.end()) user)
		{
			lua_scope_stack_cleaner cleaner(lua);
			
			if (check_lua(lua, luaL_dofile(lua, CONFIG_FILE)))
			{
				luaL_openlibs(lua);
				lua_getglobal(lua, LUA_SET_PASSWORD_FUNC);
				if (lua_isfunction(lua, -1))
				{
					lua_createtable(lua, 0, 3);
					
					lua_pushstring(lua, user->first.c_str());
					lua_setfield(lua, -2, "login");
					
					lua_pushstring(lua, user->second.password.c_str());
					lua_setfield(lua, -2, "password");
					
					lua_pushstring(lua, user->second.display_name.c_str());
					lua_setfield(lua, -2, "display_name");
					
					if (check_lua(lua, lua_pcall(lua, 1, 1, 0)))
					{
						if (lua_toboolean(lua, -1)) return true;
						else if (verbose) ::syslog(LOG_DEBUG, "[Lua] function %s returned false", function_name);
					}
					else if (verbose) ::syslog(LOG_DEBUG, "[Lua] Unable to call function %s", function_name);
				}
				else if (verbose) ::syslog(LOG_DEBUG, "[Lua] %s is not a function", function_name);
			}
			else if (verbose) ::syslog(LOG_DEBUG, "[Lua] Failed doing file \"" CONFIG_FILE "\"");
			return false;
		}
		
		/// Check if user \b login with password \b password registered on this server
		inline static bool check_credentials(
				HEADER& response, const std::string& login, std::string& password, server* serv, decltype(users.end())& user)
		{
			user = users.find(login);
			if (user == users.end())
				if (int ret = serv->db_user_manager->load_user(login); ret) // lookup for him in database
					return false;
			
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
		
		/// Check string limits
		inline static bool assert_credentials(messenger_io& io, const HEADER& header, HEADER& response)
		{
			if (header.login_size > MAX_LOGIN)
			{
				if (verbose) ::syslog(LOG_ERR, "HEADER::login_size = %zu which is too long.", header.login_size);
				response.err = HEADER::e_too_short_password;
				return true;
			}
			
			if (header.password_size > MAX_PASSWORD)
			{
				if (verbose) ::syslog(LOG_ERR, "HEADER::password_size = %zu which is too long.", header.password_size);
				response.err = HEADER::e_too_long_password;
				return true;
			}
			
			if (header.password_size < 8) // require at least 8 chars
			{
				if (verbose) ::syslog(LOG_ERR, "HEADER::password_size = %zu which is too short.", header.password_size);
				response.err = HEADER::e_too_short_password;
				return true;
			}
			
			return false;
		}
		
		inline static bool compute_passwd_hash(std::string& password, std::string& salt)
		{
			mutex_auto_lock<decltype(mutex)> locker(&mutex); // lock entire function
			
			char* arr_salt = (salt.empty() ? nullptr : salt.data());
			char* hash = nullptr;
			if (verbose) ::syslog(LOG_DEBUG, "Hashing password to operate with it.");
			if (hash_passwd(&arr_salt, &hash, password.data(), __detail__::PASSWD_HASH_TYPE))
			{
				password = hash;
				salt = arr_salt;
				return true;
			}
			else if (verbose) ::syslog(LOG_ERR, "Failed to compute password hash.");
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
				if (verbose) ::syslog(LOG_ERR, "HEADER::display_name_size = %zu which is too long.", header.display_name_size);
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
				if (verbose) ::syslog(LOG_ERR, "Incorrect arguments was passed: salt_p == nullptr.");
				return false;
			}
			
			/* first make sure we have a salt */
			if (*salt_p == nullptr)
			{
				size_t saltlen = 0;
				size_t i;
				
				if (mode == __detail__::passwd_md_5 || mode == __detail__::passwd_apr_1 || mode == __detail__::passwd_aix_md_5)
					saltlen = 8;
				
				if (mode == __detail__::passwd_sha_256 || mode == __detail__::passwd_sha_512)
					saltlen = 16;
				
				assert(saltlen != 0);
				
				if (__detail__::random_bytes(salt_p, static_cast<int>(saltlen)) <= 0)
					return false;
				
				for (i = 0; i < saltlen; i++)
				{
					(*salt_p)[i] = static_cast<char>(__detail__::cov_2_char[(*salt_p)[i] & 0x3f]); /* 6 bits */
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
			
			if (mode == __detail__::passwd_md_5 || mode == __detail__::passwd_apr_1)
				*hash = __detail__::md_5_crypt(passwd, (mode == __detail__::passwd_md_5 ? "1" : "apr1"), *salt_p);
			
			if (mode == __detail__::passwd_aix_md_5)
				*hash = __detail__::md_5_crypt(passwd, "", *salt_p);
			
			if (mode == __detail__::passwd_sha_256 || mode == __detail__::passwd_sha_512)
				*hash = __detail__::sha_crypt(passwd, (mode == __detail__::passwd_sha_256 ? "5" : "6"), *salt_p);
			
			return hash != nullptr;
		}
	};
	
	std::map<std::string, server::USER_DATA> server::users;
	std::map<std::string, server::USER_STATUS> server::statuses;
	MESSAGES server::incoming;
	std::recursive_mutex server::mutex;
	int server::scope_indicator::spaces_cnt = 0;
	std::mutex server::scope_indicator::mutex;
	
	namespace __detail__ __attribute__((visibility("hidden")))
	{
		inline static int random_bytes(char** data, int size)
		{
			if (size)
			{
				*data = new char[size];
				::srandom(::time(nullptr));
				for (int i = 0; i < size; ++i)
				{
					(*data)[i] = static_cast<char>(::random());
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
		inline static char* md_5_crypt(const char* passwd, const char* magic, const char* salt)
		{
			if (verbose) ::syslog(LOG_DEBUG, "Computing MD5 hash...");
			/* "$apr1$..salt..$.......md5hash..........\0" */
			static char out_buf[6 + 9 + 24 + 2];
			unsigned char buf[MD5_DIGEST_LENGTH];
			char ascii_magic[5];         /* "apr1" plus '\0' */
			char ascii_salt[9];          /* Max 8 chars plus '\0' */
			char* ascii_passwd = nullptr;
			char* salt_out;
			unsigned int i;
			EVP_MD_CTX* md = nullptr, * md_2 = nullptr;
			size_t n, passwd_len, salt_len, magic_len;
			
			passwd_len = ::strlen(passwd);
			
			out_buf[0] = 0;
			magic_len = ::strlen(magic);
			OPENSSL_strlcpy(ascii_magic, magic, sizeof(ascii_magic));
#ifdef CHARSET_EBCDIC
			if ((magic[0] & 0x80) != 0)    /* High bit is 1 in EBCDIC alnums */
		ebcdic2ascii(ascii_magic, ascii_magic, magic_len);
#endif
			
			/* The salt gets truncated to 8 chars */
			OPENSSL_strlcpy(ascii_salt, salt, sizeof(ascii_salt));
			salt_len = ::strlen(ascii_salt);
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
			
			if (::strlen(out_buf) > 6 + 8) /* assert "$apr1$..salt.." */
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
			
			md_2 = EVP_MD_CTX_new();
			if (md_2 == nullptr
				|| !EVP_DigestInit_ex(md_2, EVP_md5(), nullptr)
				|| !EVP_DigestUpdate(md_2, passwd, passwd_len)
				|| !EVP_DigestUpdate(md_2, ascii_salt, salt_len)
				|| !EVP_DigestUpdate(md_2, passwd, passwd_len)
				|| !EVP_DigestFinal_ex(md_2, buf, nullptr))
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
				if (!EVP_DigestInit_ex(md_2, EVP_md5(), nullptr))
					goto err;
				if (!EVP_DigestUpdate(
						md_2,
						(i & 1) ? (const unsigned char*)passwd : buf,
						(i & 1) ? passwd_len : sizeof(buf)))
					goto err;
				if (i % 3)
				{
					if (!EVP_DigestUpdate(md_2, ascii_salt, salt_len))
						goto err;
				}
				if (i % 7)
				{
					if (!EVP_DigestUpdate(md_2, passwd, passwd_len))
						goto err;
				}
				if (!EVP_DigestUpdate(
						md_2,
						(i & 1) ? buf : (const unsigned char*)passwd,
						(i & 1) ? sizeof(buf) : passwd_len
				))
					goto err;
				if (!EVP_DigestFinal_ex(md_2, buf, nullptr))
					goto err;
			}
			EVP_MD_CTX_free(md_2);
			EVP_MD_CTX_free(md);
			md_2 = nullptr;
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
					*output++ = static_cast<char>(cov_2_char[buf_perm[i + 2] & 0x3f]);
					*output++ = static_cast<char>(cov_2_char[((buf_perm[i + 1] & 0xf) << 2) | (buf_perm[i + 2] >> 6)]);
					*output++ = static_cast<char>(cov_2_char[((buf_perm[i] & 3) << 4) | (buf_perm[i + 1] >> 4)]);
					*output++ = static_cast<char>(cov_2_char[buf_perm[i] >> 2]);
				}
				assert(i == 15);
				*output++ = static_cast<char>(cov_2_char[buf_perm[i] & 0x3f]);
				*output++ = static_cast<char>(cov_2_char[buf_perm[i] >> 6]);
				*output = 0;
				assert(strlen(out_buf) < sizeof(out_buf));
#ifdef CHARSET_EBCDIC
				ascii2ebcdic(out_buf, out_buf, strlen(out_buf));
#endif
			}
			
			return out_buf;

err:
			OPENSSL_free(ascii_passwd);
			EVP_MD_CTX_free(md_2);
			EVP_MD_CTX_free(md);
			return nullptr;
		}

/*
 * SHA based password algorithm, describe by Ulrich Drepper here:
 * https://www.akkadia.org/drepper/SHA-crypt.txt
 * (note that it's in the public domain)
 */
		inline static char* sha_crypt(const char* passwd, const char* magic, const char* salt)
		{
			if (verbose) ::syslog(LOG_DEBUG, "Computing SHA hash...");
			/* Prefix for optional rounds specification.  */
			static const char rounds_prefix[] = "rounds=";
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
			EVP_MD_CTX* md = nullptr, * md_2 = nullptr;
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
			
			md_2 = EVP_MD_CTX_new();
			if (md_2 == nullptr
				|| !EVP_DigestInit_ex(md_2, sha, nullptr)
				|| !EVP_DigestUpdate(md_2, passwd, passwd_len)
				|| !EVP_DigestUpdate(md_2, ascii_salt, salt_len)
				|| !EVP_DigestUpdate(md_2, passwd, passwd_len)
				|| !EVP_DigestFinal_ex(md_2, buf, nullptr))
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
			if (!EVP_DigestInit_ex(md_2, sha, nullptr))
				goto err;
			
			for (n = passwd_len; n > 0; n--)
				if (!EVP_DigestUpdate(md_2, passwd, passwd_len))
					goto err;
			
			if (!EVP_DigestFinal_ex(md_2, temp_buf, nullptr))
				goto err;
			
			if ((p_bytes = static_cast<decltype(p_bytes)>(OPENSSL_zalloc(passwd_len))) == nullptr)
				goto err;
			for (cp = p_bytes, n = passwd_len; n > buf_size; n -= buf_size, cp += buf_size)
				memcpy(cp, temp_buf, buf_size);
			memcpy(cp, temp_buf, n);
			
			/* S sequence */
			if (!EVP_DigestInit_ex(md_2, sha, nullptr))
				goto err;
			
			for (n = 16 + buf[0]; n > 0; n--)
				if (!EVP_DigestUpdate(md_2, ascii_salt, salt_len))
					goto err;
			
			if (!EVP_DigestFinal_ex(md_2, temp_buf, nullptr))
				goto err;
			
			if ((s_bytes = static_cast<decltype(s_bytes)>(OPENSSL_zalloc(salt_len))) == nullptr)
				goto err;
			for (cp = s_bytes, n = salt_len; n > buf_size; n -= buf_size, cp += buf_size)
				memcpy(cp, temp_buf, buf_size);
			memcpy(cp, temp_buf, n);
			
			for (n = 0; n < rounds; n++)
			{
				if (!EVP_DigestInit_ex(md_2, sha, nullptr))
					goto err;
				if (!EVP_DigestUpdate(
						md_2,
						(n & 1) ? (const unsigned char*)p_bytes : buf,
						(n & 1) ? passwd_len : buf_size
				))
					goto err;
				if (n % 3)
				{
					if (!EVP_DigestUpdate(md_2, s_bytes, salt_len))
						goto err;
				}
				if (n % 7)
				{
					if (!EVP_DigestUpdate(md_2, p_bytes, passwd_len))
						goto err;
				}
				if (!EVP_DigestUpdate(
						md_2,
						(n & 1) ? buf : (const unsigned char*)p_bytes,
						(n & 1) ? buf_size : passwd_len
				))
					goto err;
				if (!EVP_DigestFinal_ex(md_2, buf, nullptr))
					goto err;
			}
			EVP_MD_CTX_free(md_2);
			EVP_MD_CTX_free(md);
			md_2 = nullptr;
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
                *cp++ = cov_2_char[w & 0x3f];                            \
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
			EVP_MD_CTX_free(md_2);
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

#endif //PRIVACY_PROTECTION_MESSENGER_MESSENGER_HPP
