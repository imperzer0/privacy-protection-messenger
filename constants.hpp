//
// Created by imper on 4/21/22.
//

#ifndef PRIVACY_PROTECTION_MESSENGER_CONSTANTS_HPP
#define PRIVACY_PROTECTION_MESSENGER_CONSTANTS_HPP

# define _STR(s) #s
# define MACRO_STR(v) _STR(v)

# ifndef USERS_TABLE_NAME
#  define USERS_TABLE_NAME "registeredusers"
# endif

# ifndef DATABASE_NAME
#  define DATABASE_NAME "PPMdb"
# endif

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

#define CASE_TO_STR(opt) case opt: return _STR(opt);


class CONSTANT
{
public:
	enum : int
	{
		invalid = 0,
		DB_NAME,
		USERS_TBL_NAME,
		APPLICATION_NAME,
		SSLCRT_DIR,
		SSLCRT_PATH,
		SSLPRIKEY_PATH,
		SSLCRT_COUNTRY,
		SSLCRT_ORGANIZATION,
		SSLCRT_CRT_NAME,
		LOGIN_LIMIT,
		PASSWORD_LIMIT,
		DISPLAY_NAME_LIMIT,
		CONFIG_DIRECTORY,
		WORK_DIRECTORY,
		PASSWD_HASH_ALGO,
		MESSENGER_PORT,
		SEARCH_USER_ENTRIES_LIMIT,
		maxval
	};
	
	inline CONSTANT(const std::string& name)
	{
		if (name == _STR(DB_NAME))
			constval = (DB_NAME);
		else if (name == _STR(USERS_TBL_NAME))
			constval = (USERS_TBL_NAME);
		else if (name == _STR(APPLICATION_NAME))
			constval = (APPLICATION_NAME);
		else if (name == _STR(SSLCRT_DIR))
			constval = (SSLCRT_DIR);
		else if (name == _STR(SSLCRT_PATH))
			constval = (SSLCRT_PATH);
		else if (name == _STR(SSLPRIKEY_PATH))
			constval = (SSLPRIKEY_PATH);
		else if (name == _STR(SSLCRT_COUNTRY))
			constval = (SSLCRT_COUNTRY);
		else if (name == _STR(SSLCRT_ORGANIZATION))
			constval = (SSLCRT_ORGANIZATION);
		else if (name == _STR(SSLCRT_CRT_NAME))
			constval = (SSLCRT_CRT_NAME);
		else if (name == _STR(LOGIN_LIMIT))
			constval = (LOGIN_LIMIT);
		else if (name == _STR(PASSWORD_LIMIT))
			constval = (PASSWORD_LIMIT);
		else if (name == _STR(DISPLAY_NAME_LIMIT))
			constval = (DISPLAY_NAME_LIMIT);
		else if (name == _STR(CONFIG_DIRECTORY))
			constval = (CONFIG_DIRECTORY);
		else if (name == _STR(WORK_DIRECTORY))
			constval = (WORK_DIRECTORY);
		else if (name == _STR(PASSWD_HASH_ALGO))
			constval = (PASSWD_HASH_ALGO);
		else if (name == _STR(MESSENGER_PORT))
			constval = (MESSENGER_PORT);
		else if (name == _STR(SEARCH_USER_ENTRIES_LIMIT))
			constval = (SEARCH_USER_ENTRIES_LIMIT);
		else constval = (invalid);
	}
	
	inline CONSTANT(decltype(invalid) constval) : constval(constval)
	{ }
	
	inline const char* to_string()
	{
		switch (constval)
		{
			CASE_TO_STR(DB_NAME)
			CASE_TO_STR(USERS_TBL_NAME)
			CASE_TO_STR(APPLICATION_NAME)
			CASE_TO_STR(SSLCRT_DIR)
			CASE_TO_STR(SSLCRT_PATH)
			CASE_TO_STR(SSLPRIKEY_PATH)
			CASE_TO_STR(SSLCRT_COUNTRY)
			CASE_TO_STR(SSLCRT_ORGANIZATION)
			CASE_TO_STR(SSLCRT_CRT_NAME)
			CASE_TO_STR(LOGIN_LIMIT)
			CASE_TO_STR(PASSWORD_LIMIT)
			CASE_TO_STR(DISPLAY_NAME_LIMIT)
			CASE_TO_STR(CONFIG_DIRECTORY)
			CASE_TO_STR(WORK_DIRECTORY)
			CASE_TO_STR(PASSWD_HASH_ALGO)
			CASE_TO_STR(MESSENGER_PORT)
			CASE_TO_STR(SEARCH_USER_ENTRIES_LIMIT)
			CASE_TO_STR(maxval)
			default:
				return _STR(invalid);
		}
	}
	
	inline bool operator==(decltype(invalid) constval)
	{
		return this->constval == constval;
	}
	
	inline bool operator==(CONSTANT constant)
	{
		return this->constval == constant.constval;
	}
	
	inline operator decltype(invalid)()
	{
		return constval;
	}
	
	inline void print_self(std::ostream& ostream)
	{
		switch (constval)
		{
			case CONSTANT::DB_NAME:
				std::cout << DATABASE_NAME << "\n";
				break;
			case CONSTANT::USERS_TBL_NAME:
				std::cout << USERS_TABLE_NAME << "\n";
				break;
			case CONSTANT::APPLICATION_NAME:
				std::cout << MESSENGER_NAME << "\n";
				break;
			case CONSTANT::SSLCRT_DIR:
				std::cout << CERTIFICATE_DIR << "\n";
				break;
			case CONSTANT::SSLCRT_PATH:
				std::cout << CERTIFICATE_PATH << "\n";
				break;
			case CONSTANT::SSLPRIKEY_PATH:
				std::cout << PRIVATE_KEY_PATH << "\n";
				break;
			case CONSTANT::SSLCRT_COUNTRY:
				std::cout << COUNTRY << "\n";
				break;
			case CONSTANT::SSLCRT_ORGANIZATION:
				std::cout << ORGANIZATION << "\n";
				break;
			case CONSTANT::SSLCRT_CRT_NAME:
				std::cout << CERTIFICATE_NAME << "\n";
				break;
			case CONSTANT::LOGIN_LIMIT:
				std::cout << MAX_LOGIN << "\n";
				break;
			case CONSTANT::PASSWORD_LIMIT:
				std::cout << MAX_PASSWORD << "\n";
				break;
			case CONSTANT::DISPLAY_NAME_LIMIT:
				std::cout << MAX_DISPLAY_NAME << "\n";
				break;
			case CONSTANT::CONFIG_DIRECTORY:
				std::cout << CONFIG_DIR << "\n";
				break;
			case CONSTANT::WORK_DIRECTORY:
				std::cout << DEFAULT_WORK_DIR << "\n";
				break;
			case CONSTANT::PASSWD_HASH_ALGO:
				std::cout << MACRO_STR(PASSWD_HASH_TYPE) << "\n";
				break;
			case CONSTANT::MESSENGER_PORT:
				std::cout << DEFAULT_PORT << "\n";
				break;
			case CONSTANT::SEARCH_USER_ENTRIES_LIMIT:
				std::cout << MAX_USER_ENTRIES_AMOUNT << "\n";
				break;
			default:
				CONSTANT::print_all_constants(std::cout);
		}
	}
	
	inline static void print_all_constants(std::ostream& ostream)
	{
		ostream << "CONSTANT\n{\n";
		for (auto i = invalid + 1; i < maxval; ++i)
		{
			ostream << "  " << CONSTANT(static_cast<decltype(invalid)>(i)).to_string() << ",\n";
		}
		ostream << "};\n";
	}

private:
	decltype(invalid) constval = invalid;
};

#endif //PRIVACY_PROTECTION_MESSENGER_CONSTANTS_HPP