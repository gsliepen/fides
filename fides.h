#ifndef __FIDES_H__
#define __FIDES_H__

#include <stdexcept>
#include <regex.h>
#include <botan/botan.h>
#include <sys/time.h>
#include <map>

class fides {
	std::string homedir;
	std::string certdir;
	std::string obsoletedir;
	std::string keydir;

	bool firstrun;
	struct timeval latest;
	static Botan::AutoSeeded_RNG rng;

	public:
	// Utility functions

	static std::string b64encode(const std::string &in);
	static std::string b64decode(const std::string &in);
	static std::string hexencode(const std::string &in);
	static std::string hexdecode(const std::string &in);

	class regexp {
		regex_t comp;

		public:
		static const int EXTENDED = REG_EXTENDED;
		static const int ICASE = REG_ICASE;
		static const int NOSUB = REG_NOSUB;
		static const int NEWLINE = REG_NEWLINE;

		static const int NOTBOL = REG_NOTBOL;
		static const int NOTEAL = REG_NOTEOL;

		regexp(const std::string &exp, int cflags = 0) {
			int err = regcomp(&comp, exp.c_str(), cflags | NOSUB);
			if(err)
				throw exception("Could not compile regular expression");
		}

		~regexp() {
			regfree(&comp);
		}

		bool match(const std::string &in, int eflags = 0) {
			return regexec(&comp, in.c_str(), 0, 0, eflags) == 0;
		}
	};

	// Exception class

	class exception: public std::runtime_error {
                public:
                exception(const std::string reason): runtime_error(reason) {}
        };

	// Objects manipulated by fides

	class publickey {
		protected:
		Botan::ECDSA_PublicKey *pub;

		public:
		publickey();
		~publickey();

		int trust;
		void load(std::istream &in);
		void save(std::ostream &out);
		void load(const std::string &filename);
		void save(const std::string &filename);
		bool verify(const std::string &data, const std::string &signature);
		std::string to_string();
		void from_string(const std::string &in);
		std::string fingerprint(unsigned int bits = 64);
	};

	class privatekey: public publickey {
		Botan::ECDSA_PrivateKey *priv;

		public:
		privatekey();
		~privatekey();

		void load_private(std::istream &in);
		void save_private(std::ostream &out);
		void load_private(const std::string &filename);
		void save_private(const std::string &filename);
		void generate(const std::string &field);
		void generate(unsigned int bits = 224);
		std::string sign(const std::string &data);
	};

	class certificate {
		friend class fides;
		publickey *signer;
		struct timeval timestamp;
		std::string statement;
		std::string signature;

		public:
		certificate(publickey *pub, struct timeval timestamp, const std::string &statement, const std::string &signature);
		certificate(privatekey *priv, struct timeval timestamp, const std::string &statement);

		std::string to_string() const;
		std::string fingerprint(unsigned int bits = 64);
		bool validate();
	};

	// Fides class itself

	private:
	privatekey mykey;
	std::map<std::string, publickey *> keys;
	std::map<std::string, certificate *> certs;
	std::set<publickey *> trustedkeys;

	void merge(certificate *cert);
	void merge(publickey *key);

	public:
	fides(const std::string &homedir = "");
	~fides();

	bool is_firstrun();
	bool fsck();
	std::string get_homedir();

	void sign(const std::string &statement);

	void allow(const std::string &statement, publickey *key = 0);
	void dontcare(const std::string &statement, publickey *key = 0);
	void deny(const std::string &statement, publickey *key = 0);
	bool is_allowed(const std::string &statement, publickey *key = 0);
	bool is_denied(const std::string &statement, publickey *key = 0);

	void auth_stats(const std::string &statement, int &self, int &trusted, int &all);
	void trust(publickey *key);
	void dctrust(publickey *key);
	void distrust(publickey *key);
	bool is_trusted(publickey *key);
	bool is_distrusted(publickey *key);
	publickey *find_key(const std::string &fingerprint);
	void update_trust();

	std::vector<certificate *> find_certificates(publickey *key, const std::string &statement);
	std::vector<certificate *> find_certificates(const std::string &statement);
	std::vector<certificate *> find_certificates(publickey *key);

	certificate *import_certificate(const std::string &certificate);
	std::string export_certificate(const certificate *);

	publickey *import_key(const std::string &key);
	std::string export_key(const publickey *key);

	void import_all(std::istream &in);
	void export_all(std::ostream &out);

	certificate *certificate_from_string(const std::string &certificate);
	certificate *certificate_load(const std::string &filename);
	void certificate_save(const certificate *cert, const std::string &filename);

};

#endif
