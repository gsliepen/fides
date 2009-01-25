/* fides.h - Light-weight, decentralised trust and authorisation management
   Copyright (C) 2008-2009  Guus Sliepen <guus@tinc-vpn.org>
  
   Fides is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
  
   Fides is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU Lesser General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __FIDES_H__
#define __FIDES_H__

#include <stdexcept>
#include <regex.h>
#include <botan/botan.h>
#include <botan/ecdsa.h>
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

	/// Compiled regular expression.

	/// This class holds a compiled regular expression,
	/// which can be used to match arbitrary strings to.
	/// It is a wrapper for the POSIX regex functions
	/// regcomp() and regexec().
	class regexp {
		regex_t comp;

		public:
		static const int EXTENDED = REG_EXTENDED;
		static const int ICASE = REG_ICASE;
		static const int NOSUB = REG_NOSUB;
		static const int NEWLINE = REG_NEWLINE;

		static const int NOTBOL = REG_NOTBOL;
		static const int NOTEOL = REG_NOTEOL;

		/// Construct a compiled regular expression.
		///
		/// @param exp    Regular expression to compile.
		/// @param cflags Bitwise OR of options to apply when compiling the regular expression:
		///               - fides::regexp::EXTENDED
		///                 Use POSIX Extended Regular Expression syntax when interpreting exp.
		///               - fides::regexp::ICASE
		///                 Make the expression case-insensitive.
		///               - fides::regexp::NOSUB
		///                 Disable support for substring addressing.
		///               - fides::regexp::NEWLINE
		///                 Do not treat the newline character as the start or end of a line.
		regexp(const std::string &exp, int cflags = 0) {
			int err = regcomp(&comp, exp.c_str(), cflags);
			if(err)
				throw exception("Could not compile regular expression");
		}

		~regexp() {
			regfree(&comp);
		}

		/// Test whether a string matches the regular expression.
		///
		/// @param in     String to test.
		/// @param eflags Bitwise OR of options to apply when matching the string:
		///               - fides::regexp::NOTBOL
		///                 Do not treat the start of the string as the start of a line.
		///               - fides::regexp::NOTEOL
		///                 Do not treat the end of the string as the end of a line.
		/// @return True if the string matches the regular expression, false otherwise.
		bool match(const std::string &in, int eflags = 0) {
			return regexec(&comp, in.c_str(), 0, 0, eflags) == 0;
		}
	};

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
		void save(std::ostream &out) const;
		void load(const std::string &filename);
		void save(const std::string &filename) const;
		bool verify(const std::string &data, const std::string &signature) const;
		std::string to_string() const;
		void from_string(const std::string &in);
		std::string fingerprint(unsigned int bits = 64) const;
	};

	class privatekey: public publickey {
		Botan::ECDSA_PrivateKey *priv;

		public:
		privatekey();
		~privatekey();

		void load_private(std::istream &in);
		void save_private(std::ostream &out) const;
		void load_private(const std::string &filename);
		void save_private(const std::string &filename) const;
		void generate(const std::string &field);
		void generate(unsigned int bits = 224);
		std::string sign(const std::string &data) const;
	};

	class certificate {
		friend class fides;

		/// Public key that signed this certificate.
		const publickey *signer;
		struct timeval timestamp;
		std::string statement;
		std::string signature;

		public:
		certificate(const publickey *pub, struct timeval timestamp, const std::string &statement, const std::string &signature);
		certificate(const privatekey *priv, struct timeval timestamp, const std::string &statement);

		std::string to_string() const;
		std::string fingerprint(unsigned int bits = 64) const;
		bool validate() const;
	};

	// Fides class itself

	private:
	privatekey mykey;
	std::map<std::string, publickey *> keys;
	std::map<std::string, certificate *> certs;

	void merge(certificate *cert);
	void merge(publickey *key);

	public:
	fides(const std::string &homedir = "");
	~fides();

	bool is_firstrun() const;
	bool fsck() const;
	std::string get_homedir() const;

	void sign(const std::string &statement);

	void allow(const std::string &statement, const publickey *key = 0);
	void dontcare(const std::string &statement, const publickey *key = 0);
	void deny(const std::string &statement, const publickey *key = 0);
	bool is_allowed(const std::string &statement, const publickey *key = 0) const;
	bool is_denied(const std::string &statement, const publickey *key = 0) const;

	void auth_stats(const std::string &statement, int &self, int &trusted, int &all) const;
	void trust(const publickey *key);
	void dctrust(const publickey *key);
	void distrust(const publickey *key);
	bool is_trusted(const publickey *key) const;
	bool is_distrusted(const publickey *key) const;
	publickey *find_key(const std::string &fingerprint) const;
	void update_trust();

	std::vector<const certificate *> find_certificates(const publickey *key, const std::string &statement) const;
	std::vector<const certificate *> find_certificates(const std::string &statement) const;
	std::vector<const certificate *> find_certificates(const publickey *key) const;

	const certificate *import_certificate(const std::string &certificate);
	std::string export_certificate(const certificate *) const;

	const publickey *import_key(const std::string &key);
	std::string export_key(const publickey *key) const;

	void import_all(std::istream &in);
	void export_all(std::ostream &out) const;

	certificate *certificate_from_string(const std::string &certificate);
	certificate *certificate_load(const std::string &filename);
	void certificate_save(const certificate *cert, const std::string &filename) const;

};

#endif
