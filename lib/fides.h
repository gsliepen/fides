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

#include <sys/time.h>
#include "certificate.h"
#include "publickey.h"
#include "privatekey.h"
#include "utility.h"

#ifdef __cplusplus
#include <stdexcept>
#include <map>
#include <vector>

namespace Fides {
	class exception: public std::runtime_error {
		public:
		exception(const std::string reason): runtime_error(reason) {}
	};

	class Manager {
		std::string homedir;
		std::string certdir;
		std::string obsoletedir;
		std::string keydir;

		bool firstrun;
		struct timeval latest;

		private:
		PrivateKey mykey;
		std::map<std::string, PublicKey *> keys;
		std::map<std::string, Certificate *> certs;

		void merge(Certificate *cert);
		void merge(PublicKey *key);

		public:
		Manager(const std::string &homedir = "");
		~Manager();

		bool is_firstrun() const;
		bool fsck() const;
		std::string get_homedir() const;

		void sign(const std::string &statement);

		void allow(const std::string &statement, const PublicKey *key = 0);
		void dontcare(const std::string &statement, const PublicKey *key = 0);
		void deny(const std::string &statement, const PublicKey *key = 0);
		bool is_allowed(const std::string &statement, const PublicKey *key = 0) const;
		bool is_denied(const std::string &statement, const PublicKey *key = 0) const;

		void auth_stats(const std::string &statement, int &self, int &trusted, int &all) const;
		void trust(const PublicKey *key);
		void dctrust(const PublicKey *key);
		void distrust(const PublicKey *key);
		bool is_trusted(const PublicKey *key) const;
		bool is_distrusted(const PublicKey *key) const;
		PublicKey *find_key(const std::string &fingerprint) const;
		void update_trust();

		std::vector<const Certificate *> find_certificates(const PublicKey *key, const std::string &statement) const;
		std::vector<const Certificate *> find_certificates(const std::string &statement) const;
		std::vector<const Certificate *> find_certificates(const PublicKey *key) const;

		const Certificate *import_certificate(const std::string &Certificate);
		std::string export_certificate(const Certificate *) const;

		const PublicKey *import_key(const std::string &key);
		std::string export_key(const PublicKey *key) const;

		void import_all(std::istream &in);
		void export_all(std::ostream &out) const;

		Certificate *certificate_from_string(const std::string &Certificate);
		Certificate *certificate_load(const std::string &filename);
		void certificate_save(const Certificate *cert, const std::string &filename) const;

	};
}

extern "C" {
typedef Fides::Manager fides_manager;
#else
#include <stdbool.h>
#include <stdio.h>
typedef struct fides_manager fides_manager;
#endif

extern fides_manager *fides_init_manager(char *homedir);
extern void fides_exit_manager(fides_manager *m);

extern bool fides_is_firstrun(fides_manager *m);
extern bool fides_fsck(fides_manager *m);
extern char *fides_get_homedir(fides_manager *m);

extern void fides_sign(fides_manager *m, const char *statement);

extern void fides_allow(fides_manager *m, const char *statement, const fides_publickey *key);
extern void fides_dontcare(fides_manager *m, const char *statement, const fides_publickey *key);
extern void fides_deny(fides_manager *m, const char *statement, const fides_publickey *key);
extern bool fides_is_allowed(fides_manager *m, const char *statement, const fides_publickey *key);
extern bool fides_is_denied(fides_manager *m, const char *statement, const fides_publickey *key);

extern void fides_auth_stats(fides_manager *m, const char *statement, int *self, int *trusted, int *all);
extern void fides_trust(fides_manager *m, const fides_publickey *key);
extern void fides_dctrust(fides_manager *m, const fides_publickey *key);
extern void fides_distrust(fides_manager *m, const fides_publickey *key);
extern bool fides_is_trusted(fides_manager *m, const fides_publickey *key);
extern bool fides_is_distrusted(fides_manager *m, const fides_publickey *key);
extern fides_publickey *fides_find_key(fides_manager *m, const char *fingerprint);
extern void fides_update_trust(fides_manager *m);

extern fides_certificate **find_certificates(fides_manager *m, const fides_publickey *key, const char *statement);

extern const fides_certificate *fides_import_certificate(fides_manager *m, const char *certificate);
extern char *fides_export_certificate(fides_manager *m, const fides_certificate *certificcate);

extern const fides_publickey *fides_import_key(fides_manager *m, const char *key);
extern char *fides_export_key(fides_manager *m, const fides_publickey *key);

extern void fides_import_all(fides_manager *m, FILE *in);
extern void fides_export_all(fides_manager *m, FILE *out);

extern fides_certificate *fides_certificate_from_string(fides_manager *m, const char *certificate);
extern fides_certificate *fides_certificate_load(fides_manager *m, const char *filename);
extern void fides_certificate_save(fides_manager *m, const fides_certificate *cert, const char *filename);

#ifdef __cplusplus
}
#endif

#endif
