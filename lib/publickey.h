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

#ifndef __FIDES_PUBLICKEY_H__
#define __FIDES_PUBLICKEY_H__

#ifdef __cplusplus
#include <string>
#include <iostream>
#include <botan/botan.h>
#include <botan/ecdsa.h>
	
namespace Fides {
	class PublicKey {
		protected:
		Botan::ECDSA_PublicKey *pub;

		public:
		PublicKey();
		~PublicKey();

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
}

extern "C" {
typedef Fides::PublicKey fides_publickey;
#else
#include <stdbool.h>
typedef struct fides_publickey fides_publickey;
#endif

extern fides_publickey *fides_publickey_new();
extern void fides_publickey_free(fides_publickey *k);

extern void fides_publickey_set_trust(fides_publickey *k, int trust);
extern int fides_publickey_get_trust(fides_publickey *k);

extern void fides_publickey_load(fides_publickey *k, const char *filename);
extern void fides_publickey_save(fides_publickey *k, const char *filename);
extern bool fides_publickey_verify(fides_publickey *k, const char *data, const char *signature);
extern char *fides_publickey_to_string(fides_publickey *k);
extern void fides_publickey_from_string(fides_publickey *k, const char *in);
extern char *fides_publickey_fingerprint(fides_publickey *k, unsigned int bits);

#ifdef __cplusplus
}
#endif

#endif
