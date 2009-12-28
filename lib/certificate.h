/* Certificate.h - Fides Certificate class
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

#ifndef __FIDES_CERTIFICATE_H__
#define __FIDES_CERTIFICATE_H__

#include <sys/time.h>
#include "publickey.h"
#include "privatekey.h"

#ifdef __cplusplus
#include <string>

namespace Fides {
	class Certificate {
		friend class Manager;

		/// Public key that signed this certificate.
		const PublicKey *signer;
		struct timeval timestamp;
		std::string statement;
		std::string signature;

		public:
		Certificate(const PublicKey *pub, struct timeval timestamp, const std::string &statement, const std::string &signature);
		Certificate(const PrivateKey *priv, struct timeval timestamp, const std::string &statement);

		std::string to_string() const;
		std::string fingerprint(unsigned int bits = 64) const;
		bool validate() const;
	};
}

extern "C" {
typedef Fides::Certificate fides_certificate;
#else
typedef struct fides_certificate fides_certificate;
#endif

extern fides_certificate *fides_certificate_new(const fides_publickey *pub, struct timeval timestamp, const char *statement, const char *signature);
extern fides_certificate *fides_certificate_new_priv(const fides_privatekey *priv, struct timeval timestamp, const char *statement);
extern void fides_certificate_free(fides_certificate *c);

extern char *fides_certificate_to_string(fides_certificate *c);
extern char *fides_certificate_fingerprint(fides_certificate *c, unsigned int bits);
extern bool fides_certificate_validate(fides_certificate *c);

#ifdef __cplusplus
}
#endif

#endif
