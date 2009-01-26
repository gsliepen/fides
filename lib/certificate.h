/* certificate.h - Fides certificate class
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

#include <string>
#include <sys/time.h>
#include "publickey.h"
#include "privatekey.h"

namespace fides {
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
}

#endif
