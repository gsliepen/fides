/* PrivateKey.h - Fides private key class
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

#ifndef __FIDES_PRIVATEKEY_H__
#define __FIDES_PRIVATEKEY_H__

#include <string>
#include <botan/botan.h>
#include <botan/ecdsa.h>
#include "publickey.h"

namespace Fides {
	class PrivateKey: public PublicKey {
		Botan::ECDSA_PrivateKey *priv;

		public:
		PrivateKey();
		~PrivateKey();

		void load_private(std::istream &in);
		void save_private(std::ostream &out) const;
		void load_private(const std::string &filename);
		void save_private(const std::string &filename) const;
		void generate(const std::string &field);
		void generate(unsigned int bits = 224);
		std::string sign(const std::string &data) const;
	};
}

#endif
