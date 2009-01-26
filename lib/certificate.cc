/* fides.cc - Light-weight, decentralised trust and authorisation management
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

#include <string>

#include "certificate.h"
#include "fides.h"

using namespace std;

namespace fides {
	/// \class fides::certificate
	///
	/// \brief Representation of a certificate.

	/// Construct a certificate from elements of an already existing certificate.
	//
	/// @param key        Public key used to sign the certificate.
	/// @param timestamp  Timestamp of the certificate.
	/// @param statement  Statement of the certificate.
	/// @param signature  Signature of the certificate.
	certificate::certificate(const publickey *key, struct timeval timestamp, const std::string &statement, const std::string &signature): signer(key), timestamp(timestamp), statement(statement), signature(signature) {}

	/// Verifies the signature of the certificate.
	//
	/// @return True if the signature is valid, false otherwise.
	bool certificate::validate() const {
		string data = signer->fingerprint(256);
		data += string((const char *)&timestamp, sizeof timestamp);
		data += statement;
		return signer->verify(data, signature);
	}

	/// Construct a new certificate and sign it with the private key.
	//
	/// @param key        Private key to sign the certificate with.
	/// @param timestamp  Timestamp of the certificate.
	/// @param statement  Statement of the certificate.
	certificate::certificate(const privatekey *key, struct timeval timestamp, const std::string &statement): signer(key), timestamp(timestamp), statement(statement) {
		string data = signer->fingerprint(256);
		data += string((const char *)&timestamp, sizeof timestamp);
		data += statement;
		signature = key->sign(data);
	}

	/// Get the fingerprint of this certificate.
	//
	/// @param bits Number of bits from the fingerprint to return.
	///             The number will be rounded down to the nearest multiple of 8.
	/// @return String containing the fingerprint.
	string certificate::fingerprint(unsigned int bits) const {
		return signature.substr(signature.size() - bits / 8);	
	}

	/// Write the certificate to a string.
	//
	/// @return String containing the certificate in textual format.
	string certificate::to_string() const {
		string data = hexencode(signer->fingerprint());
		data += ' ';
		char ts[100];
		snprintf(ts, sizeof ts, "%lu.%06lu", timestamp.tv_sec, timestamp.tv_usec);
		data += ts;
		data += ' ';
		data += b64encode(signature);
		data += ' ';
		data += statement;
		return data;
	}
}
