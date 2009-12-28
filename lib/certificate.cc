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

#include <cstdio>
#include <string>

#include "certificate.h"
#include "fides.h"

using namespace std;

namespace Fides {
	/// \class Certificate
	///
	/// \brief Representation of a certificate.

	/// Construct a certificate from elements of an already existing certificate.
	//
	/// @param key        Public key used to sign the certificate.
	/// @param timestamp  Timestamp of the certificate.
	/// @param statement  Statement of the certificate.
	/// @param signature  Signature of the certificate.
	Certificate::Certificate(const PublicKey *key, struct timeval timestamp, const std::string &statement, const std::string &signature): signer(key), timestamp(timestamp), statement(statement), signature(signature) {}

	/// Verifies the signature of the certificate.
	//
	/// @return True if the signature is valid, false otherwise.
	bool Certificate::validate() const {
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
	Certificate::Certificate(const PrivateKey *key, struct timeval timestamp, const std::string &statement): signer(key), timestamp(timestamp), statement(statement) {
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
	string Certificate::fingerprint(unsigned int bits) const {
		return signature.substr(signature.size() - bits / 8);	
	}

	/// Write the certificate to a string.
	//
	/// @return String containing the certificate in textual format.
	string Certificate::to_string() const {
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

// C bindings

fides_certificate *fides_certificate_new(const fides_publickey *pub, struct timeval timestamp, const char *statement, const char *signature) {
	return new Fides::Certificate(pub, timestamp, statement, signature);
}

fides_certificate *fides_certificate_new_priv(const fides_privatekey *priv, struct timeval timestamp, const char *statement) {
	return new Fides::Certificate(priv, timestamp, statement);
}

void fides_certificate_free(fides_certificate *c) {
	delete c;
}


char *fides_certificate_to_string(fides_certificate *c) {
	return strdup(c->to_string().c_str());
}

char *fides_certificate_fingerprint(fides_certificate *c, unsigned int bits) {
	return strdup(c->fingerprint(bits).c_str());
}

bool fides_certificate_validate(fides_certificate *c) {
	return c->validate();
}
