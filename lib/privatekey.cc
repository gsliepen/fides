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

#include <iostream>
#include <fstream>
#include <string>
#include <botan/types.h>
#include <botan/botan.h>
#include <botan/ecdsa.h>
#include <botan/look_pk.h>
#include <botan/lookup.h>
#include <botan/filters.h>
#include <botan/sha2_32.h>

#include "fides.h"
#include "privatekey.h"

using namespace std;

static Botan::AutoSeeded_RNG rng;

namespace Fides {
	/// \class PrivateKey
	///
	/// \brief Representation of a public/private keypair.
	///
	/// With a private key we can create a signature of a statement,
	/// so that others who have the corresponding public key
	/// can ascertain that the statement was really made by us.

	PrivateKey::PrivateKey(): priv(0) {
	}

	PrivateKey::~PrivateKey() {
		delete priv;
		pub = 0;
	}

	/// Generates a new public/private keypair.
	//
	/// @param field OID of the field to generate a key in.
	void PrivateKey::generate(const std::string &field) {
		Botan::EC_Domain_Params domain = Botan::get_EC_Dom_Pars_by_oid(field);
		pub = priv = new Botan::ECDSA_PrivateKey(rng, domain);
	}

	/// Generates a new public/private keypair.
	//
	/// This function uses standard NIST fields.
	/// @param bits Desired size of the keys.
	///             Allowed values are 112, 128, 160, 192, 224, 256, 384 and 521.
	///             Keys less than 160 bits are considered weak.
	///             Keys greater than 224 bits are considered very strong.
	void PrivateKey::generate(unsigned int bits) {
		switch(bits) {
			case 112: return generate("1.3.132.0.6");
			case 128: return generate("1.3.132.0.28");
			case 160: return generate("1.3.132.0.9");
			case 192: return generate("1.3.132.0.31");
			case 224: return generate("1.3.132.0.32");
			case 256: return generate("1.3.132.0.10");
			case 384: return generate("1.3.132.0.34");
			case 521: return generate("1.3.132.0.35");
			default: throw Fides::exception("Unsupported number of bits for private key");
		}
	}

	/// Loads a private key from a stream.
	//
	/// @param in Stream to read from.
	void PrivateKey::load_private(std::istream &in) {
		try {
			Botan::DataSource_Stream stream(in);
			pub = priv = dynamic_cast<Botan::ECDSA_PrivateKey *>(Botan::PKCS8::load_key(stream, rng, ""));
		} catch(Botan::Exception &e) {
			throw Fides::exception(e.what());
		}
	}

	/// Loads a private key from a file.
	//
	/// @param filename Name of the file to read from.
	void PrivateKey::load_private(const std::string &filename) {
		ifstream in(filename.c_str());
		load_private(in);
	}

	/// Saves the private key to a stream.
	//
	/// @param out Stream to write to.
	void PrivateKey::save_private(std::ostream &out) const {
		out << Botan::PKCS8::PEM_encode(*priv);
	}

	/// Saves the private key to a file.
	//
	/// @param filename Name of the file to write to.
	void PrivateKey::save_private(const std::string &filename) const {
		ofstream out(filename.c_str());
		save_private(out);
	}

	/// Signs a statement with this private key.
	//
	/// @param statement The statement that is to be signed.
	/// @return A string containing the signature.
	string PrivateKey::sign(const std::string &statement) const {
		auto_ptr<Botan::PK_Signer> signer(Botan::get_pk_signer(*priv, "EMSA1(SHA-512)"));
		Botan::SecureVector<Botan::byte> sig = signer->sign_message((const Botan::byte *)statement.data(), statement.size(), rng);
		return string((const char *)sig.begin(), (size_t)sig.size());
	}
}
