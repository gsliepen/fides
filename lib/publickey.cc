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
#include <list>

#include "fides.h"
#include "publickey.h"

using namespace std;

namespace fides {
	/// \class publickey
	///
	/// \brief Representation of a public key.
	///
	/// A public key is the counterpart of a private key that is held by some entity.
	/// If we have a public key, we can verify signatures made by the corresponding private key.
	/// Thus, we can ascertain if a statement, if it has been properly signed,
	/// was indeed made by that entity.

	publickey::publickey(): pub(0), trust(0) {
	}

	publickey::~publickey() {
		delete pub;
	}

	/// Loads a public key from a stream.
	//
	/// @param in Stream to read from.
	void publickey::load(std::istream &in) {
		try {
			Botan::DataSource_Stream source(in);
			pub = dynamic_cast<Botan::ECDSA_PublicKey *>(Botan::X509::load_key(source));
		} catch(Botan::Exception &e) {
			throw fides::exception(e.what());
		}
	}

	/// Loads a public key from a file.
	//
	/// @param filename Name of the file to read the key from.
	void publickey::load(const std::string &filename) {
		ifstream in(filename.c_str());
		load(in);
	}

	/// Saves the public key to a stream.
	//
	/// @param out Stream to write to.
	void publickey::save(std::ostream &out) const {
		out << to_string();
	}

	/// Saves the public key to a file.
	//
	/// @param filename Name of the file to save the key to.
	void publickey::save(const std::string &filename) const {
		ofstream out(filename.c_str());
		save(out);
	}

	/// Loads a public key from a string.
	//
	/// @param in String containing a public key in textual format.
	void publickey::from_string(const std::string &in) {
		try {
			Botan::DataSource_Memory source(in);
			pub = dynamic_cast<Botan::ECDSA_PublicKey *>(Botan::X509::load_key(source));
		} catch(Botan::Exception &e) {
			throw fides::exception(e.what());
		}
	}

	/// Write the public key to a string.
	//
	/// @return String containing the public key in textual format.
	string publickey::to_string() const {
		return Botan::X509::PEM_encode(*pub);
	}

	/// Get the fingerprint of the public key.
	//
	/// @param bits Number of bits from the fingerprint to return.
	///             The number will be rounded down to the nearest multiple of 8.
	/// @return String containing the fingerprint.
	string publickey::fingerprint(unsigned int bits) const {
		// TODO: find out if there is a standard way to get a hash of an ECDSA public key
		Botan::SHA_256 sha256;
		Botan::SecureVector<Botan::byte> hash = sha256.process(Botan::X509::PEM_encode(*pub));
		return string((const char *)hash.begin(), bits / 8);
	}

	/// Verify the signature of a statement.
	//
	/// @param statement The statement. This is the data that has been signed.
	/// @param signature The signature of the statement.
	/// @return Returns true if the signature is indeed a valid signature, made by this public key, of the statement.
	///         Return false otherwise.
	bool publickey::verify(const std::string &statement, const std::string &signature) const {
		auto_ptr<Botan::PK_Verifier> verifier(Botan::get_pk_verifier(*pub, "EMSA1(SHA-512)"));
		verifier->update((const Botan::byte *)statement.data(), statement.size());
		Botan::SecureVector<Botan::byte> sig;
		sig.set((const Botan::byte *)signature.data(), signature.size());
		return verifier->check_signature(sig);
	}
}
