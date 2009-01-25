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
#include <cstdlib>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <botan/types.h>
#include <botan/botan.h>
#include <botan/ecdsa.h>
#include <botan/look_pk.h>
#include <botan/lookup.h>
#include <botan/filters.h>
#include <botan/sha2_32.h>
#include <list>

#include "fides.h"

#ifndef FIDES_DEBUG
#define FIDES_DEBUG false
#endif

#define debug if(FIDES_DEBUG)

using namespace std;

// Global state

Botan::AutoSeeded_RNG fides::rng;

/// \class fides::publickey
///
/// \brief Representation of a public key.
///
/// A public key is the counterpart of a private key that is held by some entity.
/// If we have a public key, we can verify signatures made by the corresponding private key.
/// Thus, we can ascertain if a statement, if it has been properly signed,
/// was indeed made by that entity.

fides::publickey::publickey(): pub(0), trust(0) {
}

fides::publickey::~publickey() {
	delete pub;
}

/// Loads a public key from a stream.
//
/// @param in Stream to read from.
void fides::publickey::load(std::istream &in) {
	try {
		Botan::DataSource_Stream source(in);
		pub = dynamic_cast<Botan::ECDSA_PublicKey *>(Botan::X509::load_key(source));
	} catch(Botan::Exception &e) {
		throw exception(e.what());
	}
}

/// Loads a public key from a file.
//
/// @param filename Name of the file to read the key from.
void fides::publickey::load(const std::string &filename) {
	ifstream in(filename.c_str());
	load(in);
}

/// Saves the public key to a stream.
//
/// @param out Stream to write to.
void fides::publickey::save(std::ostream &out) const {
	out << to_string();
}

/// Saves the public key to a file.
//
/// @param filename Name of the file to save the key to.
void fides::publickey::save(const std::string &filename) const {
	ofstream out(filename.c_str());
	save(out);
}

/// Loads a public key from a string.
//
/// @param in String containing a public key in textual format.
void fides::publickey::from_string(const std::string &in) {
	try {
		Botan::DataSource_Memory source(in);
		pub = dynamic_cast<Botan::ECDSA_PublicKey *>(Botan::X509::load_key(source));
	} catch(Botan::Exception &e) {
		throw exception(e.what());
	}
}

/// Write the public key to a string.
//
/// @return String containing the public key in textual format.
string fides::publickey::to_string() const {
	return Botan::X509::PEM_encode(*pub);
}

/// Get the fingerprint of the public key.
//
/// @param bits Number of bits from the fingerprint to return.
///             The number will be rounded down to the nearest multiple of 8.
/// @return String containing the fingerprint.
string fides::publickey::fingerprint(unsigned int bits) const {
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
bool fides::publickey::verify(const std::string &statement, const std::string &signature) const {
	auto_ptr<Botan::PK_Verifier> verifier(Botan::get_pk_verifier(*pub, "EMSA1(SHA-512)"));
	verifier->update((const Botan::byte *)statement.data(), statement.size());
	Botan::SecureVector<Botan::byte> sig;
	sig.set((const Botan::byte *)signature.data(), signature.size());
	return verifier->check_signature(sig);
}

/// \class fides::privatekey
///
/// \brief Representation of a public/private keypair.
///
/// With a private key we can create a signature of a statement,
/// so that others who have the corresponding public key
/// can ascertain that the statement was really made by us.

fides::privatekey::privatekey(): priv(0) {
}

fides::privatekey::~privatekey() {
	delete priv;
	pub = 0;
}

/// Generates a new public/private keypair.
//
/// @param field OID of the field to generate a key in.
void fides::privatekey::generate(const std::string &field) {
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
void fides::privatekey::generate(unsigned int bits) {
	switch(bits) {
		case 112: return generate("1.3.132.0.6");
		case 128: return generate("1.3.132.0.28");
		case 160: return generate("1.3.132.0.9");
		case 192: return generate("1.3.132.0.31");
		case 224: return generate("1.3.132.0.32");
		case 256: return generate("1.3.132.0.10");
		case 384: return generate("1.3.132.0.34");
		case 521: return generate("1.3.132.0.35");
		default: throw exception("Unsupported number of bits for private key");
	}
}

/// Loads a private key from a stream.
//
/// @param in Stream to read from.
void fides::privatekey::load_private(std::istream &in) {
	try {
		Botan::DataSource_Stream stream(in);
		pub = priv = dynamic_cast<Botan::ECDSA_PrivateKey *>(Botan::PKCS8::load_key(stream, rng, ""));
	} catch(Botan::Exception &e) {
		throw exception(e.what());
	}
}

/// Loads a private key from a file.
//
/// @param filename Name of the file to read from.
void fides::privatekey::load_private(const std::string &filename) {
	ifstream in(filename.c_str());
	load_private(in);
}

/// Saves the private key to a stream.
//
/// @param out Stream to write to.
void fides::privatekey::save_private(std::ostream &out) const {
	out << Botan::PKCS8::PEM_encode(*priv);
}

/// Saves the private key to a file.
//
/// @param filename Name of the file to write to.
void fides::privatekey::save_private(const std::string &filename) const {
	ofstream out(filename.c_str());
	save_private(out);
}

/// Signs a statement with this private key.
//
/// @param statement The statement that is to be signed.
/// @return A string containing the signature.
string fides::privatekey::sign(const std::string &statement) const {
	auto_ptr<Botan::PK_Signer> signer(Botan::get_pk_signer(*priv, "EMSA1(SHA-512)"));
	Botan::SecureVector<Botan::byte> sig = signer->sign_message((const Botan::byte *)statement.data(), statement.size(), rng);
	return string((const char *)sig.begin(), (size_t)sig.size());
}

// Base64 and hex encoding/decoding functions

/// Hexadecimal encode data.
//
/// @param in A string containing raw data.
/// @return A string containing the hexadecimal encoded data.
string fides::hexencode(const std::string &in) {
	Botan::Pipe pipe(new Botan::Hex_Encoder);
	pipe.process_msg((Botan::byte *)in.data(), in.size());
	return pipe.read_all_as_string();
}

/// Decode hexadecimal data.
//
/// @param in A string containing hexadecimal encoded data.
/// @return A string containing the raw data.
string fides::hexdecode(const std::string &in) {
	Botan::Pipe pipe(new Botan::Hex_Decoder);
	pipe.process_msg((Botan::byte *)in.data(), in.size());
	return pipe.read_all_as_string();
}

/// Base-64 encode data.
//
/// @param in A string containing raw data.
/// @return A string containing the base-64 encoded data.
string fides::b64encode(const std::string &in) {
	Botan::Pipe pipe(new Botan::Base64_Encoder);
	pipe.process_msg((Botan::byte *)in.data(), in.size());
	return pipe.read_all_as_string();
}

/// Decode base-64 data.
//
/// @param in A string containing base-64 encoded data.
/// @return A string containing the raw data.
string fides::b64decode(const std::string &in) {
	Botan::Pipe pipe(new Botan::Base64_Decoder);
	pipe.process_msg((Botan::byte *)in.data(), in.size());
	return pipe.read_all_as_string();
}

/// \class fides::certificate
///
/// \brief Representation of a certificate.

/// Construct a certificate from elements of an already existing certificate.
//
/// @param key        Public key used to sign the certificate.
/// @param timestamp  Timestamp of the certificate.
/// @param statement  Statement of the certificate.
/// @param signature  Signature of the certificate.
fides::certificate::certificate(const publickey *key, struct timeval timestamp, const std::string &statement, const std::string &signature): signer(key), timestamp(timestamp), statement(statement), signature(signature) {}

/// Verifies the signature of the certificate.
//
/// @return True if the signature is valid, false otherwise.
bool fides::certificate::validate() const {
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
fides::certificate::certificate(const privatekey *key, struct timeval timestamp, const std::string &statement): signer(key), timestamp(timestamp), statement(statement) {
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
string fides::certificate::fingerprint(unsigned int bits) const {
	return signature.substr(signature.size() - bits / 8);	
}

/// Write the certificate to a string.
//
/// @return String containing the certificate in textual format.
string fides::certificate::to_string() const {
	string data = fides::hexencode(signer->fingerprint());
	data += ' ';
	char ts[100];
	snprintf(ts, sizeof ts, "%lu.%06lu", timestamp.tv_sec, timestamp.tv_usec);
	data += ts;
	data += ' ';
	data += fides::b64encode(signature);
	data += ' ';
	data += statement;
	return data;
}

// Utility functions

/// Return the names of all the files in a directory.
//
/// @param path Directory to search for files.
/// @return A vector of strings with the name of each file in the directory.
///         The filename does not contain the leading path.
static vector<string> dirlist(const std::string &path) {
	vector<string> files;

	DIR *dir = opendir(path.c_str());
	if(!dir)
		return files;

	struct dirent entry, *result = &entry;
	
	while(result) {
		readdir_r(dir, &entry, &result);
		if(!result)
			break;
		struct stat st;
		if(result->d_type == DT_UNKNOWN) {
			if(stat((path + "/" + result->d_name).c_str(), &st))
				continue;
			if(S_ISREG(st.st_mode))
				files.push_back(result->d_name);
		} else if(result->d_type == DT_REG) {
			files.push_back(result->d_name);
		}
	}

	closedir(dir);

	return files;
}

/// Saves a certificate to a file.
//
/// @param cert      Certificate to save.
/// @param filename  File to save the certificate to.
void fides::certificate_save(const certificate *cert, const std::string &filename) const {
	ofstream file(filename.c_str());
	file << cert->to_string() << '\n';
}

/// Loads a certificate from a file.
//
/// @param filename  File to save the certificate to.
/// @return          The certificate.
fides::certificate *fides::certificate_load(const std::string &filename) {
	ifstream file(filename.c_str());
	string data;
	getline(file, data);
	return certificate_from_string(data);
}

/// Loads a certificate from a string.
//
/// @param data  String containing the certificate in textual form.
/// @return      The certificate.
fides::certificate *fides::certificate_from_string(const std::string &data) {
	size_t b, e;
	e = data.find(' ', 0);
	if(e == string::npos)
		throw exception("Invalid certificate");
	string fingerprint = hexdecode(data.substr(0, e));
	const publickey *signer = find_key(fingerprint);
	if(!signer)
		throw exception("Unknown public key");
	b = e + 1;
	e = data.find('.', b);
	if(e == string::npos)
		throw exception("Invalid certificate");
	struct timeval timestamp;
	timestamp.tv_sec = atol(data.c_str() + b);
	b = e + 1;
	timestamp.tv_usec = atol(data.c_str() + b);
	e = data.find(' ', b);
	if(e == string::npos)
		throw exception("Invalid certificate");
	b = e + 1;
	e = data.find(' ', b);
	if(e == string::npos)
		throw exception("Invalid certificate");
	string signature = fides::b64decode(data.substr(b, e - b));
	b = e + 1;
	string statement = data.substr(b);

	return new certificate(signer, timestamp, statement, signature);
}

/// \class fides
///
/// \brief Interaction with a Fides database.
///
/// A fides object manages a database of public keys and certificates.
/// New certificates can be created, certificates can be imported and exported,
/// and queries can be done on the database.


/// Creates a new handle on a Fides database.
//
/// Will load the private key, known public keys and certificates.
/// After that it will calculate the trust value of all keys.
///
/// @param dir Directory where Fides stores the keys and certificates.
///            If no directory is specified, the following environment variables
///            are used, in the given order:
///            - \$FIDES_HOME
///            - \$HOME/.fides
///            - \$WPD/.fides
fides::fides(const std::string &dir): homedir(dir) {
	debug cerr << "Fides initialising\n";

	// Set homedir to provided directory, or $FIDES_HOME, or $HOME/.fides, or as a last resort $PWD/.fides
	if(homedir.empty())
		homedir = getenv("FIDES_HOME") ?: "";
	if(homedir.empty()) {
		char cwd[PATH_MAX];
		homedir = getenv("HOME") ?: getcwd(cwd, sizeof cwd);
		homedir += "/.fides";
	}

	// Derived directories
	homedir += '/';
	certdir = homedir + "certs/";
	keydir = homedir + "keys/";
	obsoletedir = homedir + ".obsolete_certs/";

	// Ensure the homedir and its subdirectories exist
	mkdir(homedir.c_str(), 0700);
	mkdir(certdir.c_str(), 0700);
	mkdir(keydir.c_str(), 0700);
	mkdir(obsoletedir.c_str(), 0700);

	try {
		mykey.load_private(homedir + "priv");
		firstrun = false;
	} catch(fides::exception &e) {
		cerr << "Fides generating keypair\n";
		mykey.generate();
		mykey.save_private(homedir + "priv");
		mykey.save(keydir + hexencode(mykey.fingerprint()));
		firstrun = true;
	}
	vector<string> files = dirlist(keydir);
	for(size_t i = 0; i < files.size(); ++i) {
		debug cerr << "Loading key " << files[i] << '\n';

		publickey *key = new publickey();
		key->load(keydir + files[i]);
		keys[hexdecode(files[i])] = key;
	}

	keys[mykey.fingerprint()] = &mykey;

	files = dirlist(certdir);
	for(size_t i = 0; i < files.size(); ++i) {
		debug cerr << "Loading certificate " << files[i] << '\n';
		certificate *cert = certificate_load(certdir + files[i]);
		if(false && !cert->validate()) {
			cerr << "Bad certificate in database: " << cert->to_string() << '\n';
			continue;
		}
		certs[hexdecode(files[i])] = cert;
	}

	// TODO: save and load this value
	latest.tv_sec = 0;
	latest.tv_usec = 0;

	update_trust();
}

fides::~fides() {
	debug cerr << "Fides exitting\n";
	for(map<string, certificate *>::const_iterator i = certs.begin(); i != certs.end(); ++i)
		delete i->second;
	for(map<string, publickey *>::const_iterator i = keys.begin(); i != keys.end(); ++i)
		if(i->second != &mykey)
			delete i->second;
}

/// Checks the validaty of all certificates.
//
/// @return True if all known certificates are valid, false otherwise.
bool fides::fsck() const {
	int errors = 0;

	for(map<string, certificate *>::const_iterator i = certs.begin(); i != certs.end(); ++i) {
		if(!i->second->validate()) {
			cerr << "Validation of certificate failed: " << i->second->to_string() << '\n';
			errors++;
		}
	}

	cerr << errors << " errors in " << certs.size() << " certificates\n";
	return !errors;
}

/// Returns the base directory used by Fides.
//
/// @return The home directory.
string fides::get_homedir() const {
	return homedir;
}

/// Tests whether this is the first time Fides has run and has generated new keys.
//
/// @return True if this is the first time, false otherwise.
bool fides::is_firstrun() const {
	return firstrun;
}

/// Find the public key corresponding to a given fingerprint.
//
/// @param fingerprint String containing a fingerprint.
/// @return Pointer to the public key corresponding to the fingerprint, or NULL if it was not found.
fides::publickey *fides::find_key(const std::string &fingerprint) const {
	map<string, publickey *>::const_iterator i;
	i = keys.find(fingerprint);
	if(i != keys.end())
		return i->second;
	else
		return 0;
}

/// Find all certificates from a give public key and that match a regular expression.
//
/// @param signer Public key to match certificates to.
/// @param regex  Regular expression to match the statement of each certificate to.
/// @return A vector of certificates that match the criteria.
vector<const fides::certificate *> fides::find_certificates(const publickey *signer, const std::string &regex) const {
	vector<const certificate *> found;
	map<string, certificate *>::const_iterator i;
	regexp regexp(regex);
	for(i = certs.begin(); i != certs.end(); ++i) {
		if(!i->second) {
			cerr << "No certificate for " << hexencode(i->first) << '\n';
			continue;
		}
		if(i->second->signer == signer)
			if(regexp.match(i->second->statement))
				found.push_back(i->second);
	}
	return found;
}

/// Find all certificates that match a regular expression.
//
/// @param regex  Regular expression to match the statement of each certificate to.
/// @return A vector of certificates that match the criteria.
vector<const fides::certificate *> fides::find_certificates(const std::string &regex) const {
	vector<const certificate *> found;
	map<string, certificate *>::const_iterator i;
	regexp regexp(regex);
	for(i = certs.begin(); i != certs.end(); ++i)
		if(regexp.match(i->second->statement))
			found.push_back(i->second);
	return found;
}

/// Find all certificates from a give public key.
//
/// @param signer Public key to match certificates to.
/// @return A vector of certificates that match the criteria.
vector<const fides::certificate *> fides::find_certificates(const publickey *signer) const {
	vector<const certificate *> found;
	map<string, certificate *>::const_iterator i;
	for(i = certs.begin(); i != certs.end(); ++i)
		if(i->second->signer == signer)
			found.push_back(i->second);
	return found;
}

/// Import public keys and certificates from a stream.
//
/// @param in Stream to read from.
void fides::import_all(std::istream &in) {
	string line, pem;
	bool is_pem = false;

	while(getline(in, line)) {
		if(line.empty())
			continue;

		if(is_pem || !line.compare(0, 11, "-----BEGIN ")) {
			pem += line + '\n';
			if(!line.compare(0, 9, "-----END ")) {
				fides::publickey *key = new publickey();
				key->from_string(pem);
				debug cerr << "Imported key " << hexencode(key->fingerprint()) << '\n';
				merge(key);
				is_pem = false;
			} else {
				is_pem = true;
			}
			continue;
		}

		fides::certificate *cert = certificate_from_string(line);
		debug cerr << "Importing certificate " << hexencode(cert->fingerprint()) << '\n';
		merge(cert);
	}
}

/// Export all public keys and certificates to a stream.
//
/// @param out Stream to write to.
void fides::export_all(std::ostream &out) const {
	for(map<string, publickey *>::const_iterator i = keys.begin(); i != keys.end(); ++i)
		out << i->second->to_string();
	for(map<string, certificate *>::const_iterator i = certs.begin(); i != certs.end(); ++i)
		out << i->second->to_string() << '\n';
}

/// Trust a public key.
//
/// This creates a certificate that says that we trust the given public key.
/// If a key is trusted, then authorisation certificates from that key are taken into account
/// when calling functions such as fides::is_allowed().
///
/// @param key Public key to trust.
void fides::trust(const publickey *key) {
	string full = "t+ " + hexencode(key->fingerprint());
	sign(full);
}

/// Distrust a public key.
//
/// This creates a certificate that says that we distrust the given public key.
/// If a key is distrusted, then authorisation certificates from that key are not taken into account
/// when calling functions such as fides::is_allowed().
///
/// @param key Public key to trust.
void fides::distrust(const publickey *key) {
	string full = "t- " + hexencode(key->fingerprint());
	sign(full);
}

/// Don't care about a public key.
//
/// This creates a certificate that says that we neither trust nor distrust the given public key.
/// This key and certificates created by it are then treated as if we have never trusted nor distrusted this key.
///
/// @param key Public key to trust.
void fides::dctrust(const publickey *key) {
	string full = "t0 " + hexencode(key->fingerprint());
	sign(full);
}

/// Recalculate the trust value of all known public keys.
void fides::update_trust() {
	// clear trust on all keys
	for(map<string, publickey *>::const_iterator i = keys.begin(); i != keys.end(); ++i)
		i->second->trust = 0;

	// Start by checking all trust certificates from ourself.
	// If another key is positively or negatively trusted, update its trust score
	// and add it to the the list of new keys to check.
	// Then add our own key to the list of already checked keys.
	// Then check all the trust certificates of those on the tocheck list, etc.
	// Already checked keys are never updated anymore (TODO: is that smart?)
	// Certificates of keys with a zero or negative trust score are not processed.

	set<publickey *> checked;
	set<publickey *> tocheck;
	set<publickey *> newkeys;
	set<publickey *>::iterator i;

	mykey.trust = 3;
	tocheck.insert(&mykey);

	while(tocheck.size()) {
		// add
		checked.insert(tocheck.begin(), tocheck.end());
		newkeys.clear();

		// loop over all keys whose certificates need to be checked

		for(i = tocheck.begin(); i != tocheck.end(); ++i) {
			debug cerr << "Trust for key " << hexencode((*i)->fingerprint()) << " set to " << (*i)->trust << '\n';

			// except if this key is not trusted

			if((*i)->trust <= 0)
				continue;

			// find all non-zero trust certificates of this key

			vector<const certificate *> matches = find_certificates(*i, "^t[+-] ");

			// update trust value of those keys

			for(size_t j = 0; j < matches.size(); j++) {
				publickey *other = find_key(hexdecode(matches[j]->statement.substr(3)));	

				if(!other) {
					cerr << "Trust certificate for unknown key: " << matches[j]->to_string() << '\n';
					continue;
				}

				// except for keys we already checked

				if(checked.find(other) != checked.end()) {
					debug cerr << "Skipping trust certificate for already checked key: " << matches[j]->to_string() << '\n';
					continue;
				}

				// update trust

				if(matches[j]->statement[1] == '+')
					other->trust++;
				else
					other->trust--;

				newkeys.insert(other);
			}
		}

		tocheck = newkeys;
	}	
}	

/// Merges a public key into the database.
//
/// @param key The public key to merge.
void fides::merge(publickey *key) {
	if(keys.find(key->fingerprint()) != keys.end()) {
		debug cerr << "Key already known\n";
		return;
	}

	keys[key->fingerprint()] = key;
	key->save(keydir + hexencode(key->fingerprint()));
}

/// Merges a certificate into the database.
//
/// The database is searched to find if there are certificates from the same signer
/// with similar statements.
/// If the given certificate is similar to another one in our database,
/// then the certificate with the newer timestamp wins and will be allowed in the database,
/// the older certificate will be removed.
///
/// @param cert The certificate to merge.
void fides::merge(certificate *cert) {
	// TODO: check if cert is already in database
	// TODO: check if cert obsoletes other certs

	// If we already know this certificate, drop it.
	if(certs.find(cert->fingerprint()) != certs.end()) {
		debug cerr << "Certificate already known\n";
		return;
	}

	// If the certificate does not validate, drop it.
	if(!cert->validate()) {
		// TODO: this should not happen, be wary of DoS attacks
		cerr << "Trying to merge invalid certificate: " << cert->to_string() << '\n';
		return;
	}

	// TODO: move these regexps to the class?
	regexp authexp("^a[+0-] ");
	regexp trustexp("^t[+0-] ");
	vector<const certificate *> others;

	// Is this an authorisation cert?
	if(authexp.match(cert->statement)) {
		// Find certs identical except for the +/-/0
		// TODO: escape statement in regexp
		others = find_certificates(cert->signer, string("^a[+0-] ") + cert->statement.substr(3) + '$');
		if(others.size()) {
			if(timercmp(&others[0]->timestamp, &cert->timestamp, >)) {
				debug cerr << "Certificate is overruled by a newer certificate\n";
				return;
			}
			if(timercmp(&others[0]->timestamp, &cert->timestamp, ==)) {
				// TODO: this should not happen, be wary of DoS attacks
				debug cerr << "Certificate has same timestamp as another timestamp!\n";
				return;
			}
			debug cerr << "Certificate overrules an older certificate!\n";
			// save new cert first
			certificate_save(cert, certdir + hexencode(cert->fingerprint()));
			certs[cert->fingerprint()] = cert;

			// delete old one
			rename((certdir + hexencode(others[0]->fingerprint())).c_str(), (obsoletedir + hexencode(others[0]->fingerprint())).c_str());
			certs.erase(others[0]->fingerprint());
			delete others[0];
			return;
		}
	}

	// Is this a trust cert?
	// TODO: it's just the same as above!
	if(trustexp.match(cert->statement)) {
		// Find certs identical except for the +/-/0
		// TODO: escape statement in regexp
		others = find_certificates(cert->signer, string("^t[+0-] ") + cert->statement.substr(3) + '$');
		if(others.size()) {
			if(timercmp(&others[0]->timestamp, &cert->timestamp, >)) {
				debug cerr << "Certificate is overruled by a newer certificate\n";
				return;
			}
			if(timercmp(&others[0]->timestamp, &cert->timestamp, ==)) {
				// TODO: this should not happen, be wary of DoS attacks
				debug cerr << "Certificate has same timestamp as another timestamp!\n";
				return;
			}
			debug cerr << "Certificate overrules an older certificate!\n";
			// delete old one
			rename((certdir + hexencode(others[0]->fingerprint())).c_str(), (obsoletedir + hexencode(others[0]->fingerprint())).c_str());
			certs.erase(others[0]->fingerprint());
			delete others[0];
			certs[cert->fingerprint()] = cert;
			certificate_save(cert, certdir + hexencode(cert->fingerprint()));
			return;
		}
	}

	// Did somebody sign the exact same statement twice?
	// Could happen if there is a different, conflicting statement between this new and the corresponding old one.
	others = find_certificates(cert->signer, string("^") + cert->statement + '$');
	if(others.size()) {
		if(timercmp(&others[0]->timestamp, &cert->timestamp, >)) {
			debug cerr << "Certificate is overruled by a newer certificate\n";
			return;
		}
		if(timercmp(&others[0]->timestamp, &cert->timestamp, ==)) {
			// TODO: this should not happen, be wary of DoS attacks
			debug cerr << "Certificate has same timestamp as another timestamp!\n";
			return;
		}
		debug cerr << "Certificate overrules an older certificate!\n";
		// delete old one
		rename((certdir + hexencode(others[0]->fingerprint())).c_str(), (obsoletedir + hexencode(others[0]->fingerprint())).c_str());
		certs.erase(others[0]->fingerprint());
		delete others[0];
		certs[cert->fingerprint()] = cert;
		certificate_save(cert, certdir + hexencode(cert->fingerprint()));
		return;
	}

	debug cerr << "Certificate is new\n";
	certs[cert->fingerprint()] = cert;
	certificate_save(cert, certdir + hexencode(cert->fingerprint()));
}

/// Calculates whether a statement is allowed or denied.
//
/// @param statement The statement to calculate the authorisation values for.
/// @param self      Will be set to 1 if we allow the statement,
///                  0 if we neither allowed nor denied it,
///                  or -1 if we denied it.
/// @param trusted   Will be positive if the majority of the trusted public keys
///                  gave a positive authorisation, 0 if there is a tie,
///                  or negative if the majority gave a negative authorisation.
/// @param all       Same as trusted but for all public keys.
void fides::auth_stats(const std::string &statement, int &self, int &trusted, int &all) const {
	self = trusted = all = 0;
	vector<const certificate *> matches = find_certificates(string("^a[+0-] ") + statement + '$');
	for(size_t i = 0; i < matches.size(); ++i) {
		char code = matches[i]->statement[1];
		int diff = 0;
		if(code == '+')
			diff = 1;
		else if(code == '-')
			diff = -1;
		if(matches[i]->signer == &mykey)
			self += diff;
		if(matches[i]->signer->trust > 0)
			trusted += diff;
		all += diff;
	}
}

/// Tests whether the given public key is trusted.
//
/// @param key The public key to test.
/// @return True if the key is explicitly trusted, false otherwise.
bool fides::is_trusted(const publickey *key) const {
	return key->trust > 0;
}

/// Tests whether the given public key is distrusted.
//
/// @param key The public key to test.
/// @return True if the key is explicitly distrusted, false otherwise.
bool fides::is_distrusted(const publickey *key) const {
	return key->trust < 0;
}

/// Tests whether the given statement is allowed.
//
/// @param statement The statement to test.
/// @param key       The public key to test.
/// @return True if the statement is allowed for the given key, false otherwise.
bool fides::is_allowed(const std::string &statement, const publickey *key) const {
	int self, trusted, all;

	if(key)
		auth_stats(hexencode(key->fingerprint()) + " " + statement, self, trusted, all);
	else
		auth_stats(statement, self, trusted, all);
		
	if(self)
		return self > 0;
	else if(trusted)
		return trusted > 0;
	else
		return false;
}

/// Tests whether the given statement is denied.
//
/// @param statement The statement to test.
/// @param key       The public key to test.
/// @return True if the statement is denied for the given key, false otherwise.
bool fides::is_denied(const std::string &statement, const publickey *key) const {
	int self, trusted, all;

	if(key)
		auth_stats(hexencode(key->fingerprint()) + " " + statement, self, trusted, all);
	else
		auth_stats(statement, self, trusted, all);

	if(self)
		return self < 0;
	else if(trusted)
		return trusted < 0;
	else
		return false;
}

/// Creates a certificate for the given statement.
//
/// @param statement The statement to create a certificate for.
void fides::sign(const std::string &statement) {
	// Try to set "latest" to now, but ensure monoticity
	struct timeval now;
	gettimeofday(&now, 0);
	if(timercmp(&latest, &now, >=)) {
		latest.tv_usec++;
		if(latest.tv_usec >= 1000000) {
			latest.tv_sec++;
			latest.tv_usec -= 1000000;
		}
	} else {
		latest = now;
	}

	// Create a new certificate and merge it with our database
	merge(new certificate(&mykey, latest, statement));
}

void fides::allow(const std::string &statement, const publickey *key) {
	string full = "a+ ";
	if(key)
		full += hexencode(key->fingerprint()) + ' ';
	full += statement;
	sign(full);
}

void fides::dontcare(const std::string &statement, const publickey *key) {
	string full = "a0 ";
	if(key)
		full += hexencode(key->fingerprint()) + ' ';
	full += statement;
	sign(full);
}

void fides::deny(const std::string &statement, const publickey *key) {
	string full = "a- ";
	if(key)
		full += hexencode(key->fingerprint()) + ' ';
	full += statement;
	sign(full);
}

