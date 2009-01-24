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
#include <cstring>
#include <cstdlib>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include <botan/types.h>
#include <botan/botan.h>
#include <botan/ecdsa.h>
#include <botan/look_pk.h>
#include <botan/lookup.h>
#include <botan/filters.h>
#include <botan/sha2_32.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <list>

#include "fides.h"

using namespace std;

// Global state

Botan::LibraryInitializer libinit;
Botan::AutoSeeded_RNG fides::rng;

// Public key functions

fides::publickey::publickey(): pub(0), trust(0) {
}

fides::publickey::~publickey() {
	delete pub;
}

void fides::publickey::load(istream &in) {
	try {
		Botan::DataSource_Stream source(in);
		pub = dynamic_cast<Botan::ECDSA_PublicKey *>(Botan::X509::load_key(source));
	} catch(Botan::Exception &e) {
		throw exception(e.what());
	}
}

void fides::publickey::load(const std::string &filename) {
	ifstream in(filename.c_str());
	load(in);
}

void fides::publickey::save(ostream &out) {
	out << to_string();
}

void fides::publickey::save(const std::string &filename) {
	ofstream out(filename.c_str());
	save(out);
}

void fides::publickey::from_string(const std::string &in) {
	try {
		Botan::DataSource_Memory source(in);
		pub = dynamic_cast<Botan::ECDSA_PublicKey *>(Botan::X509::load_key(source));
	} catch(Botan::Exception &e) {
		throw exception(e.what());
	}
}

string fides::publickey::to_string() {
	return Botan::X509::PEM_encode(*pub);
}

string fides::publickey::fingerprint(unsigned int bits) {
	// TODO: find out if there is a standard way to get a hash of an ECDSA public key
	Botan::SHA_256 sha256;
	Botan::SecureVector<Botan::byte> hash = sha256.process(Botan::X509::PEM_encode(*pub));
	return string((const char *)hash.begin(), bits / 8);
}

bool fides::publickey::verify(const std::string &statement, const std::string &signature) {
	auto_ptr<Botan::PK_Verifier> verifier(Botan::get_pk_verifier(*pub, "EMSA1(SHA-512)"));
	verifier->update((const Botan::byte *)statement.data(), statement.size());
	Botan::SecureVector<Botan::byte> sig;
	sig.set((const Botan::byte *)signature.data(), signature.size());
	return verifier->check_signature(sig);
}

// Private key functions

fides::privatekey::privatekey(): priv(0) {
}

fides::privatekey::~privatekey() {
	delete priv;
	pub = 0;
}

void fides::privatekey::generate(const std::string &field) {
	Botan::EC_Domain_Params domain = Botan::get_EC_Dom_Pars_by_oid(field);
	pub = priv = new Botan::ECDSA_PrivateKey(rng, domain);
}

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

void fides::privatekey::load_private(istream &in) {
	try {
		Botan::DataSource_Stream stream(in);
		pub = priv = dynamic_cast<Botan::ECDSA_PrivateKey *>(Botan::PKCS8::load_key(stream, rng, ""));
	} catch(Botan::Exception &e) {
		throw exception(e.what());
	}
}

void fides::privatekey::load_private(const std::string &filename) {
	ifstream in(filename.c_str());
	load_private(in);
}

void fides::privatekey::save_private(ostream &out) {
	out << Botan::PKCS8::PEM_encode(*priv);
}

void fides::privatekey::save_private(const std::string &filename) {
	ofstream out(filename.c_str());
	save_private(out);
}

string fides::privatekey::sign(const std::string &statement) {
	auto_ptr<Botan::PK_Signer> signer(Botan::get_pk_signer(*priv, "EMSA1(SHA-512)"));
	Botan::SecureVector<Botan::byte> sig = signer->sign_message((const Botan::byte *)statement.data(), statement.size(), rng);
	return string((const char *)sig.begin(), (size_t)sig.size());
}

// Base64 and hex encoding/decoding functions

string fides::hexencode(const string &in) {
	Botan::Pipe pipe(new Botan::Hex_Encoder);
	pipe.process_msg((Botan::byte *)in.data(), in.size());
	return pipe.read_all_as_string();
}

string fides::hexdecode(const string &in) {
	Botan::Pipe pipe(new Botan::Hex_Decoder);
	pipe.process_msg((Botan::byte *)in.data(), in.size());
	return pipe.read_all_as_string();
}

string fides::b64encode(const string &in) {
	Botan::Pipe pipe(new Botan::Base64_Encoder);
	pipe.process_msg((Botan::byte *)in.data(), in.size());
	return pipe.read_all_as_string();
}

string fides::b64decode(const string &in) {
	Botan::Pipe pipe(new Botan::Base64_Decoder);
	pipe.process_msg((Botan::byte *)in.data(), in.size());
	return pipe.read_all_as_string();
}

// Certificate functions

fides::certificate::certificate(publickey *key, struct timeval timestamp, const std::string &statement, const std::string &signature): signer(key), timestamp(timestamp), statement(statement), signature(signature) {}

bool fides::certificate::validate() {
	string data = signer->fingerprint(256);
	data += string((const char *)&timestamp, sizeof timestamp);
	data += statement;
	return signer->verify(data, signature);
}

fides::certificate::certificate(privatekey *key, struct timeval timestamp, const std::string &statement): signer(key), timestamp(timestamp), statement(statement) {
	string data = signer->fingerprint(256);
	data += string((const char *)&timestamp, sizeof timestamp);
	data += statement;
	signature = key->sign(data);
}

string fides::certificate::fingerprint(unsigned int bits) {
	return signature.substr(signature.size() - bits / 8);	
}

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

static vector<string> dirlist(const string &path) {
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

void fides::certificate_save(const certificate *cert, const string &filename) {
	ofstream file(filename.c_str());
	file << cert->to_string() << '\n';
}

fides::certificate *fides::certificate_load(const string &filename) {
	ifstream file(filename.c_str());
	string data;
	getline(file, data);
	return certificate_from_string(data);
}

fides::certificate *fides::certificate_from_string(const string &data) {
	size_t b, e;
	e = data.find(' ', 0);
	if(e == string::npos)
		throw exception("Invalid certificate");
	string fingerprint = hexdecode(data.substr(0, e));
	publickey *signer = find_key(fingerprint);
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

// Fides main functions

fides::fides(const string &dir): homedir(dir) {
	cerr << "Fides initialising\n";

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
		cerr << "Loading key " << files[i] << '\n';

		publickey *key = new publickey();
		key->load(keydir + files[i]);
		keys[hexdecode(files[i])] = key;
	}

	keys[mykey.fingerprint()] = &mykey;

	files = dirlist(certdir);
	for(size_t i = 0; i < files.size(); ++i) {
		cerr << "Loading certificate " << files[i] << '\n';
		certificate *cert = certificate_load(certdir + files[i]);
		if(false && !cert->validate()) {
			cerr << "Bad certificate!\n";
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
	cerr << "Fides exitting\n";
	for(map<string, certificate *>::iterator i = certs.begin(); i != certs.end(); ++i)
		delete i->second;
	for(map<string, publickey *>::iterator i = keys.begin(); i != keys.end(); ++i)
		if(i->second != &mykey)
			delete i->second;
}

bool fides::fsck() {
	int errors = 0;

	for(map<string, certificate *>::iterator i = certs.begin(); i != certs.end(); ++i) {
		if(!i->second->validate()) {
			cerr << "Validation of certificate failed: " << i->second->to_string() << '\n';
			errors++;
		}
	}

	cerr << errors << " errors in " << certs.size() << " certificates\n";
	return !errors;
}

string fides::get_homedir() {
	return homedir;
}

bool fides::is_firstrun() {
	return firstrun;
}

fides::publickey *fides::find_key(const string &fingerprint) {
	map<string, publickey *>::iterator i;
	i = keys.find(fingerprint);
	if(i != keys.end())
		return i->second;
	else
		return 0;
}

vector<fides::certificate *> fides::find_certificates(publickey *signer, const string &regex) {
	vector<certificate *> found;
	map<string, certificate *>::iterator i;
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

vector<fides::certificate *> fides::find_certificates(const string &regex) {
	vector<certificate *> found;
	map<string, certificate *>::iterator i;
	regexp regexp(regex);
	for(i = certs.begin(); i != certs.end(); ++i)
		if(regexp.match(i->second->statement))
			found.push_back(i->second);
	return found;
}

vector<fides::certificate *> fides::find_certificates(publickey *signer) {
	vector<certificate *> found;
	map<string, certificate *>::iterator i;
	for(i = certs.begin(); i != certs.end(); ++i)
		if(i->second->signer == signer)
			found.push_back(i->second);
	return found;
}

void fides::import_all(istream &in) {
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
				cerr << "Imported key " << hexencode(key->fingerprint()) << '\n';
				merge(key);
				is_pem = false;
			} else {
				is_pem = true;
			}
			continue;
		}

		fides::certificate *cert = certificate_from_string(line);
		cerr << "Importing certificate " << hexencode(cert->fingerprint()) << '\n';
		merge(cert);
	}
}

void fides::export_all(ostream &out) {
	for(map<string, publickey *>::iterator i = keys.begin(); i != keys.end(); ++i)
		out << i->second->to_string();
	for(map<string, certificate *>::iterator i = certs.begin(); i != certs.end(); ++i)
		out << i->second->to_string() << '\n';
}

void fides::trust(publickey *key) {
	string full = "t+ " + hexencode(key->fingerprint());
	sign(full);
}

void fides::distrust(publickey *key) {
	string full = "t- " + hexencode(key->fingerprint());
	sign(full);
}

void fides::dctrust(publickey *key) {
	string full = "t0 " + hexencode(key->fingerprint());
	sign(full);
}

void fides::update_trust() {
	// clear trust on all keys
	for(map<string, publickey *>::iterator i = keys.begin(); i != keys.end(); ++i)
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
			cerr << "Trust for key " << hexencode((*i)->fingerprint()) << " set to " << (*i)->trust << '\n';

			// except if this key is not trusted

			if((*i)->trust <= 0)
				continue;

			// find all non-zero trust certificates of this key

			vector<certificate *> matches = find_certificates(*i, "^t[+-] ");

			// update trust value of those keys

			for(size_t j = 0; j < matches.size(); j++) {
				publickey *other = find_key(hexdecode(matches[j]->statement.substr(3)));	

				if(!other) {
					cerr << "Trust certificate for unknown key: " << matches[j]->to_string() << '\n';
					continue;
				}

				// except for keys we already checked

				if(checked.find(other) != checked.end()) {
					cerr << "Skipping trust certificate for already checked key: " << matches[j]->to_string() << '\n';
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

void fides::merge(publickey *key) {
	if(keys.find(key->fingerprint()) != keys.end()) {
		cerr << "Key already known\n";
		return;
	}

	keys[key->fingerprint()] = key;
	key->save(keydir + hexencode(key->fingerprint()));
}

void fides::merge(certificate *cert) {
	// TODO: check if cert is already in database
	// TODO: check if cert obsoletes other certs

	// If we already know this certificate, drop it.
	if(certs.find(cert->fingerprint()) != certs.end()) {
		cerr << "Certificate already known\n";
		return;
	}

	// If the certificate does not validate, drop it.
	if(!cert->validate()) {
		// TODO: this should not happen, be wary of DoS attacks
		cerr << "Certificate invalid\n";
		return;
	}

	// TODO: move these regexps to the class?
	regexp authexp("^a[+0-] ");
	regexp trustexp("^t[+0-] ");
	vector<certificate *> others;

	// Is this an authorisation cert?
	if(authexp.match(cert->statement)) {
		// Find certs identical except for the +/-/0
		// TODO: escape statement in regexp
		others = find_certificates(cert->signer, string("^a[+0-] ") + cert->statement.substr(3) + '$');
		if(others.size()) {
			if(timercmp(&others[0]->timestamp, &cert->timestamp, >)) {
				cerr << "Certificate is overruled by a newer certificate\n";
				return;
			}
			if(timercmp(&others[0]->timestamp, &cert->timestamp, ==)) {
				// TODO: this should not happen, be wary of DoS attacks
				cerr << "Certificate has same timestamp as another timestamp!\n";
				return;
			}
			cerr << "Certificate overrules an older certificate!\n";
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
				cerr << "Certificate is overruled by a newer certificate\n";
				return;
			}
			if(timercmp(&others[0]->timestamp, &cert->timestamp, ==)) {
				// TODO: this should not happen, be wary of DoS attacks
				cerr << "Certificate has same timestamp as another timestamp!\n";
				return;
			}
			cerr << "Certificate overrules an older certificate!\n";
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
			cerr << "Certificate is overruled by a newer certificate\n";
			return;
		}
		if(timercmp(&others[0]->timestamp, &cert->timestamp, ==)) {
			// TODO: this should not happen, be wary of DoS attacks
			cerr << "Certificate has same timestamp as another timestamp!\n";
			return;
		}
		cerr << "Certificate overrules an older certificate!\n";
		// delete old one
		rename((certdir + hexencode(others[0]->fingerprint())).c_str(), (obsoletedir + hexencode(others[0]->fingerprint())).c_str());
		certs.erase(others[0]->fingerprint());
		delete others[0];
		certs[cert->fingerprint()] = cert;
		certificate_save(cert, certdir + hexencode(cert->fingerprint()));
		return;
	}

	cerr << "Certificate is new\n";
	certs[cert->fingerprint()] = cert;
	certificate_save(cert, certdir + hexencode(cert->fingerprint()));
}

void fides::auth_stats(const string &statement, int &self, int &trusted, int &all) {
	self = trusted = all = 0;
	vector<certificate *> matches = find_certificates(string("^a[+0-] ") + statement + '$');
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

bool fides::is_trusted(publickey *key) {
	return key->trust > 0;
}

bool fides::is_distrusted(publickey *key) {
	return key->trust < 0;
}

bool fides::is_allowed(const string &statement, publickey *key) {
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

bool fides::is_denied(const string &statement, publickey *key) {
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

void fides::sign(const string &statement) {
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

void fides::allow(const string &statement, publickey *key) {
	string full = "a+ ";
	if(key)
		full += hexencode(key->fingerprint()) + ' ';
	full += statement;
	sign(full);
}

void fides::dontcare(const string &statement, publickey *key) {
	string full = "a0 ";
	if(key)
		full += hexencode(key->fingerprint()) + ' ';
	full += statement;
	sign(full);
}

void fides::deny(const string &statement, publickey *key) {
	string full = "a- ";
	if(key)
		full += hexencode(key->fingerprint()) + ' ';
	full += statement;
	sign(full);
}

