/* fides.cc - Light-weight, decentralised trust and authorisation management
   Copyright (C) 2008-2009  Guus Sliepen <guus@tinc-vpn.org>
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include <getopt.h>
#include <sysexits.h>
#include <iostream>
#include <fstream>

#include "fides.h"

using namespace std;

static void help(ostream &out, const string &argv0) {
	out << "Usage: " << argv0 << "<command> [arguments]\n"
	"\n"
	"Available commands are:\n"
	"\n"
	"  init      Initialise fides, generate a public/private keypair.\n"
	"  version   Show version and copyright information.\n"
	"  help      Show this help message.\n"
	"\n"
	"  trust <keyid>\n"
	"            Trust allow/deny packets signed by the specified key.\n"
	"  distrust <keyid>\n"
	"            Distrust allow/deny packets signed by the specified key.\n"
	"  dctrust <keyid>\n"
	"            Don't care about allow/deny packets signed by the specified key.\n"
	"  is_trusted <keyid>\n"
	"            Returns 0 if key is trusted, 1 otherwise\n"
	"  is_distrusted <keyid>\n"
	"            Returns 0 if key is distrusted, 1 otherwise\n"
	"\n"
	"  sign <stuff ...>\n"
	"            Sign stuff.\n"
	"  allow <stuff ...>\n"
	"            Allow stuff.\n"
	"  deny <stuff ...> \n"
	"            Deny stuff.\n"
	"  dontcare <stuff ...> \n"
	"            Don't care about stuff.\n"
	"  is_allowed <stuff ...>\n"
	"            Returns 0 if stuff is allowed, 1 otherwise\n"
	"  is_denied <stuff ...>\n"
	"            Returns 0 if stuff is denied, 1 otherwise\n"
	"\n"
	"  import [filename]\n"
	"            Import keys and certificates from file, or stdin if unspecified.\n"
	"  export [filename]\n"
	"            Export keys and certificates to file, or stdout if unspecified.\n"
	"  test <stuff ...>\n"
	"            Tell whether stuff is allowed or not by counting relevant certificates\n"
	"  find <regexp>\n"
	"            Find all certificates matching regexp\n"
	"  fsck      Verify the signature on all information collected.\n";
}

static void version(ostream &out = cout) {
	out << "fides version 0.1\n"
	"Copyright (c) 2008-2009 Guus Sliepen <guus@tinc-vpn.org>\n"
	"\n"
	"This program is free software; you can redistribute it and/or modify\n"
	"it under the terms of the GNU General Public License as published by\n"
	"the Free Software Foundation; either version 2 of the License, or\n"
	"(at your option) any later version.\n";
}

static int init() {
	Fides::Manager fides;
	if(fides.is_firstrun()) {
		cout << "New keys generated in " << fides.get_homedir() << '\n';
	} else {
		cout << "Fides already initialised\n";
	}
	return 0;
}

static int is_trusted(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	Fides::PublicKey *key = fides.find_key(Fides::hexdecode(argv[0]));
	if(!key) {
		cerr << "Unknown key!\n";
		return 1;
	}
	return fides.is_trusted(key) ? 0 : 1;
}

static int is_distrusted(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	Fides::PublicKey *key = fides.find_key(Fides::hexdecode(argv[0]));
	if(!key) {
		cerr << "Unknown key!\n";
		return 1;
	}
	return fides.is_distrusted(key) ? 0 : 1;
}

static int trust(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	Fides::PublicKey *key = fides.find_key(Fides::hexdecode(argv[0]));
	if(key)
		fides.trust(key);
	else {
		cerr << "Unknown key!\n";
		return -1;
	}
	return 0;
}

static int dctrust(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	Fides::PublicKey *key = fides.find_key(Fides::hexdecode(argv[0]));
	if(key)
		fides.dctrust(key);
	else {
		cerr << "Unknown key!\n";
		return -1;
	}
	return 0;
}

static int distrust(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	Fides::PublicKey *key = fides.find_key(Fides::hexdecode(argv[0]));
	if(key)
		fides.distrust(key);
	else {
		cerr << "Unknown key!\n";
		return -1;
	}
	return 0;
}

static int sign(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	fides.sign(argv[0]);
	return 0;
}

static int allow(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	fides.allow(argv[0]);
	return 0;
}

static int dontcare(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	fides.dontcare(argv[0]);
	return 0;
}

static int deny(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	fides.deny(argv[0]);
	return 0;
}

static int import(int argc, char *const argv[]) {
	Fides::Manager fides;
	
	if(argc) {
		ifstream in(argv[0]);
		fides.import_all(in);
	} else
		fides.import_all(cin);
	return 0;
}

static int exprt(int argc, char *const argv[]) {
	Fides::Manager fides;

	if(argc) {
		ofstream out(argv[0]);
		fides.export_all(out);
	} else
		fides.export_all(cout);
	return 0;
}

static int find(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	// Find certificates matching statement
	Fides::Manager fides;
	const vector<const Fides::Certificate *> &certs = fides.find_certificates(argv[0]);
	for(size_t i = 0; i < certs.size(); ++i)
		cout << i << ' ' << certs[i]->to_string() << '\n';
	return 0;
}

static int is_allowed(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	return fides.is_allowed(argv[0]) ? 0 : 1;
}

static int is_denied(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	return fides.is_denied(argv[0]) ? 0 : 1;
}

static int test(int argc, char *const argv[]) {
	if(argc < 1)
		return EX_USAGE;

	Fides::Manager fides;
	int self, trusted, all;
	fides.auth_stats(argv[0], self, trusted, all);
	cout << "Self: " << self << ", trusted: " << trusted << ", all: " << all << '\n';
	return 0;
}

static int fsck() {
	Fides::Manager fides;
	if(fides.fsck()) {
		cout << "Everything OK\n";
		return 0;
	} else {
		cout << "Integrity failure!\n";
		return 1;
	}
}

int main(int argc, char *const argv[]) {
	int r;
	int option_index;

	static struct option const long_options[] = {
		{"homedir", required_argument, NULL, 2},
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 3},
		{NULL, 0, NULL, 0}
	};

        while((r = getopt_long(argc, argv, "h", long_options, &option_index)) != EOF) {
                switch (r) {
                        case 0:                         /* long option */
                                break;
			case 1:				/* non-option */
				break;
			case 2:
				//homedir = strdup(optarg);
				break;
			case 3:
				version();
				return 0;
			case 'h':
				help(cout, argv[0]);
				return 0;
		}
	}

	if(argc < 2) {
		help(cerr, argv[0]);
		return EX_USAGE;
	}

	if(!strcmp(argv[1], "help")) {
		help(cout, argv[0]);
		return 0;
	}

	if(!strcmp(argv[1], "version")) {
		version();
		return 0;
	}

	if(!strcmp(argv[1], "init"))
		return init();

	if(!strcmp(argv[1], "trust"))
		return trust(argc - 2, argv + 2);

	if(!strcmp(argv[1], "dctrust"))
		return dctrust(argc - 2, argv + 2);

	if(!strcmp(argv[1], "distrust"))
		return distrust(argc - 2, argv + 2);

	if(!strcmp(argv[1], "is_trusted"))
		return is_trusted(argc - 2, argv + 2);

	if(!strcmp(argv[1], "is_distrusted"))
		return is_distrusted(argc - 2, argv + 2);

	if(!strcmp(argv[1], "is_allowed"))
		return is_allowed(argc - 2, argv + 2);

	if(!strcmp(argv[1], "is_denied"))
		return is_denied(argc - 2, argv + 2);

	if(!strcmp(argv[1], "allow"))
		return allow(argc - 2, argv + 2);

	if(!strcmp(argv[1], "dontcare"))
		return dontcare(argc - 2, argv + 2);

	if(!strcmp(argv[1], "deny"))
		return deny(argc - 2, argv + 2);

	if(!strcmp(argv[1], "sign"))
		return sign(argc - 2, argv + 2);

	if(!strcmp(argv[1], "import"))
		return import(argc - 2, argv + 2);

	if(!strcmp(argv[1], "export"))
		return exprt(argc - 2, argv + 2);

	if(!strcmp(argv[1], "test"))
		return test(argc - 2, argv + 2);

	if(!strcmp(argv[1], "find"))
		return find(argc - 2, argv + 2);

	if(!strcmp(argv[1], "fsck"))
		return fsck();

	cerr << "Unknown command: " << argv[1] << '\n';
	return EX_USAGE;
}
