#include <stdio.h>
#include <sysexits.h>

void help(FILE *out, const char *argv0) {
	fprintf(out, "Usage: %s <command> [arguments]\n\n", argv0);
	fprintf(out, "Available commands are:\n");
	fprintf(out, "  init      Initialise fides, generate a public/private keypair.\n");
	fprintf(out, "  version   Show version and copyright information.\n");
	fprintf(out, "  help      Show this help message.\n");
	fprintf(out, "  trust <keyid>\n");
	fprintf(out, "            Trust allow/deny packets signed by the specified key.\n");
	fprintf(out, "  distrust <keyid>\n");
	fprintf(out, "            Distrust allow/deny packets signed by the specified key.\n");
	fprintf(out, "  allow <keyid> <stuff ...>\n");
	fprintf(out, "            Allow the entity identified by keyid some stuff.\n");
	fprintf(out, "  deny <keyid> <stuff ...> \n");
	fprintf(out, "            Deny the entity identified by keyid some stuff.\n");
	fprintf(out, "  import [filename]\n");
	fprintf(out, "            Import trust packets from file, or stdin if unspecified.\n");
	fprintf(out, "  export [filename]\n");
	fprintf(out, "            Export trust packets to file, or stdout if unspecified.\n"); 
	fprintf(out, "  test <stuff ...>\n");
	fprintf(out, "            Tell whether stuff is allowed or not, and why.\n");
	fprintf(out, "  fsck      Verify the signature on all information collected.\n");
}

int version() {
	fprintf(stdout, "fides version 0.1\n");
	fprintf(stdout, "Copyright (c) 2008 Guus Sliepen <guus@tinc-vpn.org>\n\n");
	fprintf(stdout, "This program is free software; you can redistribute it and/or modify\n"
	                "it under the terms of the GNU General Public License as published by\n"
	                "the Free Software Foundation; either version 2 of the License, or\n"
	                "(at your option) any later version.\n");

	return 0;
}

int init() {
	// Generate a public/private keypair if it does not already exist
	return 0;
}

int trust(int argc, char *argv[]) {
	// Trust another key
	return 0;
}

int distrust(int argc, char *argv[]) {
	// Distrust another key
	return 0;
}

int allow(int argc, char *argv[]) {
	// Generate a certficate allowing something
	return 0;
}

int deny(int argc, char *argv[]) {
	// Generate a certificate denying something
	return 0;
}

int import(int argc, char *argv[]) {
	// Import certificates
	return 0;
}

int export(int argc, char *argv[]) {
	// Export certificates
	return 0;
}

int test(int argc, char *argv[]) {
	// Test something against all certificates
	return 0;
}

int fsck() {
	// Verify the integrity of all certificates
	return 0;
}

main(int argc, char *argv[]) {
	if(argc < 2) {
		help(stderr, argv[0]);
		return EX_USAGE;
	}

	if(!strcmp(argv[1], "help")) {
		help(stdout, argv[0]);
		return 0;
	}

	if(!strcmp(argv[1], "version"))
		return version();

	if(!strcmp(argv[1], "init"))
		return init();

	if(!strcmp(argv[1], "trust"))
		return trust(argc - 2, argv + 2);

	if(!strcmp(argv[1], "distrust"))
		return distrust(argc - 2, argv + 2);

	if(!strcmp(argv[1], "allow"))
		return allow(argc - 2, argv + 2);

	if(!strcmp(argv[1], "deny"))
		return deny(argc - 2, argv + 2);

	if(!strcmp(argv[1], "import"))
		return import(argc - 2, argv + 2);

	if(!strcmp(argv[1], "export"))
		return export(argc - 2, argv + 2);

	if(!strcmp(argv[1], "test"))
		return test(argc - 2, argv + 2);

	if(!strcmp(argv[1], "fsck"))
		return fsck();

	fprintf(stderr, "Unknown command '%s'\n", argv[1]);
	return EX_USAGE;
}

