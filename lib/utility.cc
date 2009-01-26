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

namespace Fides {
	// Base64 and hex encoding/decoding functions

	/// Hexadecimal encode data.
	//
	/// @param in A string containing raw data.
	/// @return A string containing the hexadecimal encoded data.
	string hexencode(const std::string &in) {
		Botan::Pipe pipe(new Botan::Hex_Encoder);
		pipe.process_msg((Botan::byte *)in.data(), in.size());
		return pipe.read_all_as_string();
	}

	/// Decode hexadecimal data.
	//
	/// @param in A string containing hexadecimal encoded data.
	/// @return A string containing the raw data.
	string hexdecode(const std::string &in) {
		Botan::Pipe pipe(new Botan::Hex_Decoder);
		pipe.process_msg((Botan::byte *)in.data(), in.size());
		return pipe.read_all_as_string();
	}

	/// Base-64 encode data.
	//
	/// @param in A string containing raw data.
	/// @return A string containing the base-64 encoded data.
	string b64encode(const std::string &in) {
		Botan::Pipe pipe(new Botan::Base64_Encoder);
		pipe.process_msg((Botan::byte *)in.data(), in.size());
		return pipe.read_all_as_string();
	}

	/// Decode base-64 data.
	//
	/// @param in A string containing base-64 encoded data.
	/// @return A string containing the raw data.
	string b64decode(const std::string &in) {
		Botan::Pipe pipe(new Botan::Base64_Decoder);
		pipe.process_msg((Botan::byte *)in.data(), in.size());
		return pipe.read_all_as_string();
	}

	/// Return the names of all the files in a directory.
	//
	/// @param path Directory to search for files.
	/// @return A vector of strings with the name of each file in the directory.
	///         The filename does not contain the leading path.
	vector<string> dirlist(const std::string &path) {
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
}
