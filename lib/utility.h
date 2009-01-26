/* fides.h - Light-weight, decentralised trust and authorisation management
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

#ifndef __FIDES_UTILITY_H__
#define __FIDES_UTILITY_H__

#include <stdexcept>
#include <string>
#include <vector>
#include <regex.h>

namespace Fides {
	class regexp {
		regex_t comp;

		public:
		static const int EXTENDED = REG_EXTENDED;
		static const int ICASE = REG_ICASE;
		static const int NOSUB = REG_NOSUB;
		static const int NEWLINE = REG_NEWLINE;

		static const int NOTBOL = REG_NOTBOL;
		static const int NOTEOL = REG_NOTEOL;

		/// Construct a compiled regular expression.
		///
		/// @param exp    Regular expression to compile.
		/// @param cflags Bitwise OR of options to apply when compiling the regular expression:
		///               - Fides::regexp::EXTENDED
		///                 Use POSIX Extended Regular Expression syntax when interpreting exp.
		///               - Fides::regexp::ICASE
		///                 Make the expression case-insensitive.
		///               - Fides::regexp::NOSUB
		///                 Disable support for substring addressing.
		///               - Fides::regexp::NEWLINE
		///                 Do not treat the newline character as the start or end of a line.
		regexp(const std::string &exp, int cflags = 0) {
			int err = regcomp(&comp, exp.c_str(), cflags);
			if(err)
				throw std::runtime_error("Could not compile regular expression");
		}

		~regexp() {
			regfree(&comp);
		}

		/// Test whether a string matches the regular expression.
		///
		/// @param in     String to test.
		/// @param eflags Bitwise OR of options to apply when matching the string:
		///               - Fides::regexp::NOTBOL
		///                 Do not treat the start of the string as the start of a line.
		///               - Fides::regexp::NOTEOL
		///                 Do not treat the end of the string as the end of a line.
		/// @return True if the string matches the regular expression, false otherwise.
		bool match(const std::string &in, int eflags = 0) {
			return regexec(&comp, in.c_str(), 0, 0, eflags) == 0;
		}
	};

	std::string b64encode(const std::string &in);
	std::string b64decode(const std::string &in);
	std::string hexencode(const std::string &in);
	std::string hexdecode(const std::string &in);

	std::vector<std::string> dirlist(const std::string &path);
}

#endif
