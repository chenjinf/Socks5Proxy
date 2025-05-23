/**
 * \copyright (C) 2010 Mbdsys
 * \file StringEx.h
 * \brief ��QuteCom�а�����ַ���ģ��
 *
 * QuteCom, a voice over Internet phone
 * Copyright (C) 2010 Mbdsys
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * \author QuteCom , FDD
 * \date 2017/8/15
 * \version 1.0
 */

#ifndef OWSTRING_H
#define OWSTRING_H

#include <string>
#include <vector>

class StringList;
/**
 * \defgroup STRINGS �ַ�������
 * \{
 */

/**
 * std::string wrapper/helper.
 *
 * Inspired from the class QString from the Qt library.
 *
 * @see QString
 * @see std::string
 * @see java.lang.String
 * @author Tanguy Krotoff
 */
class String : public std::string {
public:

	/**
	 * Null string.
	 *
	 * Rather than to code something like this:
	 * if (myString == "")
	 * it's better to write:
	 * if (myString.empty())
	 * return "" -> return String::null
	 */
	 static const char * null;

	 String();

	 String(const char * str);

	 String(const std::string & str);

	/**
	 * Converts this String to std::string.
	 *
	 * @return the converted String to std::string
	 */
	 operator const std::string&() {
		return *this;
	}

	/**
	 * Converts this string to an int.
	 *
	 * @return the string converted to an int or 0 if failed to convert
	 */
	 int toInteger() const;

	 /**
	 * Converts this string to an long long.
	 *
	 * @return the string converted to an long long or 0 if failed to convert
	 */
	 long long tolonglong() const;

	 /**
	 * Converts this string to an int,this string is hex format number as "0x1a2b3c4e"
	 */
	 int toIntegerHex() const;

	/**
	 * Converts this string to a boolean.
	 *
	 * Detects strings: "true", "TRUE", "yes", "YES", "1"
	 *                  "false", "FALSE", "no", "NO", "0"
	 * Be very carefull when using this method, maybe it should throw an Exception.
	 *
	 * @return the string converted to a boolean (return false if failed to convert)
	 */
	 bool toBoolean() const;

	/**
	 * Converts all of the characters in this string to lower case.
	 *
	 * Example:
	 * <pre>
	 * String myString("QuteCom");
	 * str = myString.toLowerCase();	//str == "qutecom"
	 * </pre>
	 *
	 * @return the string converted to lowercase
	 */
	 std::string toLowerCase() const;

	/**
	 * Converts all of the characters in this string to upper case.
	 *
	 * Example:
	 * <pre>
	 * String myString("QuteCom");
	 * str = myString.toUpperCase();	//str == "QUTECOM"
	 * </pre>
	 *
	 * @return the string converted to uppercase
	 */
	 std::string toUpperCase() const;

	/**
	 * @param str the string to test
	 * @return true if String begins with str
	 */
	 bool beginsWith(const String & str) const;

	/**
	 * @param str the string to test
	 * @return true if String ends with str
	 */
	 bool endsWith(const String & str) const;

	/**
	 * Gets the number of occurences of the string str inside this string.
	 *
	 * @param str string to find
	 * @param caseSensitive the search is case sensitive; otherwise the search is case insensitive
	 * @return true if this list contains the specified element
	 */
	 bool contains(const std::string & str, bool caseSensitive = true) const;

	/**
	 * @see contains()
	 */
	 bool contains(char ch, bool caseSensitive = true) const;

	/**
	 * Replaces every occurence of the string 'before' with the string 'after'.
	 *
	 * @param before occurence to find
	 * @param after the string that will replace the string before
	 * @param caseSensitive the search is case sensitive; otherwise the search is case insensitive
	 */
	 void replace(const std::string & before, const std::string & after, bool caseSensitive = true);

	/**
	 * Replaces first occurence of the string 'before' with the string 'after'.
     *
	 * This version will only look for 'before' into the given range of the string. 
	 *
	 * @param index index of the first character of the substring to find in
	 * @param size size of the substring to find in
	 * @param before occurence to find
	 * @param after the string that will replace the string before
	 * @param caseSensitive the search is case sensitive; otherwise the search is case insensitive
	 */
	 void replaceInRange(unsigned index, unsigned size,
		const std::string & before, const std::string & after, bool caseSensitive = true);

	/**
	 * Appends a string onto the end of this string.
	 *
	 * @param str string to append
	 * @return the new string
	 */
	 std::string & append(const std::string & str);

	/**
	 * Removes every occurrence of str in the string.
	 *
	 * @param str to remove in the string
	 */
	 void remove(const std::string & str);

	/**
	 * Gets a string from a number.
	 *
	 * @param number number to convert into a string
 	 * @param minLength minimal length of the string (i.e. fromNumber(15, 3) => "015")
	 * @return number converted to a string
	 */
	 static std::string fromNumber(int number, int minLength = 0);

	/**
	 * Gets a string from a boolean.
	 *
	 * @param boolean boolean to convert into a string
	 * @return boolean converted to a string
	 */
	 static std::string fromBoolean(bool boolean);

	/**
	 * Gets a string from an unsigned int.
	 *
	 * @param number unsigned int to convert into a string
	 * @return unsigned int converted to a string
	 */
	static std::string fromUnsignedInt(unsigned int number);

	/**
	 * Gets a string from an double.
	 *
	 * @param number double to convert into a string
	 * @return double converted to a string
	 */
	 static std::string fromDouble(double number);

	/**
	 * Gets a string from a long.
	 *
	 * @param number long to convert into a string
	 * @return long converted to a string
	 */
	 static std::string fromLong(long number);

	/**
	 * Gets a string from a long long.
	 *
	 * @param number long long to convert into a string
	 * @return long long converted to a string
	 */
	 static std::string fromLongLong(long long number);

	/**
	 * Gets a string from a unsigned long long.
	 *
	 * @param number unsigned long long to convert into a string
	 * @return unsigned long long converted to a string
	 */
	 static std::string fromUnsignedLongLong(unsigned long long number);

	/**
	 * URL-encodes a string.
	 *
	 * @param url the string to encode
	 * @return a string with all non-alphanumeric characters replaced by their
	 *         URL-encoded equivalent.
	 */
	 static std::string encodeUrl(const std::string & url);

	/**
	 * URL-decodes a string.
	 *
	 * @param url the URL-encoded string to decode
	 * @return a string with all URL-encoded sequences replaced by their
	 *         ASCII equivalent
	 */
	 static std::string decodeUrl(const std::string & url);


	 std::wstring toStdWString();
	 static std::string fromStdWString(const std::wstring& wstr);
	/**
	 * Tokenizes the string with a delimiter of your choice.
	 *
	 * Example:
	 * <pre>
	 * String str("four");
	 * StringList tokens = str.split("");	//tokens = "four"
	 * String str("four roses");
	 * StringList tokens = str.split(" ");	//tokens = "four", "roses"
	 * </pre>
	 *
	 * @param separator string delimiter
	 * @return tokens, strings created by splitting the input string
	 */
	 StringList split(const std::string & separator) const;

	 std::vector<std::string> split_array(const std::string& separator) const;
	/**
	 * Removes spaces at the beginning and the end of a string.
	 *
	 * @return a cleaned string
	 */
	 std::string trim();

	 bool isNumber();
};

/**
 * \}
 */
#endif	//OWSTRING_H
