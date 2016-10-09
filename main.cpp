#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "Kuznyechik.hpp"
#include "mycrypto.hpp"

int main() {
	ByteBlock thekey = hex_to_bytes(
		"8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
	);
	ByteBlock themsg = hex_to_bytes(
		"1122334455667700ffeeddccbbaa9988"
	);
	ByteBlock thect;
	cout << hex_representation(themsg) << endl;
	cout << hex_representation(thekey) << endl;
/*
	Kuznyechik encryptor(thekey);
	encryptor.encrypt(themsg, thect);
	cout << hex_representation(thect) << endl;
*/
	return 0;
}
