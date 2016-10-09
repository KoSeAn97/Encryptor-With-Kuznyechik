#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>

#include "Kuznyechik.hpp"
#include "mycrypto.hpp"

int main() {
	try {
		ByteBlock thekey = hex_to_bytes(
			"8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"
		);
		ByteBlock themsg = hex_to_bytes(
			"1122334455667700ffeeddccbbaa9988"
		);
		ByteBlock iv = hex_to_bytes(
			"abcdef12345600dacdef94756eeabefa"
		);
		CFB_Mode<Kuznyechik> encryptor(Kuznyechik(thekey), iv);
		ByteBlock output;
		encryptor.encrypt(thekey, output);
		cout << hex_representation(output) << endl;
	} catch(const std::exception & e) {
		cerr << e.what() << endl;
	}

	return 0;
}
