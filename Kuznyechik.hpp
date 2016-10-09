#ifndef __KUZNYECHIK__
#define __KUZNYECHIK__

#include <vector>
#include "mycrypto.hpp"

#define BLOCK_LENGTH 16

class Kuznyechik {
	std::vector<ByteBlock> keys;
	static bool is_init;
public:
	Kuznyechik(const ByteBlock & key);
	~Kuznyechik();
	void encrypt(const ByteBlock & src, ByteBlock & dst);
	void decrypt(const ByteBlock & src, ByteBlock & dst);
};

#endif
