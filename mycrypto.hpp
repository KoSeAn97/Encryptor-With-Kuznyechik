#include <string>
using std::string;

#ifndef __MYCRYPTO__
#define __MYCRYPTO__

typedef unsigned char BYTE;
typedef unsigned short WORD;

class ByteBlock {
	BYTE * pBlocks;
	size_t amount_of_blocks;
public:
	ByteBlock(size_t size_ = 0, BYTE init_value = 0);
    ByteBlock(BYTE * pBlocks_, size_t size_);
	ByteBlock(ByteBlock && rhs);
    ~ByteBlock();
	void operator = (ByteBlock && rhs);
	operator BYTE * ();
    operator const BYTE * () const {
        return pBlocks;
    }
    BYTE & operator [] (size_t index);
    BYTE operator [] (size_t index) const;

    void reset(const BYTE * pBlocks_, size_t size_);
    size_t size() const {
        return amount_of_blocks;
    };
    ByteBlock deep_copy() const {
        return ByteBlock(pBlocks, amount_of_blocks);
    }
};

string hex_representation(const ByteBlock & bb);
ByteBlock hex_to_bytes(const string & s);

#endif
