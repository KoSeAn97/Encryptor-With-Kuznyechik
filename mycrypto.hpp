#include <string>
using std::string;

#ifndef __MYCRYPTO__
#define __MYCRYPTO__

typedef unsigned char BYTE;
typedef unsigned short WORD;

class ByteBlock {
	BYTE * pBlocks;
	size_t amount_of_bytes;
public:
    // Construct block of bytes which contsists of
    // size_ blocks each of them with init_value in it
	ByteBlock(size_t size_ = 0, BYTE init_value = 0);

    // Construct block with size_ first bytes of pBlocks_
    // The value will be copied, source stays untouchable
    ByteBlock(BYTE * pBlocks_, size_t size_);

    // Move constructer
    // Copy constructer thus implicitly deleted
    // Object to move turn to null
    ByteBlock(ByteBlock && rhs);

    // Destructor, yeah
    ~ByteBlock();

    // Move assigment operator
    // Object to move turn to null
	void operator = (ByteBlock && rhs);

    // This cast may be convenient to use the ByteBlock
    // in functions which takes raw pointers as argument
    operator BYTE * ();
    operator const BYTE * () const;

    // Indexing operator with evident functionality
    BYTE & operator [] (size_t index);
    BYTE operator [] (size_t index) const;

    // Replace body of the current block with pBlocks_
    // Old value will be zerod, and then, deleted
    // New value copied into the block,
    // source stays untouchable
    void reset(const BYTE * pBlocks_, size_t size_);

    // Return amount of bytes in block
    size_t size() const;

    // It'll return deep copy of the block, which
    // points to different place in memory
    ByteBlock deep_copy() const;

    ByteBlock operator () (size_t begin, size_t length) const {
        ByteBlock tmp(length);
        memcpy(tmp, pBlocks + begin, length);
        return tmp;
    }
};

string hex_representation(const ByteBlock & bb);
ByteBlock hex_to_bytes(string s);
void xor128(BYTE * dst, const BYTE * lhs, const BYTE * rhs);


template <typename CipherType>
class CFB_Mode {
    CipherType algorithm;
    ByteBlock iv;
public:
    CFB_Mode(const CipherType & alg, const ByteBlock & init_vec) :
        algorithm(alg), iv(init_vec.deep_copy())
    {
        // nothing
    }
    void encrypt(const ByteBlock & src, ByteBlock & dst);
    void decrypt(const ByteBlock & src, ByteBlock & dst);
};

#endif
