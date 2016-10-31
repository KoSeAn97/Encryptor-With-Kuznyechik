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

    // Move constructor
    // Copy constructor thus implicitly deleted
    // Object to move turn to null
    ByteBlock(ByteBlock && rhs);

    // Destructor, yeah
    ~ByteBlock();

    // Move assigment operator
    // Object to move turn to null
	void operator = (ByteBlock && rhs);

    // This cast may be convenient to use the ByteBlock
    // in functions which takes raw pointers as argument
    BYTE * byte_ptr();
    const BYTE * byte_ptr() const;

    // Indexing operator with evident functionality
    BYTE & operator [] (size_t index);
    BYTE operator [] (size_t index) const;

	bool operator == (const ByteBlock & lhs) const;
	bool operator != (const ByteBlock & lhs) const;

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

	// It'll return slice of current ByteBlock
    ByteBlock operator () (size_t begin, size_t length) const;

	// Changes values between two ByteBlock-s
	friend void swap(ByteBlock & lhs, ByteBlock & rhs);
};

// Some functions which will be useful for implementation of encryption algorithms
std::vector<ByteBlock> split_blocks(const ByteBlock & src, size_t length);
ByteBlock join_blocks(const std::vector<ByteBlock> & blocks);
void xor_blocks(ByteBlock & to_assign, const ByteBlock & lhs, const ByteBlock & rhs);

// Some I/O functions to work with hex representation of ByteBlock
string hex_representation(const ByteBlock & bb);
ByteBlock hex_to_bytes(const string & s);

// Template class that provides implementation of Cipher Feadback mode
// of operation with any block cipher (algorithm) which saticfy several
// requirement. It must have got:
// copy constructor, methods encrypt and decrypt with the same interface
// and public member-data block_lenght
template <typename CipherType>
class CFB_Mode {
    const CipherType algorithm;
    const ByteBlock iv;

	void decrypt_with_iv(const ByteBlock & src, ByteBlock & dst, const ByteBlock & iv_) const;
public:
    CFB_Mode(const CipherType & alg, const ByteBlock & init_vec);
    void encrypt(const ByteBlock & src, ByteBlock & dst) const;
    void decrypt(const ByteBlock & src, ByteBlock & dst) const;

	void parallel_decrypt(const ByteBlock & src, ByteBlock & dst) const;
};

// Implementations of modes of encryption
#include "modes.hpp"

#endif
