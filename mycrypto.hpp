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

	friend void swap(ByteBlock & lhs, ByteBlock & rhs) {
		BYTE * p = lhs.pBlocks;
		size_t s = lhs.amount_of_bytes;
		lhs.pBlocks = rhs.pBlocks;
		lhs.amount_of_bytes = rhs.amount_of_bytes;
		rhs.pBlocks = p;
		rhs.amount_of_bytes = s;
	}
};

string hex_representation(const ByteBlock & bb);
ByteBlock hex_to_bytes(string s);

std::vector<ByteBlock> split_blocks(const ByteBlock & src, size_t length);
ByteBlock join_blocks(const std::vector<ByteBlock> & blocks);
void xor_blocks(ByteBlock & to_assign, const ByteBlock & lhs, const ByteBlock & rhs);

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

template <typename CipherType>
void CFB_Mode<CipherType>::encrypt(const ByteBlock & src, ByteBlock & dst) {
    auto blocks = split_blocks(src, CipherType::block_lenght);
    ByteBlock tmp;

    algorithm.encrypt(iv, tmp);
    xor_blocks(tmp, tmp, blocks[0]);
    blocks[0] = std::move(tmp);
    for(int i = 1; i < blocks.size(); i++) {
        algorithm.encrypt(blocks[i-1], tmp);
        xor_blocks(tmp, tmp, blocks[i]);
        blocks[i] = std::move(tmp);
    }
    //blocks.insert(blocks.begin(), iv.deep_copy());
    dst = join_blocks(blocks);
}

template <typename CipherType>
void CFB_Mode<CipherType>::decrypt(const ByteBlock & src, ByteBlock & dst) {
	auto blocks = split_blocks(src, CipherType::block_lenght);
	ByteBlock tmp;

	algorithm.encrypt(iv, tmp);
	xor_blocks(tmp, blocks[0], tmp);
	swap(tmp, blocks[0]);
	for(int i = 1; i < blocks.size(); i++) {
		algorithm.encrypt(tmp, tmp);
		xor_blocks(tmp, blocks[i], tmp);
		swap(tmp, blocks[i]);
	}
	dst = join_blocks(blocks);
}

#endif
