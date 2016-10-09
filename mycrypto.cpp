#include <sstream>
using std::stringstream;
#include <string>
using std::string;
using std::getline;

#include <iostream>
using std::cerr;
using std::endl;

#include "mycrypto.hpp"

ByteBlock::ByteBlock(size_t size_, BYTE init_value) :
    amount_of_blocks(size_)
{
    if(!size_) pBlocks = nullptr;
    else {
        pBlocks = new BYTE [size_];
        memset(pBlocks, init_value, size_);
    }
}
ByteBlock::ByteBlock(BYTE * pBlocks_, size_t size_) :
    amount_of_blocks(size_)
{
    pBlocks = new BYTE [size_];
    memcpy(pBlocks, pBlocks_, size_);
}
ByteBlock::ByteBlock(ByteBlock && rhs) :
    pBlocks(rhs.pBlocks), amount_of_blocks(rhs.amount_of_blocks)
{
    rhs.pBlocks = nullptr;
    rhs.amount_of_blocks = 0;
}
ByteBlock::~ByteBlock() {
    memset(pBlocks, 0, amount_of_blocks);
    if(pBlocks) delete [] pBlocks;
}

void ByteBlock::operator = (ByteBlock && rhs) {
    pBlocks = rhs.pBlocks;
    amount_of_blocks = rhs.amount_of_blocks;
    rhs.pBlocks = nullptr;
    rhs.amount_of_blocks = 0;
}

ByteBlock::operator BYTE * () {
    return pBlocks;
}

BYTE & ByteBlock::operator [] (size_t index) {
    return *(pBlocks + index);
}
BYTE ByteBlock::operator [] (size_t index) const {
    return *(pBlocks + index);
}

void ByteBlock::reset(const BYTE * pBlocks_, size_t size_) {
    if(!pBlocks) memset(pBlocks, 0, amount_of_blocks);
    pBlocks = new BYTE [size_];
    memcpy(pBlocks, pBlocks_, size_);
    amount_of_blocks = size_;
}

inline char to_hex_literal(BYTE number) {
    if(number < 10) return '0' + number;
    if(number < 16) return 'a' + number - 10;
    throw string("bad argument");
}
inline BYTE from_hex_literal(char symbol) {
    if(isdigit(symbol)) return symbol - '0';
    if(symbol >= 'a' && symbol <= 'f') return symbol - 'a' + 10;
    if(symbol >= 'A' && symbol <= 'F') return symbol - 'A' + 10;
    throw string("bad argument");
}
string hex_representation(const ByteBlock & bb) {
    stringstream ss;
    for(int i = 0; i < bb.size(); i++) {
        ss << to_hex_literal(bb[i] >> 4);
        ss << to_hex_literal(bb[i] & 0xFF);
    }
    string result;
    getline(ss, result);

    return result;
}
ByteBlock hex_to_bytes(const string & s) {
    if(s.size() % 2) throw string("bad argument");
    int size = s.size() / 2;

    ByteBlock result(size);
    for(int i = 0; i < size; i++) {
        result[i] = from_hex_literal(s[2 * i]) << 4;
        result[i] |= from_hex_literal(s[2 * i + 1]);
    }
    cerr << hex_representation(result) << endl;
    return result;
}
