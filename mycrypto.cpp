#include <sstream>
using std::stringstream;

#include <string>
using std::string;
using std::getline;

#include <iostream>
using std::cerr;
using std::endl;

#include <vector>
using std::vector;

#include <cstring>

#include "mycrypto.hpp"

ByteBlock::ByteBlock(size_t size_, BYTE init_value) :
    amount_of_bytes(size_)
{
    if(!size_) pBlocks = nullptr;
    else {
        pBlocks = new BYTE [size_];
        memset(pBlocks, init_value, size_);
    }
}
ByteBlock::ByteBlock(BYTE * pBlocks_, size_t size_) :
    amount_of_bytes(size_)
{
    pBlocks = new BYTE [size_];
    memcpy(pBlocks, pBlocks_, size_);
}
ByteBlock::ByteBlock(ByteBlock && rhs) :
    pBlocks(rhs.pBlocks), amount_of_bytes(rhs.amount_of_bytes)
{
    rhs.pBlocks = nullptr;
    rhs.amount_of_bytes = 0;
}
ByteBlock::~ByteBlock() {
    if(pBlocks) {
        memset(pBlocks, 0, amount_of_bytes);
        delete [] pBlocks;
    }
}

void ByteBlock::operator = (ByteBlock && rhs) {
    if(this == &rhs) return;
    if(pBlocks) {
        memset(pBlocks, 0, amount_of_bytes);
        delete [] pBlocks;
    }
    pBlocks = rhs.pBlocks;
    amount_of_bytes = rhs.amount_of_bytes;
    rhs.pBlocks = nullptr;
    rhs.amount_of_bytes = 0;
}

ByteBlock::operator BYTE * () {
    return pBlocks;
}
ByteBlock::operator const BYTE * () const {
    return pBlocks;
}

BYTE & ByteBlock::operator [] (size_t index) {
    return *(pBlocks + index);
}
BYTE ByteBlock::operator [] (size_t index) const {
    return *(pBlocks + index);
}

void ByteBlock::reset(const BYTE * pBlocks_, size_t size_) {
    if(pBlocks) {
        memset(pBlocks, 0, amount_of_bytes);
        delete [] pBlocks;
    }
    pBlocks = new BYTE [size_];
    memcpy(pBlocks, pBlocks_, size_);
    amount_of_bytes = size_;
}

size_t ByteBlock::size() const {
    return amount_of_bytes;
};

ByteBlock ByteBlock::deep_copy() const {
    return ByteBlock(pBlocks, amount_of_bytes);
}


vector<ByteBlock> split_blocks(const ByteBlock & src, size_t length) {
    vector<ByteBlock> tmp;
    int amount = src.size() / length;
    for(int i = 0; i < amount; i++)
        tmp.push_back(src(i * length, length));
    return tmp;
}

ByteBlock join_blocks(const vector<ByteBlock> & blocks) {
    size_t amount_of_blocks = blocks.size();
    size_t length_of_blocks;
    if(amount_of_blocks) length_of_blocks = blocks[0].size();

    ByteBlock tmp(amount_of_blocks * length_of_blocks);
    for(int i = 0; i < blocks.size(); i++) {
        memcpy(tmp + i * length_of_blocks, blocks[i], length_of_blocks);
    }
    return tmp;
}

template <typename CipherType>
void CFB_Mode<CipherType>::encrypt(const ByteBlock & src, ByteBlock & dst) {
    auto blocks = split_blocks(src, CipherType::block_lenght);
    ByteBlock tmp;

    algorithm.encrypt(iv, tmp);
    xor128(tmp, tmp, blocks[0]);
    blocks[0] = tmp;
    for(int i = 1; i < blocks.size(); i++) {
        algorithm.encrypt(blocks[i-1], tmp);
        xor128(tmp, tmp, blocks[i]);
        blocks[i] = tmp;
    }
    dst = join_blocks(blocks);
}
template <typename CipherType>
void CFB_Mode<CipherType>::decrypt(const ByteBlock & src, ByteBlock & dst) {

}


inline char to_hex_literal(BYTE number) {
    if(number < 10) return '0' + number;
    if(number < 16) return 'a' + number - 10;
    throw std::invalid_argument("to_hex_literal: " + std::to_string(number));
}
inline BYTE from_hex_literal(char symbol) {
    if(isdigit(symbol)) return symbol - '0';
    if(symbol >= 'a' && symbol <= 'f') return symbol - 'a' + 10;
    if(symbol >= 'A' && symbol <= 'F') return symbol - 'A' + 10;
    throw std::invalid_argument("from_hex_literal: " + std::to_string(symbol));
}
string hex_representation(const ByteBlock & bb) {
    stringstream ss;
    for(int i = 0; i < bb.size(); i++) {
        ss << to_hex_literal(bb[i] >> 4);
        ss << to_hex_literal(bb[i] & 0xF);
    }
    string result;
    getline(ss, result);
    return result;
}
ByteBlock hex_to_bytes(string s) {
    if(s.size() % 2) s = "0" + s;
    int size = s.size() / 2;

    ByteBlock result(size);
    for(int i = 0; i < size; i++) {
        result[i] = from_hex_literal(s[2 * i]) << 4;
        result[i] += from_hex_literal(s[2 * i + 1]);
    }
    return result;
}
