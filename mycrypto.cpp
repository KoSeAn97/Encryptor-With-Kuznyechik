#include <stdexcept>

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

BYTE * ByteBlock::byte_ptr() {
    return pBlocks;
}
const BYTE * ByteBlock::byte_ptr() const {
    return pBlocks;
}

BYTE & ByteBlock::operator [] (size_t index) {
    return *(pBlocks + index);
}
BYTE ByteBlock::operator [] (size_t index) const {
    return *(pBlocks + index);
}

bool ByteBlock::operator == (const ByteBlock & lhs) const {
    return pBlocks == lhs.pBlocks;
}
bool ByteBlock::operator != (const ByteBlock & lhs) const {
    return !(*this == lhs);
}

void ByteBlock::reset(const BYTE * pBlocks_, size_t size_) {
    if(pBlocks) {
        memset(pBlocks, 0, amount_of_bytes);
        delete [] pBlocks;
    }
    if(size_ && pBlocks_) {
        pBlocks = new BYTE [size_];
        memcpy(pBlocks, pBlocks_, size_);
        amount_of_bytes = size_;
    } else  {
        pBlocks = nullptr;
        amount_of_bytes = 0;
    }
}

size_t ByteBlock::size() const {
    return amount_of_bytes;
};

ByteBlock ByteBlock::deep_copy() const {
    return ByteBlock(pBlocks, amount_of_bytes);
}

ByteBlock ByteBlock::operator () (size_t begin, size_t length) const {
    ByteBlock tmp;
    tmp.reset(pBlocks + begin, length);
    return tmp;
}

void swap(ByteBlock & lhs, ByteBlock & rhs) {
    BYTE * p = lhs.pBlocks;
    size_t s = lhs.amount_of_bytes;
    lhs.pBlocks = rhs.pBlocks;
    lhs.amount_of_bytes = rhs.amount_of_bytes;
    rhs.pBlocks = p;
    rhs.amount_of_bytes = s;
}

vector<ByteBlock> split_blocks(const ByteBlock & src, size_t length) {
    vector<ByteBlock> tmp;
    int amount = src.size() / length;
    int tail = src.size() % length;
    for(int i = 0; i < amount; i++)
        tmp.push_back(src(i * length, length));
    if(tail)
        tmp.push_back(src(amount * length, tail));

    return tmp;
}

ByteBlock join_blocks(const vector<ByteBlock> & blocks) {
    if(blocks.empty()) return ByteBlock();

    size_t size_vector = blocks.size();
    size_t size_block = blocks[0].size();
    size_t size_last = blocks[size_vector - 1].size();
    size_t size_byteblock = (size_vector - 1) * size_block + size_last;

    ByteBlock tmp(size_byteblock);
    for(int i = 0; i < size_vector - 1; i++) {
        memcpy(
            tmp.byte_ptr() + i * size_block,
            blocks[i].byte_ptr(),
            size_block
        );
    }
    memcpy(
        tmp.byte_ptr() + (size_vector - 1) * size_block,
        blocks[size_vector - 1].byte_ptr(),
        size_last
    );

    return tmp;
}

void xor_blocks(ByteBlock & to_assign, const ByteBlock & lhs, const ByteBlock & rhs) {
    size_t result_size = lhs.size() > rhs.size() ? rhs.size() : lhs.size();
    ByteBlock tmp(result_size);
    for(size_t i = 0; i < result_size; i++)
        tmp[i] = lhs[i] ^ rhs[i];
    to_assign = std::move(tmp);
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
ByteBlock hex_to_bytes(const string & s) {
    if(s.size() % 2) throw std::invalid_argument("length of hex-string must be even number");
    int size = s.size() / 2;

    ByteBlock result(size);
    for(int i = 0; i < size; i++) {
        result[i] = from_hex_literal(s[2 * i]) << 4;
        result[i] += from_hex_literal(s[2 * i + 1]);
    }
    return result;
}
