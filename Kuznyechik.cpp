#include <vector>
#include <map>

#include "Kuznyechik.hpp"
#include "mycrypto.hpp"

using std::vector;
using std::map;

bool Kuznyechik::is_init = false;

const vector<BYTE> nonlinear_transform_perm = {
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196,
	250, 218, 35, 197, 4, 77, 233, 119, 240, 219,
	147, 46, 153, 186, 23, 54, 241, 187, 20, 205,
	95, 193, 249, 24, 101, 90, 226, 92, 239, 33,
	129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2,
	174, 227, 106, 143, 160, 6, 11, 237, 152, 127,
	212, 211, 31, 235, 52, 44, 81, 234, 200, 72,
	171, 242, 42, 104, 162, 253, 58, 206, 204, 181,
	112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71,
	156, 183, 93, 135, 21, 161, 150, 41, 16, 123,
	154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
	50, 117, 25, 61, 255, 53, 138, 126, 109, 84,
	198, 128, 195, 189, 13, 87, 223, 245, 36, 169,
	62, 168, 67, 201, 215, 121, 214, 246, 124, 34,
	185, 3, 224, 15, 236, 222, 122, 148, 176, 188,
	220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96,
	115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159,
	38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140,
	163, 165, 125, 105, 213, 149, 59, 7, 88, 179,
	64, 134, 172, 29, 247, 48, 55, 107, 228, 136,
	217, 231, 137, 225, 27, 131, 73, 76, 63, 248,
	254, 141, 83, 170, 144, 202, 216, 133, 97, 32,
	113, 103, 164, 45, 43, 9, 91, 203, 155, 37,
	208, 190, 229, 108, 82, 89, 166, 116, 210, 230,
	244, 180, 192, 209, 102, 175, 194, 57, 75, 99,
	182
};
const map<WORD, WORD> direct_permutation, inverse_permutation;

const vector<WORD> linear_transform_coeff = {
	148, 32, 133, 16, 194, 192, 1, 251, 1, 192,
	194, 16, 133, 32, 148, 1
};
const WORD linear_transform_modulus = 0x1C3;

const vector<ByteBlock> iteration_constants;

void init_perms() {
	map<WORD, WORD> *p_direct, *p_inverse;
	p_direct = const_cast< map<WORD, WORD> * >(&direct_permutation);
	p_inverse = const_cast< map<WORD, WORD> * >(&inverse_permutation);
	for(int i = 0; i < nonlinear_transform_perm.size(); i++) {
		(*p_direct)[i] = nonlinear_transform_perm[i];
		(*p_inverse)[nonlinear_transform_perm[i]] = i;
	}
}

void xor128(BYTE * dst, const BYTE * lhs, const BYTE * rhs) {
	const BYTE * p_end = dst + BLOCK_LENGTH;
	while(dst != p_end) {
		*(dst++) = *(lhs++) ^ *(rhs++);
	}
}
void nonlinear_transform_direct128(BYTE * target) {
	BYTE * p_end = target + BLOCK_LENGTH;
	while(target != p_end) {
		*target = direct_permutation.at(*target);
		target++;
	}
}
void nonlinear_transform_inverse128(BYTE * target) {
	BYTE * p_end = target + BLOCK_LENGTH;
	while(target != p_end) {
		*target = inverse_permutation.at(*target);
		target++;
	}
}
BYTE linear_transform_core_direct128(const BYTE * target) {
	BYTE result = 0;
	for(int i = 0; i < BLOCK_LENGTH; i++)
		result ^= (*target * linear_transform_coeff[i]) % linear_transform_modulus;

	return result;
}
BYTE linear_transform_core_inverse128(const BYTE * target) {
	BYTE result = 0;
	const BYTE * p_begin = target++;
	for(int i = 0; i < 15; i++)
		result ^= (*target * linear_transform_coeff[i]) % linear_transform_modulus;
	result ^= (*p_begin * linear_transform_coeff[15]) % linear_transform_modulus;

	return result;
}

void linear_transform_direct128(BYTE * target) {
	BYTE buffer = linear_transform_core_direct128(target);
	for(int i = BLOCK_LENGTH - 1; i > 0; i--)
		target[i] = target[i-1];
	*target = buffer;
}
void linear_tranform_inverse128(BYTE * target) {
	BYTE buffer = *target;
	for(int i = 0; i < BLOCK_LENGTH - 1; i++)
		target[i] = target[i+1];
	target[15] = buffer;
	buffer = linear_transform_core_inverse128(target);
	target[15] = buffer;
}

void encrypt128(BYTE * target, vector<ByteBlock> & keys) {
	xor128(target, target, keys[0]);
	for(int i = 1; i < 10; i++) {
		nonlinear_transform_direct128(target);
		linear_transform_direct128(target);
		xor128(target, target, keys[i]);
	}
}

void decrypt128(BYTE * target, vector<ByteBlock> & keys) {
	xor128(target, target, keys[9]);
	for(int i = 8; i >= 0; i++) {
		linear_tranform_inverse128(target);
		nonlinear_transform_inverse128(target);
		xor128(target, target, keys[i]);
	}
}

void init_consts() {
	vector<ByteBlock> * p = const_cast< vector<ByteBlock> * >(&iteration_constants);
    ByteBlock v128;
    for(BYTE i = 1; i <= 32; i++) {
        v128 = ByteBlock(BLOCK_LENGTH, 0);
		v128[BLOCK_LENGTH - 1] = i;
		linear_transform_direct128(v128);
		p->push_back(std::move(v128));
	}
}

void keys_transform128(BYTE * k1, BYTE * k2, int iconst) {
	BYTE buffer[BLOCK_LENGTH];
	memcpy(buffer, k1, BLOCK_LENGTH);
	xor128(k1, k1, iteration_constants[iconst]);
	nonlinear_transform_direct128(k1);
	linear_transform_direct128(k1);
	xor128(k1, k2, k1);
	memcpy(k2, buffer, BLOCK_LENGTH);
}

void key_derivation128(BYTE * k1, BYTE * k2, BYTE * k3, BYTE * k4, int ipair) {
	if(k1 != k3) memcpy(k3, k1, BLOCK_LENGTH);
	if(k2 != k4) memcpy(k4, k2, BLOCK_LENGTH);
	for(int i = 0; i < 8; i++) {
		keys_transform128(k3, k4, ipair + i);
	}
}

Kuznyechik::Kuznyechik(const ByteBlock & key) :
    keys(10)
{
    if(key.size() != 32) throw string("bad argument");
    if(!is_init) {
        init_perms();
        init_consts();
        is_init = true;
    }
    keys[0].reset(key, BLOCK_LENGTH);
    keys[1].reset(key + BLOCK_LENGTH, BLOCK_LENGTH);
    for(int i = 0; i < 4; i++)
        key_derivation128(keys[i], keys[i+1], keys[i+2], keys[i+3], i);
}
Kuznyechik::~Kuznyechik() {}

void Kuznyechik::encrypt(const ByteBlock & src, ByteBlock & dst) {
    if(src.size() != BLOCK_LENGTH) throw 2;
    if(dst != src) dst = src.deep_copy();
    encrypt128(dst, keys);
}
void Kuznyechik::decrypt(const ByteBlock & src, ByteBlock & dst) {
    if(src.size() != BLOCK_LENGTH) throw 2;
    if(dst != src) dst = src.deep_copy();
    decrypt128(dst, keys);
}
