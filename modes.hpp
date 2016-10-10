template <typename CipherType>
CFB_Mode<CipherType>::CFB_Mode(const CipherType & alg, const ByteBlock & init_vec) :
    algorithm(alg), iv(init_vec.deep_copy())
{
    // nothing
}

template <typename CipherType>
void CFB_Mode<CipherType>::encrypt(const ByteBlock & src, ByteBlock & dst) const {
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
    dst = join_blocks(blocks);
}

template <typename CipherType>
void CFB_Mode<CipherType>::decrypt(const ByteBlock & src, ByteBlock & dst) const {
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
