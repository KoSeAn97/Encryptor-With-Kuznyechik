#include <thread>
#include <algorithm>
#include <functional>
#include <iostream>

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
void CFB_Mode<CipherType>::decrypt_with_iv(const ByteBlock & src, ByteBlock & dst, const ByteBlock & iv_) const {
    auto blocks = split_blocks(src, CipherType::block_lenght);
	ByteBlock tmp;

	algorithm.encrypt(iv_, tmp);
	xor_blocks(tmp, blocks[0], tmp);
	swap(tmp, blocks[0]);
	for(int i = 1; i < blocks.size(); i++) {
		algorithm.encrypt(tmp, tmp);
		xor_blocks(tmp, blocks[i], tmp);
		swap(tmp, blocks[i]);
	}
	dst = join_blocks(blocks);
}

template <typename CipherType>
void CFB_Mode<CipherType>::decrypt(const ByteBlock & src, ByteBlock & dst) const {
	decrypt_with_iv(src, dst, iv);
}

template <typename CipherType>
void CFB_Mode<CipherType>::parallel_decrypt(const ByteBlock & src, ByteBlock & dst) const {
    // length in blocks of CipherType::block_lenght
    unsigned long const length =
        src.size() / CipherType::block_lenght + (src.size() % CipherType::block_lenght ? 1 : 0);

    // amount of threads which can perform really simultaniously
    unsigned long const hardware_threads = std::thread::hardware_concurrency();

    // blocks of size CipherType::block_lenght to perform on by one thread
    unsigned long const min_per_thread = 1;

    // amount of threads to satisfy current condition
    unsigned long const max_threads = (length + min_per_thread - 1) / min_per_thread;

    // amount of threads to create
    unsigned long const num_threads = std::min(
        hardware_threads != 0 ? hardware_threads : 2,
        max_threads
    );

    // if we aren't able to use multiple threads call common decryptor
    if(num_threads <= 1) {
        decrypt(src, dst);
        return;
    }

    std::cerr << "Running " << num_threads << " threads." << endl;

    unsigned long const block_size = (length / num_threads) * CipherType::block_lenght;
    std::vector<ByteBlock> init_vectors(num_threads);
    std::vector<ByteBlock> results(num_threads);
    std::vector<std::thread> threads(num_threads - 1);

    init_vectors[0] = iv.deep_copy();
    for(int i = 1; i < num_threads; i++)
        init_vectors[i] = src(i * block_size - CipherType::block_lenght, CipherType::block_lenght);

    unsigned long start_pos = 0;
    for(unsigned long i = 0; i < num_threads - 1; i++) {
        threads[i] = std::thread(
            &CFB_Mode<CipherType>::decrypt_with_iv,
            this,
            src(start_pos, block_size),
            std::ref( results[i] ),
            std::ref( init_vectors[i] )
        );
        start_pos += block_size;
    }

    decrypt_with_iv(
        src(start_pos, src.size() - start_pos),
        results[num_threads - 1],
        init_vectors[num_threads - 1]
    );

    for(auto & t : threads) t.join();

    dst = join_blocks(results);
}
