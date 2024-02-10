/*
** Modified from https://github.com/Visa-Research/volepsi.git
** (1) simplify the design
** (2) support multi-thread programming with OpenMP
*/


#ifndef KUNLUN_BAXOS_HPP_
#define KUNLUN_BAXOS_HPP_
#include "paxos.hpp"
#include "okvs_utility.hpp"

#include <future>
template <DenseType dense_type = binary, typename value_type = block>
class Baxos
{
public:
    uint64_t item_num = 0;
    uint64_t bin_num = 0;
    uint64_t item_num_per_bin = 0;
    uint8_t sparse_weight = 0;
    uint8_t statistical_security_parameter = 40;
    bool is_decoding = false;

    uint64_t sparse_size;
    uint64_t dense_size;
    uint64_t total_size;
    uint8_t g_limit;

    PRG::Seed seed;

    Baxos() = default;
    Baxos(const uint64_t item_num, const uint64_t bin_size, const uint8_t sparse_weight = 3, const uint8_t statistical_security_parameter = 40, const PRG::Seed *seed = nullptr);
    template <typename idx_type>
    void impl_solve(const std::vector<block> &keys, const std::vector<value_type> &values, std::vector<value_type> &output, PRG::Seed *prng, uint8_t thread_num);
    template <typename idx_type>
    void impl_decode(const std::vector<block> &keys, std::vector<value_type> &values, const std::vector<value_type> &output, uint8_t thread_num);
    template <typename idx_type>
    void impl_decode_batch(block *keys, value_type *values, uint64_t batch_len, value_type *output);
    // template <typename idx_type>
    // void impl_decode_bin(block *keys, uint64_t len, block *keys_indexes, block *output,
    //                      OKVS<idx_type, dense_type> &paxos);
    void solve(const std::vector<block> &keys, const std::vector<value_type> &values, std::vector<value_type> &output, PRG::Seed *prng = nullptr, uint8_t thread_num = 1);
    void decode(const std::vector<block> &keys, std::vector<value_type> &values, const std::vector<value_type> &output, uint8_t thread_num = 1);
};

template <DenseType dense_type, typename value_type>
Baxos<dense_type, value_type>::Baxos(const uint64_t item_num, const uint64_t bin_size,
                         const uint8_t sparse_weight, const uint8_t statistical_security_parameter, const PRG::Seed *input_seed) : item_num(item_num), sparse_weight(sparse_weight),
                                                                                                           bin_num((item_num + bin_size - 1) / bin_size), statistical_security_parameter(statistical_security_parameter)
{
    // Calculate the number of elements that can be safely stored in each bin
    item_num_per_bin = hashtable_bin_size(bin_num, item_num, statistical_security_parameter + std::log2(bin_num));

    seed = input_seed ? *input_seed : PRG::SetSeed(fixed_seed, 0);

    // Calculate sparse_size and dense_size for each bin
    {
        double logN = log2(item_num_per_bin);
        if (sparse_weight < 2)
        {
            throw;
        }
        else if (sparse_weight == 2)
        {
            double a = 7.529, b = 0.61, c = 2.556;
            double lambdaVsGap = a / (logN - c) + b;

            g_limit = static_cast<uint64_t>(std::ceil(statistical_security_parameter / lambdaVsGap + 1.9));
            sparse_size = 2 * item_num_per_bin;
        }
        else
        {
            double ee = 0;
            if (sparse_weight == 3)
                ee = 1.223;
            else if (sparse_weight == 4)
                ee = 1.293;
            else if (sparse_weight >= 5)
                ee = 0.1485 * sparse_weight + 0.6845;

            double logW = std::log2(sparse_weight);
            double logLambdaVsE = 0.555 * logN + 0.093 * std::pow(logW, 3) - 1.01 * std::pow(logW, 2) + 2.925 * logW - 0.133;
            double lambdaVsE = std::pow(2, logLambdaVsE);

            double b = -9.2 - lambdaVsE * ee;
            double e = (statistical_security_parameter - b) / lambdaVsE;
            g_limit = std::floor(statistical_security_parameter / ((sparse_weight - 2) * std::log2(e * item_num_per_bin)));
            sparse_size = item_num_per_bin * e;
        }
    }

    dense_size = g_limit + (dense_type == binary ? statistical_security_parameter : 0);
    total_size = sparse_size + dense_size;
}
template <DenseType dense_type, typename value_type>
template <typename idx_type>
inline void Baxos<dense_type, value_type>::impl_solve(const std::vector<block> &keys, const std::vector<value_type> &values, std::vector<value_type> &output, PRG::Seed *prng, uint8_t thread_num)
{
    if (bin_num == 1)
    {
        // If there is only one bin, then call single-threaded OKVS
        OKVS<idx_type, dense_type, value_type> paxos(item_num_per_bin, sparse_weight, statistical_security_parameter, &seed);
        paxos.set_keys(keys.data());
        output = paxos.encode(values, prng);
        return;
    }
    else
    {
        omp_set_num_threads(thread_num);
        auto total_bin_num = thread_num * bin_num;
        // thread_1:bin_0,bin_1,...,bin_
        // thread_2:bin_0,bin_1,...,bin_
        auto item_num_per_thread = (item_num + thread_num - 1) / thread_num;
        // item_i1,item_i2,...item_ik   item_j1,item_j2,...,item_jl
        //      thread_1                    thread_2
        auto bin_size_per_thread = hashtable_bin_size(bin_num, item_num_per_thread, statistical_security_parameter);
        auto bin_size_all_thread = thread_num * bin_size_per_thread;

        std::vector<std::vector<idx_type>> bin_size_thread(thread_num, std::vector<idx_type>(bin_num, 0));

        std::unique_ptr<idx_type[]> item_to_bin_thread(new idx_type[bin_num * bin_size_all_thread]);
        std::unique_ptr<value_type[]> value_to_bin_thread(new value_type[bin_num * bin_size_all_thread]);
        std::unique_ptr<block[]> hash_to_bin_thread(new block[bin_num * bin_size_all_thread]);

        // The storage format is shown in the table below
        /*
               |<-                              bin_size_all_thread                               ->|
               |<-bin_size_per_thread->|
                -----------------------------------------------------------------------------------------------
        bin_0  |_______________________|_______________________|_______________________|_______________________|
        bin_1  |_______________________|_______________________|_______________________|_______________________|
        bin_2  |_______________________|_______________________|_______________________|_______________________|
        bin_3  |                       |                       |                       |                       |
                -----------------------------------------------------------------------------------------------
        */

        auto get_item_bin_thread = [&](uint8_t bin_idx, uint8_t thread_idx)
        {
            auto bin_begin = bin_idx * bin_size_all_thread;
            auto thread_begin = thread_idx * bin_size_per_thread;

            return item_to_bin_thread.get() + bin_begin + thread_begin;
        };
        auto get_value_bin_thread = [&](uint8_t bin_idx, uint8_t thread_idx)
        {
            auto bin_begin = bin_idx * bin_size_all_thread;
            auto thread_begin = thread_idx * bin_size_per_thread;

            return value_to_bin_thread.get() + bin_begin + thread_begin;
        };
        auto get_hash_bin_thread = [&](uint8_t bin_idx, uint8_t thread_idx)
        {
            auto bin_begin = bin_idx * bin_size_all_thread;
            auto thread_begin = thread_idx * bin_size_per_thread;

            return hash_to_bin_thread.get() + bin_begin + thread_begin;
        };

        divider divider = gen_divider(bin_num);

        uint8_t thread_done_num(0);
        // std::atomic<uint8_t> thread_done_num(0);
        // std::promise<void> assignment_done;
        // auto assignment_done_future = assignment_done.get_future().share();
        const uint64_t keys_size = keys.size();
        block *keys_data = (block *)keys.data();

#pragma omp parallel
        {
            const uint8_t thread_id = omp_get_thread_num();
            uint64_t begin = (keys_size * thread_id) / thread_num;
            const uint64_t len = keys_size * (thread_id + 1) / thread_num - begin;

            block *keys_thread_pointer = keys_data + begin;
            auto &bin_sizes = bin_size_thread[thread_id];

            // Assign the key std::array to different threads, and the thread assigns the key to the entry in the table
            std::array<block, 32> hashes;
            std::array<uint64_t, 32> bin_idxes;
            uint64_t i = 0;
            auto idx = begin;
            auto main_bound = len - 32;
            for (; i <= main_bound; i += 32, keys_thread_pointer += 32)
            {
                // assert(keys_thread_pointer == keys_data + begin + i);
                AES::FastECBEnc(seed.aes_key, keys_thread_pointer, 32, hashes.data());
                for (auto j = 0; j < 32; j++)
                {
                    hashes[j] ^= keys_thread_pointer[j];
                    const uint64_t *h_pointer64 = (uint64_t *)(hashes.data() + j);
                    const uint32_t *h_pointer32 = (uint32_t *)(h_pointer64);
                    bin_idxes[j] = h_pointer64[0] ^ h_pointer64[1] ^ h_pointer32[3];
                }
                doMod32(bin_idxes.data(), &divider, bin_num);
                auto bin_idx_pointer = bin_idxes.data();
                for (auto j = 0; j < 32; j++, idx++, bin_idx_pointer++)
                {
                    auto bin_idx = *bin_idx_pointer;
                    auto bin_size = bin_sizes[bin_idx]++;

                    get_item_bin_thread(bin_idx, thread_id)[bin_size] = idx;
                    get_value_bin_thread(bin_idx, thread_id)[bin_size] = values[idx];
                    get_hash_bin_thread(bin_idx, thread_id)[bin_size] = hashes[j];
                }
            }

            for (; i < len; i++, keys_thread_pointer++, idx++)
            {
                auto hash_pointer = hashes.data();

                AES::FastECBEnc(seed.aes_key, keys_thread_pointer, 1, hash_pointer);
                *hash_pointer ^= *keys_thread_pointer;

                const uint64_t *hash_pointer64 = (uint64_t *)hash_pointer;
                const uint32_t *hash_pointer32 = (uint32_t *)hash_pointer;
                const uint64_t bin_idx = (hash_pointer64[0] ^ hash_pointer64[1] ^ hash_pointer32[3]) % bin_num;
                auto bin_size = bin_sizes[bin_idx]++;
                assert(bin_size <= bin_size_per_thread);
                get_item_bin_thread(bin_idx, thread_id)[bin_size] = idx;
                get_value_bin_thread(bin_idx, thread_id)[bin_size] = values[idx];
                get_hash_bin_thread(bin_idx, thread_id)[bin_size] = hashes[0];
            }

            // #pragma omp atomic
            //             thread_done_num++;
            //             if (thread_done_num == thread_num)
            //                 assignment_done.set_value();
            //             else
            //                 assignment_done_future.get();
        }
#pragma omp parallel
        {

            // Use different threads to process each bin.
            uint8_t thread_id = omp_get_thread_num();
            for (auto bin_idx = thread_id; bin_idx < bin_num; bin_idx += thread_num)
            {
                uint32_t bin_size = 0;
                for (auto bin_size_thread_bin : bin_size_thread)
                    bin_size += bin_size_thread_bin[bin_idx];

                assert(bin_size <= item_num_per_bin); // 0:262420 1:261874 2:262425 3:261857

                // Initialize small-sized single-threaded OKVS
                OKVS<idx_type, dense_type, value_type> paxos;
                paxos.item_num = bin_size;
                paxos.sparse_weight = sparse_weight;
                paxos.sparse_size = sparse_size;
                paxos.dense_size = dense_size;
                paxos.total_size = total_size;
                paxos.seed = seed;
                paxos.statistical_security_parameter = statistical_security_parameter;
                paxos.g_limit = g_limit;

                // Allocate storage space for variables, the process is similar to the OKVS::allocate() function
                auto allocate_size = sizeof(idx_type) * (item_num_per_bin * sparse_weight * 2 + sparse_size) + sizeof(idx_type *) * sparse_size;
                std::unique_ptr<uint8_t[]> storage(new uint8_t[allocate_size]);
                uint8_t *iter = storage.get();

                paxos.h_sparse.resize(iter, item_num_per_bin, sparse_weight);
                iter += item_num_per_bin * sparse_weight * sizeof(idx_type);

                paxos.col_weights = (idx_type *)iter;
                iter += sparse_size * sizeof(idx_type);

                idx_type **col_begin = (idx_type **)iter;
                iter += sparse_size * sizeof(idx_type *);

                paxos.h_cols.resize(iter, sparse_size);
                iter += item_num_per_bin * sparse_weight * sizeof(idx_type);

                assert(iter == storage.get() + allocate_size);

                auto bin_begin = bin_idx * bin_size_all_thread;
                auto values_pointer = value_to_bin_thread.get() + bin_begin;
                auto hashes_pointer = hash_to_bin_thread.get() + bin_begin;
                auto output_pointer = output.data() + bin_idx * total_size;

                // Merges an entire row of entries in the table, eliminating empty slots
                // Since the addresses of the incoming std::arrays in the encoding process need to be continuous,
                // it is necessary to merge the entries of multiple threads belonging to the same bin

                auto bin_pos = bin_size_thread[0][bin_idx];
                assert(hashes_pointer == get_hash_bin_thread(bin_idx, 0));

                for (auto thread_idx = 1; thread_idx < thread_num; thread_idx++)
                {
                    auto size = bin_size_thread[thread_idx][bin_idx];
                    auto hash_thread = get_hash_bin_thread(bin_idx, thread_idx);
                    auto value_thread = get_value_bin_thread(bin_idx, thread_idx);

                    memmove(hashes_pointer + bin_pos, hash_thread, size * sizeof(block));

                    for (auto j = 0; j < size; j++, bin_pos++)
                    {
                        values_pointer[bin_pos] = value_thread[j];
                    }
                }

                // Initialization process, similar to OKVS::set_keys
                memset(paxos.col_weights, 0, sizeof(idx_type) * sparse_size);
                {
                    paxos.h_dense = hashes_pointer;
                    paxos.sparse_weight = sparse_weight;
                    paxos.weight_nodes.reset(new typename OKVS<idx_type, dense_type, value_type>::weight_node[sparse_size]);

                    paxos.weight_set.resize(200);
                    paxos.mModVals.reserve(sparse_weight);
                    paxos.mMods.reserve(sparse_weight);
                    for (uint8_t ii = 0; ii < sparse_weight; ++ii)
                    {
                        const idx_type temp = sparse_size - ii;
                        paxos.mModVals[ii] = (temp);
                        paxos.mMods[ii] = (gen_divider(temp));
                    }
                    paxos.set_sparse();
                    paxos.weight_statistic();
                    paxos.init_hcols();
                }
                paxos.encode(values_pointer, output_pointer, prng);
#ifndef NDEBUG

                // Check in advance that the single encode process is executed correctly,
                // this process will not happen during the actual execution

                std::vector<value_type> temp(total_size);
                memcpy(temp.data(), output_pointer, total_size * sizeof(value_type));
                std::vector<value_type> v2(bin_size);
                block t;
                paxos.decode(&keys[get_item_bin_thread(bin_idx, thread_id)[0]], 1, output_pointer,values_pointer, &t);
                paxos.decode(0, bin_size, output_pointer, v2.data(), paxos.h_dense);
                // std::cout << bin_size << "  " << output_pointer << " " << bin_idx << " " << Block::BlockToInt64(output_pointer[0])
                //           << " " << Block::BlockToInt64(values_pointer[bin_size - 1]) << " " << paxos.h_sparse[bin_size - 1][0] << std::endl;
                
                /**for (auto ij = 0; ij < v2.size(); ij++)
                {
                    if (v2[ij] != values_pointer[ij])
                    {
                        throw;
                    }
                }**/
#endif
            }
        }
    }
}

inline uint64_t get_bin_idx(block *p)
{
    auto p64 = (uint64_t *)p;
    auto p32 = (uint32_t *)p;
    return p64[0] ^ p64[1] ^ p32[3];
}

// template <DenseType dense_type>
// template <typename idx_type>
// void Baxos<dense_type>::impl_decode_bin(uint64_t len, block *keys_indexes, block *output,
//                                         OKVS<idx_type, dense_type> &paxos)
// {
// }

template <DenseType dense_type, typename value_type>
template <typename idx_type>
inline void Baxos<dense_type, value_type>::impl_decode_batch(block *keys, value_type *values, uint64_t batch_len, value_type *output)
{
    // Decode is performed in units of decode_size groups
    auto decode_size = std::min(uint64_t(512), batch_len);
    std::vector<std::vector<block>> batches(bin_num, std::vector<block>(decode_size));
    std::vector<std::vector<uint64_t>> keys_idxes(bin_num, std::vector<uint64_t>(decode_size));
    std::vector<uint64_t> batch_sizes(bin_num);

    // Initialize small-sized single-threaded OKVS
    OKVS<idx_type, dense_type, value_type> paxos;
    {
        paxos.item_num = decode_size;
        paxos.sparse_weight = sparse_weight;
        paxos.sparse_size = sparse_size;
        paxos.dense_size = dense_size;
        paxos.total_size = total_size;
        paxos.seed = seed;
        paxos.statistical_security_parameter = statistical_security_parameter;
        paxos.g_limit = g_limit;
        for (uint8_t i = 0; i < sparse_weight; ++i)
        {
            auto temp = sparse_size - i;
            paxos.mModVals.emplace_back(temp);
            paxos.mMods.emplace_back(gen_divider(temp));
        }
    }
    std::array<block, 32> buffer;
    std::vector<value_type> value_buffer(decode_size);
    std::array<uint64_t, 32> bin_idxes;
    divider divider = gen_divider(bin_num);
    uint64_t i = 0;
    for (; i + 32 <= batch_len; i += 32, keys += 32)
    {
        paxos.set_dense(keys, 32, buffer.data());

        for (auto j = 0; j < 32; j += 8)
        {
            auto bin_idx_pointer = bin_idxes.data() + j;
            auto buffer_pointer = buffer.data() + j;

            *bin_idx_pointer++ = get_bin_idx(buffer_pointer++);
            *bin_idx_pointer++ = get_bin_idx(buffer_pointer++);
            *bin_idx_pointer++ = get_bin_idx(buffer_pointer++);
            *bin_idx_pointer++ = get_bin_idx(buffer_pointer++);
            *bin_idx_pointer++ = get_bin_idx(buffer_pointer++);
            *bin_idx_pointer++ = get_bin_idx(buffer_pointer++);
            *bin_idx_pointer++ = get_bin_idx(buffer_pointer++);
            *bin_idx_pointer = get_bin_idx(buffer_pointer);
        }
        doMod32(bin_idxes.data(), &divider, bin_num);

        for (auto k = 0; k < 32; k++)
        {

            auto bin_idx = bin_idxes[k];
            auto batch_size = batch_sizes[bin_idx]++;
            batches[bin_idx][batch_size] = buffer[k];
            keys_idxes[bin_idx][batch_size] = i + k;
            // If after processing the current key,
            // the decode_size size group (the unit of decoding) is just filled,
            // then start decoding immediately
            if (batch_size + 1 == decode_size)
            {
                auto output_pointer = output + bin_idx * total_size;
                auto idxes = keys_idxes[bin_idx];
                paxos.h_dense = batches[bin_idx].data();
                paxos.decode(nullptr, decode_size, output_pointer, value_buffer.data(), batches[bin_idx].data());

                for (auto ii = 0; ii < decode_size; ii++)
                {
                    values[idxes[ii]] = value_buffer[ii];
                }
                batch_sizes[bin_idx] = 0;
            }
        }
    }
    // Perform decoding preprocessing on the remaining groups of less than 32 elements
    for (; i < batch_len; i++, keys++)
    {
        paxos.set_dense(keys, 1, buffer.data());
        auto bin_idx = get_bin_idx(buffer.data()) % bin_num;

        auto &batch_bin = batches[bin_idx];

        auto batch_size = batch_sizes[bin_idx]++;
        batch_bin[batch_size] = buffer[0];
        keys_idxes[bin_idx][batch_size] = i;

        // Similarly, once the number of processing reaches decode_size, start decoding immediately
        if (batch_size + 1 == decode_size)
        {
            auto output_pointer = output + bin_idx * total_size;
            paxos.h_dense = batch_bin.data();
            paxos.decode(nullptr, decode_size, output_pointer, value_buffer.data(), batch_bin.data());
            for (auto ii = 0; ii < decode_size; ii++)
            {
                values[keys_idxes[bin_idx][ii]] = value_buffer[ii];
            }
            batch_sizes[bin_idx] = 0;
        }
    }

    // It is no longer required that the unit of decoding must be a group of decode_size size,
    // and handle bins with insufficient size
    for (auto bin_idx = 0; bin_idx < bin_num; bin_idx++)
    {
        auto batch_size = batch_sizes[bin_idx];
        if (batch_size)
        {
            auto output_pointer = output + bin_idx * total_size;
            // paxos.h_dense = batches[bin_idx].data();

            paxos.decode(nullptr, batch_size, output_pointer, value_buffer.data(), batches[bin_idx].data());
            // cout << batch_size << " " << output_pointer << " " << bin_idx << endl;
            for (auto ii = 0; ii < batch_size; ii++)
            {
                values[keys_idxes[bin_idx][ii]] = value_buffer[ii];
            }
        }
    }
}
template <DenseType dense_type, typename value_type>
template <typename idx_type>
inline void Baxos<dense_type, value_type>::impl_decode(const std::vector<block> &keys, std::vector<value_type> &values, const std::vector<value_type> &output, uint8_t thread_num)
{
    if (bin_num == 1)
    {
        OKVS<idx_type, dense_type, value_type> paxos(item_num_per_bin, sparse_weight, statistical_security_parameter, &seed);
        paxos.decode(keys.data(), keys.size(), output.data(), values.data());
        return;
    }
    omp_set_num_threads(thread_num);

    auto keys_size = keys.size();
    auto keys_begin = keys.data();
    auto values_begin = values.data();
#pragma omp parallel
    {
        // Assign the keys std::array and values ​​std::array to different threads
        uint8_t thread_id = omp_get_thread_num();
        uint64_t begin = (keys_size * thread_id) / thread_num;
        uint64_t len = keys_size * (thread_id + 1) / thread_num - begin;

        auto keys_pointer = keys_begin + begin;
        auto values_pointer = values_begin + begin;
        impl_decode_batch<idx_type>((block *)keys_pointer, values_pointer, len, (value_type *)output.data());
    }
}

template <DenseType dense_type, typename value_type>
inline void Baxos<dense_type, value_type>::solve(const std::vector<block> &keys, const std::vector<value_type> &values, std::vector<value_type> &output, PRG::Seed *prng, uint8_t thread_num)
{
    // Calculate the number of bits occupied by a single variable that occupies the largest space among member variables
    auto bit_len = log2_ceil(sparse_size + 1);

    // According to the calculated number of bits, select the appropriate function implementation
    if (bit_len <= 8)
    {
        impl_solve<uint8_t>(keys, values, output, prng, thread_num);
    }
    else if (bit_len <= 16)
    {
        impl_solve<uint16_t>(keys, values, output, prng, thread_num);
    }
    else if (bit_len <= 32)
    {
        impl_solve<uint32_t>(keys, values, output, prng, thread_num);
    }
    else if (bit_len <= 64)
    {
        impl_solve<uint64_t>(keys, values, output, prng, thread_num);
    }
}

template <DenseType dense_type, typename value_type>
inline void Baxos<dense_type, value_type>::decode(const std::vector<block> &keys, std::vector<value_type> &values, const std::vector<value_type> &output, uint8_t thread_num)
{
    auto bit_len = log2_ceil(sparse_size + 1);
    if (bit_len <= 8)
    {
        impl_decode<uint8_t>(keys, values, output, thread_num);
    }
    else if (bit_len <= 16)
    {
        impl_decode<uint16_t>(keys, values, output, thread_num);
    }
    else if (bit_len <= 32)
    {
        impl_decode<uint32_t>(keys, values, output, thread_num);
    }
    else if (bit_len <= 64)
    {
        impl_decode<uint64_t>(keys, values, output, thread_num);
    }
}


void test_baxos_BlockArrayValue()
{
    // We observe that when bin_size = n >> 7, the performance seems better than others.
    uint64_t n = 1ull << 20;
    uint64_t bin_size = 1 << 13;

    auto t = Baxos<gf_128>(n, bin_size, 3);
    std::vector<BlockArrayValue> out(t.bin_num * t.total_size);
    std::vector<BlockArrayValue> v(n);
    std::vector<BlockArrayValue> v2(n);
    
    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0);
    std::vector<block> k = PRG::GenRandomBlocks(seed, n);
    std::vector<block> v_pre = PRG::GenRandomBlocks(seed, n*(sizeof(BlockArrayValue)/sizeof(block)));
    memcpy(v.data(), &v_pre[0], sizeof(BlockArrayValue) * n);
    
    auto start = std::chrono::steady_clock::now();
    Baxos<gf_128, BlockArrayValue> baxos(n, bin_size, 3);
    uint8_t thread_num = 4;
    baxos.solve(k, v, out, 0, thread_num);
    auto end = std::chrono::steady_clock::now();
    std::cout << "encode"
              << ":" << std::chrono::duration<double, std::milli>(end - start).count() << " ms" << std::endl;
    start = std::chrono::steady_clock::now();
    
    Baxos<gf_128, BlockArrayValue> baxos2(n, bin_size, 3);
    baxos2.decode(k, v2, out, thread_num);

    end = std::chrono::steady_clock::now();
    std::cout << "decode"
              << ":" << std::chrono::duration<double, std::milli>(end - start).count() << " ms" << std::endl;
              
    for (auto i = 0; i < v.size(); i++)
    {
        if (v2[i]!= v[i])
        {
            throw;
        }
    }

}

void test_baxos_block()
{
    uint64_t n = 1ull << 20;
    // We observe that when bin_size = n >> 7, the performance seems better than others.
    uint64_t bin_size = 1 << 13;
    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0);

    std::vector<block> v = PRG::GenRandomBlocks(seed, n);
    std::vector<block> k = PRG::GenRandomBlocks(seed, n);
    auto t = Baxos<gf_128>(n, bin_size, 3);
    std::vector<block> out(t.bin_num * t.total_size);
    std::vector<block> v2(n);

    auto start = std::chrono::steady_clock::now();
    Baxos<gf_128> baxos(n, bin_size, 3);
    uint8_t thread_num = 4;
    baxos.solve(k, v, out, 0, thread_num);
    auto end = std::chrono::steady_clock::now();
    std::cout << "encode"
              << ":" << std::chrono::duration<double, std::milli>(end - start).count() << " ms" << std::endl;
    start = std::chrono::steady_clock::now();
    baxos.decode(k, v2, out, thread_num);

    end = std::chrono::steady_clock::now();
    std::cout << "decode"
              << ":" << std::chrono::duration<double, std::milli>(end - start).count() << " ms" << std::endl;
    for (auto i = 0; i < v.size(); i++)
    {
        if (!Block::Compare(v2[i], v[i]))
        {
            throw;
        }
    }

}
#endif
