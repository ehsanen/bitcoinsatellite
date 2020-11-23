
#include <boost/test/unit_test.hpp>
#include <fec.h>
#include <memory>
#include <test/setup_common.h>
#include <util/system.h>

#define DIV_CEIL(a, b) (((a) + (b)-1) / (b))

constexpr char* hex_digits = "0123456789ABCDEF";

struct TestData {
    std::vector<std::vector<unsigned char>> encoded_blocks;
    std::vector<uint32_t> chunk_ids;
    std::vector<unsigned char> original_block;
};

/**
 * Fills the input vector with random generated hex values
 */
void fill_with_random_data(std::vector<unsigned char>& vec)
{
    auto rand_hex_gen = [&]() {
        auto h1 = hex_digits[(rand() % 16)];
        auto h2 = hex_digits[(rand() % 16)];
        return h1 + h2;
    };
    std::generate(vec.begin(), vec.end(), rand_hex_gen);
}

/**
 * Generates some random data and encodes them using one of the encoders.
 * The function will fill in the input generated_test_data parameter with
 * the encoded chunks as well as their chunk_ids and the original randomly
 * generated data to be used in tests.
 */
void generate_encoded_chunks(size_t block_size, TestData& generated_test_data)
{
    size_t block_fec_chunk_count = DIV_CEIL(block_size, FEC_CHUNK_SIZE);

    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>
        block_fec_chunks(std::piecewise_construct,
            std::forward_as_tuple(new FECChunkType[block_fec_chunk_count]),
            std::forward_as_tuple(block_fec_chunk_count));

    generated_test_data.original_block.resize(block_size);
    fill_with_random_data(generated_test_data.original_block);

    FECEncoder block_encoder(&generated_test_data.original_block, &block_fec_chunks);

    bool all_successful = true;
    for (size_t vector_idx = 0; vector_idx < block_fec_chunks.second.size(); vector_idx++) {
        // build the chunk and make sure chunk_id is set correctly afterwards
        if (!block_encoder.BuildChunk(vector_idx) || block_fec_chunks.second[vector_idx] <= 0) {
            break;
        }
        std::vector<unsigned char> encoded_block(FEC_CHUNK_SIZE);
        memcpy(encoded_block.data(), &block_fec_chunks.first[vector_idx], FEC_CHUNK_SIZE);
        generated_test_data.encoded_blocks.emplace_back(encoded_block);
        generated_test_data.chunk_ids.emplace_back(block_fec_chunks.second[vector_idx]);
    }
}

BOOST_FIXTURE_TEST_SUITE(fec_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fec_BuildChunk_invalid_idx_test)
{
    constexpr size_t chunk_count = 5;
    constexpr size_t block_size = chunk_count * FEC_CHUNK_SIZE;

    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>
        block_fec_chunks(std::piecewise_construct,
            std::forward_as_tuple(new FECChunkType[chunk_count]),
            std::forward_as_tuple(chunk_count));

    std::vector<unsigned char> original_block(block_size);
    fill_with_random_data(original_block);

    FECEncoder block_encoder(&original_block, &block_fec_chunks);

    BOOST_CHECK_THROW(block_encoder.BuildChunk(block_fec_chunks.second.size()), std::runtime_error);
    BOOST_CHECK_THROW(block_encoder.BuildChunk(block_fec_chunks.second.size() + 1), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(fec_BuildChunk_do_not_overwrite_if_not_asked)
{
    constexpr size_t chunk_count = 5;
    constexpr size_t block_size = chunk_count * FEC_CHUNK_SIZE;

    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>
        block_fec_chunks(std::piecewise_construct,
            std::forward_as_tuple(new FECChunkType[chunk_count]),
            std::forward_as_tuple(chunk_count));

    std::vector<unsigned char> original_block(block_size);
    fill_with_random_data(original_block);

    block_fec_chunks.second[0] = 123;

    FECEncoder block_encoder(&original_block, &block_fec_chunks);
    size_t vector_idx = 0;
    BOOST_CHECK(block_encoder.BuildChunk(vector_idx, false));
}

BOOST_AUTO_TEST_CASE(fec_BuildChunk_small_chunk)
{
    constexpr size_t chunk_count = 1;
    constexpr size_t block_size = 5;

    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>
        block_fec_chunks(std::piecewise_construct,
            std::forward_as_tuple(new FECChunkType[chunk_count]),
            std::forward_as_tuple(chunk_count));

    std::vector<unsigned char> original_block(block_size);
    fill_with_random_data(original_block);

    FECEncoder block_encoder(&original_block, &block_fec_chunks);

    size_t vector_idx = 0;
    BOOST_CHECK(block_encoder.BuildChunk(vector_idx));
    BOOST_CHECK_EQUAL(block_fec_chunks.second[vector_idx], vector_idx);
}

BOOST_AUTO_TEST_CASE(fec_BuildChunk_successful_Wirehair_encoder)
{
    constexpr size_t chunk_count = CM256_MAX_CHUNKS;
    constexpr size_t block_size = chunk_count * FEC_CHUNK_SIZE;

    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>
        block_fec_chunks(std::piecewise_construct,
            std::forward_as_tuple(new FECChunkType[chunk_count]),
            std::forward_as_tuple(chunk_count));

    std::vector<unsigned char> original_block(block_size);
    fill_with_random_data(original_block);

    FECEncoder block_encoder(&original_block, &block_fec_chunks);

    bool all_successful = true;
    for (size_t vector_idx = 0; vector_idx < block_fec_chunks.second.size(); vector_idx++) {
        // build the chunk and make sure chunk_id is set correctly afterwards
        if (!block_encoder.BuildChunk(vector_idx) || block_fec_chunks.second[vector_idx] <= 0) {
            all_successful = false;
            break;
        }
    }

    BOOST_CHECK(all_successful);
}

BOOST_AUTO_TEST_CASE(fec_BuildChunk_successful_cm256_encoder)
{
    // Choose block size bigger than 1 chunk and smaller than
    // CM256_MAX_CHUNKS to force using cm256 encoder
    size_t block_size = FEC_CHUNK_SIZE + 1;
    size_t block_fec_chunk_count = DIV_CEIL(block_size, FEC_CHUNK_SIZE);

    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>
        block_fec_chunks(std::piecewise_construct,
            std::forward_as_tuple(new FECChunkType[block_fec_chunk_count]),
            std::forward_as_tuple(block_fec_chunk_count));

    std::vector<unsigned char> test_block(FEC_CHUNK_SIZE + 1);
    fill_with_random_data(test_block);

    FECEncoder block_encoder(&test_block, &block_fec_chunks);

    bool all_successful = true;
    for (size_t vector_idx = 0; vector_idx < block_fec_chunks.second.size(); vector_idx++) {
        // build the chunk and make sure chunk_id is set correctly afterwards
        if (!block_encoder.BuildChunk(vector_idx) || block_fec_chunks.second[vector_idx] <= 0) {
            all_successful = false;
            break;
        }
    }
    BOOST_CHECK(all_successful);
}


BOOST_AUTO_TEST_CASE(fec_ProvideChunk_invalid_chunk_id_test)
{
    // Set data size in a way that CHUNK_COUNT_USES_CM256 is true
    constexpr size_t chunk_count = 2;
    constexpr size_t data_size = chunk_count * FEC_CHUNK_SIZE;
    std::vector<unsigned char> chunk(data_size);
    fill_with_random_data(chunk);

    FECDecoder decoder(data_size);
    BOOST_CHECK(!decoder.ProvideChunk(chunk.data(), 256));

    // Set data size in a way that CHUNK_COUNT_USES_CM256 is true
    constexpr size_t chunk_count2 = CM256_MAX_CHUNKS;
    constexpr size_t data_size2 = chunk_count2 * FEC_CHUNK_SIZE + 1;
    std::vector<unsigned char> chunk2(data_size2);
    fill_with_random_data(chunk2);

    FECDecoder decoder2(data_size2);
    BOOST_CHECK(!decoder2.ProvideChunk(chunk2.data(), FEC_CHUNK_COUNT_MAX + 1));
    BOOST_CHECK(!decoder.DecodeReady());
}

BOOST_AUTO_TEST_CASE(fec_ProvideChunk_small_chunk_count)
{
    // For chunk_count < 2
    size_t data_size = 5;
    FECDecoder decoder(data_size);
    std::vector<unsigned char> chunk(data_size + 1);
    fill_with_random_data(chunk);

    // decode chunk 0
    BOOST_CHECK(decoder.ProvideChunk(chunk.data(), 0));

    // Make sure the chunk has been added
    BOOST_CHECK(decoder.HasChunk(0));

    // when chunk_count < 2, the whole chunk should be available in tmp_chunk
    const void* tmp_chunk = decoder.GetDataPtr(0);
    const char* tmp_chunk_char = static_cast<const char*>(tmp_chunk);
    BOOST_CHECK_EQUAL(strlen(tmp_chunk_char), chunk.size());

    bool are_equal = true;
    for (size_t i = 0; i < data_size; i++) {
        if (tmp_chunk_char[i] != chunk[i]) {
            are_equal = false;
            break;
        }
    }
    BOOST_CHECK(are_equal);

    // calling again should return true immediately
    BOOST_CHECK(decoder.ProvideChunk(chunk.data(), 0));
    BOOST_CHECK(decoder.DecodeReady());
}

BOOST_AUTO_TEST_CASE(fec_ProvideChunk_cm256_min_chunks)
{
    TestData test_data;
    size_t num_chunks = 2;
    size_t data_size = FEC_CHUNK_SIZE * num_chunks;
    generate_encoded_chunks(data_size, test_data);

    if (test_data.encoded_blocks.size() != test_data.chunk_ids.size()) {
        BOOST_TEST_MESSAGE("Failed to generate correct test data, this test will be skipped!");
        return;
    }

    FECDecoder decoder(data_size);
    for (size_t i = 0; i < test_data.encoded_blocks.size(); i++) {
        decoder.ProvideChunk(test_data.encoded_blocks[i].data(), test_data.chunk_ids[i]);
    }
    BOOST_CHECK(decoder.DecodeReady());
    std::vector<unsigned char> decoded_data(data_size);
    for (size_t i = 0; i < num_chunks; i++)
        memcpy(&decoded_data[i * FEC_CHUNK_SIZE], decoder.GetDataPtr(i), FEC_CHUNK_SIZE);

    BOOST_CHECK_EQUAL(decoded_data.size(), test_data.original_block.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data.begin(), decoded_data.end(),
        test_data.original_block.begin(), test_data.original_block.end());
}

BOOST_AUTO_TEST_CASE(fec_ProvideChunk_cm256_max_chunks)
{
    TestData test_data;
    size_t num_chunks = CM256_MAX_CHUNKS;
    size_t data_size = FEC_CHUNK_SIZE * num_chunks;
    generate_encoded_chunks(data_size, test_data);

    if (test_data.encoded_blocks.size() != test_data.chunk_ids.size()) {
        BOOST_TEST_MESSAGE("Failed to generate correct test data, this test will be skipped!");
        return;
    }

    FECDecoder decoder(data_size);
    for (size_t i = 0; i < test_data.encoded_blocks.size(); i++) {
        decoder.ProvideChunk(test_data.encoded_blocks[i].data(), test_data.chunk_ids[i]);
    }
    BOOST_CHECK(decoder.DecodeReady());
    std::vector<unsigned char> decoded_data(data_size);
    for (size_t i = 0; i < num_chunks; i++)
        memcpy(&decoded_data[i * FEC_CHUNK_SIZE], decoder.GetDataPtr(i), FEC_CHUNK_SIZE);

    BOOST_CHECK_EQUAL(decoded_data.size(), test_data.original_block.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data.begin(), decoded_data.end(),
        test_data.original_block.begin(), test_data.original_block.end());
}

BOOST_AUTO_TEST_CASE(fec_ProvideChunk_wirehair)
{
    TestData test_data;
    size_t num_chunks = CM256_MAX_CHUNKS + 1;
    size_t data_size = FEC_CHUNK_SIZE * num_chunks;
    generate_encoded_chunks(data_size, test_data);

    if (test_data.encoded_blocks.size() != test_data.chunk_ids.size()) {
        BOOST_TEST_MESSAGE("Failed to generate correct test data, this test will be skipped!");
        return;
    }

    FECDecoder decoder(data_size);
    for (size_t i = 0; i < test_data.encoded_blocks.size(); i++) {
        decoder.ProvideChunk(test_data.encoded_blocks[i].data(), test_data.chunk_ids[i]);
    }
    BOOST_CHECK(decoder.DecodeReady());
    std::vector<unsigned char> decoded_data(data_size);
    for (size_t i = 0; i < num_chunks; i++)
        memcpy(&decoded_data[i * FEC_CHUNK_SIZE], decoder.GetDataPtr(i), FEC_CHUNK_SIZE);

    BOOST_CHECK_EQUAL(decoded_data.size(), test_data.original_block.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded_data.begin(), decoded_data.end(),
        test_data.original_block.begin(), test_data.original_block.end());
}


BOOST_AUTO_TEST_SUITE_END()