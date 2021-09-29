#include <iostream>
#include <random>
#include <fstream>
#include <chrono>
#include <tuple>
#include "kalyna.h"
#include "aes.h"

#define RUN_CIPHER 1

#define RUN_AES 1
#define RUN_KALYNA 1

const std::string kTestFileName = "test.bin";
const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(uint8_t);
size_t const microseconds_in_a_second = 1000 * 1000;
size_t const test_runs = 1u << 3u;

void generate_messages_internal(int length, std::vector<uint8_t> &buffer, std::vector<std::vector<uint8_t> > &result) {
  if (buffer.size() == length) {
    result.push_back(buffer);
  } else {
    for (int value = 0; value < 256; value++) {
      buffer.push_back(value);
      generate_messages_internal(length, buffer, result);
      buffer.pop_back();
    }
  }
}
std::vector<std::vector<uint8_t> > generate_messages(int length) {
  std::vector<std::vector<uint8_t> > result;
  std::vector<uint8_t> buffer;
  generate_messages_internal(length, buffer, result);
  return result;
}

void Ciphers(uint8_t input_data[], const int &kBytes) {
#if RUN_AES
  const int keyLen = 256;
  AES aes(keyLen);
  unsigned char iv[] =
      {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
       0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  unsigned int len;

  auto const &before_aes = std::chrono::high_resolution_clock::now();

  for (size_t test = 0; test < test_runs; test++) {
    unsigned char *out = aes.EncryptCFB(input_data ,6, kBytes, key, iv,len);
    unsigned char *innew = aes.DecryptCFB(out,6, kBytes, key,iv);
    assert(!memcmp(innew, input_data, kBytes));
    delete[] out;
  }

  auto const &after_aes = std::chrono::high_resolution_clock::now();

  printf(
      "AES(%u) CFB on %u bytes took %.6lfs\n",
      keyLen,
      kBytes,
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_aes - before_aes).count())
          / static_cast< double >(test_runs * microseconds_in_a_second));

#endif //AES

#if RUN_KALYNA
  Kalyna kalyna(256, 256);
  uint64_t key44_e[4] =
      {0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL, 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL};
  kalyna.KeyExpand(key44_e);
  uint64_t input[4], ciphered_text[4], output[4];

  auto const &before_kalyna = std::chrono::high_resolution_clock::now();

  for (size_t test = 0; test < test_runs; test++) {
    for (int i = 0; i < kBytes; i += BLOCK_BYTES_LENGTH) {
      memcpy(input, input_data, BLOCK_BYTES_LENGTH);
      kalyna.Encipher(input, ciphered_text);
      kalyna.Decipher(ciphered_text, output);
      assert(memcmp(input, output, sizeof(input)));
    }
  }

  auto const &after_kalyna = std::chrono::high_resolution_clock::now();

  printf(
      "Kalyna(%u, %u) on %u bytes took %.6lfs\n",
      256, 256,
      kBytes,
      static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_kalyna - before_kalyna).count())
          / static_cast< double >(test_runs * microseconds_in_a_second));

#endif // Kalyna

}

inline bool FileExists(const std::string &name) {
  std::ifstream f(name.c_str());
  return f.good();
}

void GenerateData(const int &kBytes) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> distrib(std::numeric_limits<uint8_t>::min(), std::numeric_limits<uint8_t>::max());

  std::cout << "Starting data generation" << std::endl;

  if (!FileExists(kTestFileName)) {
    std::ofstream test_file;
    test_file.open(kTestFileName, std::ios::out | std::ios::binary);

    if (test_file.is_open()) {
      for (int i = 0; i < kBytes; i++) {
        test_file << (unsigned char) distrib(gen);
      }
      test_file.close();
    }
  }

  std::cout << "Data generation finished" << std::endl;
}

void Measurement(const int &kBytes = 1000000) {

  auto *input_data = new uint8_t[kBytes];
  if (FileExists(kTestFileName)) {
    std::ifstream input(kTestFileName.c_str(), std::ios::in | std::ios::binary);
    if (input.is_open()) {
      for (int i = 0; i < kBytes; i++) {
        input >> input_data[i];
      }
    }
  } else {
    std::cout << "Couldn't find testing file" << std::endl;
    exit(1);
  }

#if RUN_CIPHER
  Ciphers(input_data, kBytes);
#endif // CIPHER


  delete[] input_data;
}

int main() {
  GenerateData(1000000000);
  Measurement(1000000);
  exit(0);
  //return 0;
}