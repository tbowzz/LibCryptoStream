#include "Cipher.h"

#include <iostream>
#include "Aes.h"

#define KEY_SIZE 32
#define SECRET_KEY "$fkdj@@ekl|fi4fgKEnUifklQh435#$%"

Cipher::Cipher()
{
	std::string secretKey = SECRET_KEY;
	for (unsigned int ii = 0; ii < KEY_SIZE; ii++) // Port the key to the key_ vector
	{
		key_.push_back((uint8_t)secretKey.at(ii));
	}

	iv_.resize(BLOCK_SIZE); // Init the IV size

	EVP_add_cipher(EVP_aes_256_cbc()); // Init the AES-256 cipher
}


Cipher::~Cipher()
{
	// Cleanup
	OPENSSL_cleanse(key_.data(), KEY_SIZE);
	OPENSSL_cleanse(iv_.data(), BLOCK_SIZE);

	key_.clear();
	iv_.clear();
}


bool Cipher::encrypt(std::string inputFileName, std::string outputFileName, std::string ivFileName)
{
	std::vector<uint8_t> inputBytes;
	fileToBytes(inputFileName, inputBytes);

	std::vector<uint8_t> outputBytes;
	std::vector<uint8_t> ivBytes;
	bool retVal = encrypt(inputBytes, outputBytes, ivBytes);
	if (!retVal) { return false; }

	if (!bytesToFile(outputBytes, outputFileName)) { return false; }
	if (!bytesToFile(ivBytes, ivFileName)) { return false; }

	return true;
}


bool Cipher::encrypt(std::vector<uint8_t> &input, std::vector<uint8_t> &output, std::vector<uint8_t> &decryptionIv)
{
	decryptionIv.clear(); // Ensure a clean start
	decryptionIv.resize(BLOCK_SIZE);

	if (!generateParams()) // generate the IV
	{
		return false;
	}

	EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
	int retVal = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key_.data(), iv_.data());
	if (retVal != 1)
	{
		printf("EVP_EncryptInit_ex failed\n");
		return false;
	}

	// Recovered text expands upto BLOCK_SIZE
	output.resize(input.size()+BLOCK_SIZE);

	int out_len1 = (int)output.size();
	retVal = EVP_EncryptUpdate(ctx.get(), output.data(), &out_len1, input.data(), (int)input.size());
	if (retVal != 1)
	{
		printf("EVP_EncryptUpdate failed\n");
		return false;
	}

	int out_len2 = (int)output.size() - out_len1;
	retVal = EVP_EncryptFinal_ex(ctx.get(), output.data() + out_len1, &out_len2);
	if (retVal != 1)
	{
		printf("EVP_EncryptFinal_ex failed\n");
		return false;
	}

	// Set cipher text size now that we know it
	output.resize(out_len1 + out_len2);

	decryptionIv = iv_; // save IV to output vector

	return true;
}


bool Cipher::decrypt(std::string inputFileName, std::string outputFileName, std::string ivFileName)
{
	std::vector<uint8_t> inputBytes;
	fileToBytes(inputFileName, inputBytes);

	std::vector<uint8_t> ivBytes;
	fileToBytes(ivFileName, ivBytes);

	std::vector<uint8_t> outputBytes;
	bool retVal = decrypt(inputBytes, outputBytes, ivBytes);
	if (!retVal) { return false; }

	if (!bytesToFile(outputBytes, outputFileName)) { return false; }

	return true;
}


bool Cipher::decrypt(std::vector<uint8_t> &input, std::vector<uint8_t> &output, std::vector<uint8_t> &decryptionIv)
{
	if (decryptionIv.size() != BLOCK_SIZE)
	{
		printf("ERROR: Decryption IV must be of size %d\n", BLOCK_SIZE);
		return false;
	}

	EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
	int retVal = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key_.data(), decryptionIv.data());
	if (retVal != 1)
	{
		printf("EVP_DecryptInit_ex failed\n");
		return false;
	}

	// Recovered text contracts upto BLOCK_SIZE
	output.resize(input.size());
	int out_len1 = (int)output.size();

	retVal = EVP_DecryptUpdate(ctx.get(), output.data(), &out_len1, input.data(), (int)input.size());
	if (retVal != 1)
	{
		printf("EVP_DecryptUpdate failed\n");
		return false;
	}

	int out_len2 = (int)output.size() - out_len1;
	retVal = EVP_DecryptFinal_ex(ctx.get(), output.data() + out_len1, &out_len2);
	if (retVal != 1)
	{
		printf("EVP_DecryptFinal_ex failed\n");
		return false;
	}

	// Set recovered text size now that we know it
	output.resize(out_len1 + out_len2);

	return true;
}


bool Cipher::generateParams()
{
	// Generate the IV. Helper function for encrypt().
	int retVal = RAND_bytes(iv_.data(), BLOCK_SIZE);
    if (retVal != 1)
	{
		printf("ERROR: Unable to generate IV\n");
		return false;
	}

	return true;
}


bool Cipher::stringToBytes(std::string &input, std::vector<uint8_t> &bytes)
{
	for (unsigned int ii = 0; ii < input.size(); ii++)
	{
		bytes.push_back(input.at(ii));
	}

	return true;
}


bool Cipher::bytesToString(std::vector<uint8_t> &bytes, std::string &output)
{
	output.clear();

	for (unsigned int ii = 0; ii < bytes.size(); ii++)
	{
		output += bytes[ii];
	}

	return true;
}


bool Cipher::fileToBytes(std::string &filePath, std::vector<uint8_t> &bytes)
{
	FILE* fp = fopen(filePath.c_str(), "rb");
	if (fp == NULL)
	{
		printf("ERROR: File does not exist\n");
		return false;
	}

	fseek(fp, 0, SEEK_END); // Go to the end of the file
	uint64_t length = ftell(fp); // Get length of file
	rewind(fp);

	bytes.resize(length);
	size_t readCount = 1;
	int retVal = fread(bytes.data(), length, readCount, fp);
	fclose(fp);
	if (retVal != (int)readCount)
	{
		printf("ERROR: File read failed (%d)\n", retVal);
		return false;
	}

	return true;
}


bool Cipher::fileToString(std::string &filePath, std::string &contents)
{
	FILE* fp = fopen(filePath.c_str(), "r");
	if (fp == NULL)
	{
		printf("ERROR: File does not exist\n");
		return false;
	}

	fseek(fp, 0, SEEK_END); // Go to the end of the file
	uint64_t length = ftell(fp); // Get length of file
	rewind(fp);

	char buf[length];
	size_t readCount = 1;
	int retVal = fread(buf, length, readCount, fp);
	fclose(fp);
	if (retVal != (int)readCount)
	{
		printf("ERROR: File read failed (%d)\n", retVal);
		return false;
	}

	contents = buf;

	return true;
}


bool Cipher::bytesToFile(std::vector<uint8_t> &bytes, std::string &filePath)
{
	FILE* fp = fopen(filePath.c_str(), "wb");
	if (fp == NULL)
	{
		printf("ERROR: Unable to open file for writing\n");
		return false;
	}

	int retVal = fwrite(bytes.data(), sizeof(uint8_t), bytes.size(), fp);
	fclose(fp);
	if (retVal != (int)bytes.size())
	{
		printf("ERROR: File write failed(%d)\n", retVal);
		return false;
	}

	return true;
}
