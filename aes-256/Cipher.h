#pragma once

#include <string>
#include <vector>

#define BLOCK_SIZE 16

class Cipher
{
public:
	Cipher();
	virtual ~Cipher();

	bool encrypt(std::string inputFileName, std::string outputFileName, std::string ivFileName);
	bool encrypt(std::vector<uint8_t> &input, std::vector<uint8_t> &output, std::vector<uint8_t> &decryptionIv);

	bool decrypt(std::string inputFileName, std::string outputFileName, std::string ivFileName);
	bool decrypt(std::vector<uint8_t> &input, std::vector<uint8_t> &output, std::vector<uint8_t> &decryptionIv);

	// Utility functions
	static bool stringToBytes(std::string &input, std::vector<uint8_t> &bytes);
	static bool bytesToString(std::vector<uint8_t> &bytes, std::string &output);
	static bool fileToBytes(std::string &filePath, std::vector<uint8_t> &bytes);
	static bool fileToString(std::string &filePath, std::string &contents);
	static bool bytesToFile(std::vector<uint8_t> &bytes, std::string &filePath);

private:
	bool generateParams();

	std::vector<uint8_t> key_;
	std::vector<uint8_t> iv_;
};
