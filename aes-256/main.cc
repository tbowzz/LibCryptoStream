#include "Cipher.h"
#include "stdio.h"

void testStringEncryptDecrypt(std::vector<std::string> args);
void testFileEncrypt(std::vector<std::string> args);
void testFileDecrypt(std::vector<std::string> args);
void printUsage();

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		printUsage();
		return -1;
	}

	std::vector<std::string> args;
	for (int ii = 1; ii < argc; ii++) { args.push_back(argv[ii]); }
	// args contains all argv strings after the executable name
	
	if (args.size() == 4)
	{
		if (args[0].compare("encrypt") == 0)
		{
			testFileEncrypt(args);
			return 0;
		}
		else if (args[0].compare("decrypt") == 0)
		{
			testFileDecrypt(args);
			return 0;
		}
		else
		{
			printUsage();
			return -1;
		}
	}
	if (args.size() == 2)
	{
		if (args[0].compare("string") == 0)
		{
			testStringEncryptDecrypt(args);
			return 0;
		}
		else
		{
			printUsage();
			return -1;
		}
	}
	else
	{
		printUsage();
		return -1;
	}

	return 0;
}


void testStringEncryptDecrypt(std::vector<std::string> args)
{
	std::string plaintext = args[1];
	std::vector<uint8_t> plainBytes;
	Cipher::stringToBytes(plaintext, plainBytes);

	Cipher cipher;
	std::vector<uint8_t> cipherBytes;
	std::vector<uint8_t> decryptionIv;
	bool retVal = cipher.encrypt(plainBytes, cipherBytes, decryptionIv);
	if (retVal)
	{
		// Print results as an example
		std::string ciphertext;
		Cipher::bytesToString(cipherBytes, ciphertext);
		std::string decryptionIvText;
		Cipher::bytesToString(decryptionIv, decryptionIvText);

		printf("Encrypted: \"%s\"\n", plaintext.c_str());
		printf("ciphertext: \"%s\"\n", ciphertext.c_str());
		printf("Decryption IV: \"%s\"\n", decryptionIvText.c_str());
	}
	else
	{
		printf("ERROR: Could not encrypt\n");
		return;
	}

	// decrypt it back as an example
	std::vector<uint8_t> recoveredBytes;
	retVal = cipher.decrypt(cipherBytes, recoveredBytes, decryptionIv);
	if (retVal)
	{
		std::string recoveredText;
		Cipher::bytesToString(recoveredBytes, recoveredText);
		printf("\nDecrypted back: \"%s\"\n", recoveredText.c_str());
	}
	else
	{
		printf("ERROR: Could not decrypt\n");
		return;
	}
}


void testFileEncrypt(std::vector<std::string> args)
{
	std::string plaintextFile = args[1];
	std::string encryptedFile = args[2];
	std::string ivFile = args[3];

	Cipher cipher;
	bool retVal = cipher.encrypt(plaintextFile, encryptedFile, ivFile);
	if (retVal)
	{
		printf("Encrypted \"%s\"\n", plaintextFile.c_str());
		printf("Ciphertext saved to \"%s\"\n", encryptedFile.c_str());
		printf("Decryption IV saved to \"%s\"\n", ivFile.c_str());
	}
	else
	{
		printf("ERROR: Could not encrypt\n");
		return;
	}
}


void testFileDecrypt(std::vector<std::string> args)
{
	std::string encryptedFile = args[1];
	std::string plaintextFile = args[2];
	std::string ivFile = args[3];

	Cipher cipher;
	bool retVal = cipher.decrypt(encryptedFile, plaintextFile, ivFile);
	if (retVal)
	{
		printf("Decrypted \"%s\"\n", encryptedFile.c_str());
		printf("Plaintext saved to \"%s\"\n", plaintextFile.c_str());
	}
	else
	{
		printf("ERROR: Could not decrypt\n");
		return;
	}
}


void printUsage()
{
	printf("USAGE:  ./cipher encrypt plain.txt ciphertxt.bin iv.bin\n"
	             "\t./cipher decrypt ciphertxt.bin plain.txt iv.bin\n"
	             "\t./cipher string \"String you want encrypted, then decrypted\"\n");
}
