// DecryptDoc.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <Windows.h>
#include <wil\resource.h>
#include <algorithm>
#include <vector>

bool SetAESKeyAndMode(HCRYPTKEY* phKey, HCRYPTPROV* phProv, BYTE* pMem, DWORD bytes);
bool SetAESKey(HCRYPTKEY* phKey, HCRYPTPROV hProv, ALG_ID Algid, BYTE* pMem, DWORD bytes);
bool AESDecryptFile(HCRYPTKEY* phKey, HCRYPTPROV* phProv, std::string path);
bool AESSetIV(HCRYPTKEY* phKey, HCRYPTPROV* phProv, std::string fileName);

int main()
{
	wil::unique_hcryptprov hProvider;
	wil::unique_hcryptkey hKey;
	std::string key = "thosefilesreallytiedthefoldertogether";
	DWORD bytes = key.length();
	std::string path = ".\\BusinessPapers.doc";
	bool isOk = SetAESKeyAndMode(hKey.addressof(), hProvider.addressof(), (BYTE*)key.data(), bytes);
	if (isOk) {
		AESDecryptFile(hKey.addressof(), hProvider.addressof(), path);
	}
}

bool SetAESKeyAndMode(HCRYPTKEY* phKey, HCRYPTPROV* phProv, BYTE* pMem, DWORD bytes) {
	DWORD cipherMode = CRYPT_MODE_CBC;
	if (!CryptAcquireContext(phProv, nullptr, nullptr, PROV_RSA_AES, 0)) {
		if (GetLastError() != NTE_BAD_KEYSET)
			return false;
		if (!CryptAcquireContext(phProv, 0, 0, PROV_RSA_AES, CRYPT_NEWKEYSET))
			return false;
	}
	if (SetAESKey(phKey, *phProv, CALG_AES_256, pMem, bytes)) {
		if (CryptSetKeyParam(*phKey, KP_MODE, (const BYTE*)&cipherMode, 0)) {
			return true;
		}
		else {
			return false;
		}
	}

	return false;
}

bool SetAESKey(HCRYPTKEY* phKey, HCRYPTPROV hProv, ALG_ID Algid, BYTE* pMem, DWORD bytes) {
	wil::unique_hcrypthash hHash;
	if (!hProv || !phKey)
		return false;

	if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, hHash.addressof())) {
		return false;
	}

	if (CryptHashData(hHash.get(), pMem, bytes, 0)) {
		std::vector<uint8_t> sha1;
		DWORD hashSize;
		DWORD len = sizeof(DWORD);
		if (!::CryptGetHashParam(hHash.get(), HP_HASHSIZE, (BYTE*)&hashSize, &len, 0))
			return false;

		sha1.resize(len = hashSize);
		::CryptGetHashParam(hHash.get(), HP_HASHVAL, sha1.data(), &len, 0);
		if (CryptDeriveKey(hProv, Algid, hHash.get(), CRYPT_EXPORTABLE, phKey)) {
			return true;
		}
	}
	return false;
}

bool AESDecryptFile(HCRYPTKEY* phKey, HCRYPTPROV* phProv, std::string path) {
	auto pos = path.rfind('\\') + 1;
	std::string fileName = path.substr(pos, path.length() - pos);
	std::transform(fileName.begin(), fileName.end(), fileName.begin(), std::tolower);
	AESSetIV(phKey, phProv, fileName);



	wil::unique_hfile hFile(::CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr,
		OPEN_EXISTING, 0x80, nullptr));
	if (!hFile)
		return false;

	auto size = ::GetFileSize(hFile.get(), nullptr);

	DWORD blockLen;
	DWORD dataLen = 4;
	if (CryptGetKeyParam(*phKey, KP_BLOCKLEN, (BYTE*)&blockLen, &dataLen, 0)) {
		blockLen >>= 3;
		DWORD blockSize = 0x4000 - 0x4000 % blockLen;
		DWORD bufLen = 0;
		if (blockLen <= 1) {
			bufLen = blockSize;
		}
		else {
			bufLen = blockLen + blockSize;
		}
		bool final = false;

		wil::unique_hfile hWriteFile(::CreateFileA(".\\Test.jpg", GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ,
			nullptr, CREATE_ALWAYS, 0x80, nullptr));
		if (!hWriteFile)
			return false;
		SIZE_T bytes = 0;

		bytes = bufLen + 1;
		BYTE* pData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bytes);
		DWORD readBytes = 0;
		if (pData) {
			while (ReadFile(hFile.get(), pData, blockSize, &readBytes, nullptr)) {
				if (readBytes < blockSize) {
					final = true;
				}
				if (!CryptDecrypt(*phKey, 0, final, 0, pData, &readBytes)) {
					break;
				}
				if (!WriteFile(hWriteFile.get(), pData, readBytes, &readBytes, nullptr)) {
					break;
				}
			}
			if (final) {
				return true;
			}
		}
		HeapFree(GetProcessHeap(), 0, pData);
	}

	return false;
}

bool AESSetIV(HCRYPTKEY* phKey, HCRYPTPROV* phProv, std::string fileName) {
	DWORD blockLen;
	DWORD dataLen = 4;
	wil::unique_hcrypthash hHash;
	if (CryptGetKeyParam(*phKey, KP_BLOCKLEN, (BYTE*)&blockLen, &dataLen, 0)) {
		blockLen >>= 3;
		void* pMem = HeapAlloc(GetProcessHeap(), 0, blockLen);
		memset(pMem, 0, blockLen);
		if (CryptCreateHash(*phProv, CALG_MD5, 0, 0, hHash.addressof())) {
			if (hHash) {
				if (CryptHashData(hHash.get(), (BYTE*)fileName.data(), fileName.length(), 0)) {
					dataLen = 16;
					if (CryptGetHashParam(hHash.get(), HP_HASHVAL, (BYTE*)pMem, &dataLen, 0)) {
						if (CryptSetKeyParam(*phKey, KP_IV, (BYTE*)pMem, 0)) {
							return true;
						}
					}
				}
			}
		}
	}

}