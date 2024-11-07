//
// Created by athbe on 2024/10/25.
//

#include "cookies.h"
#include "TypeUtil.h"



std::vector<BYTE> GetKey::GetMasterKey(const std::string& filePath) {
    std::vector<BYTE> masterKey;

    std::ifstream file(filePath);
    if (!file.is_open()) {
        return {};
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::regex pattern("\"encrypted_key\":\"(.*?)\"");
    std::smatch matches;

    if (std::regex_search(content, matches, pattern) && matches.size() > 1) {
        std::string base64Key = matches[1].str();
        DWORD decodedLength = 0;
        CryptStringToBinaryA(base64Key.c_str(), base64Key.length(), CRYPT_STRING_BASE64, nullptr, &decodedLength, nullptr, nullptr);
        masterKey.resize(decodedLength);
        CryptStringToBinaryA(base64Key.c_str(), base64Key.length(), CRYPT_STRING_BASE64, masterKey.data(), &decodedLength, nullptr, nullptr);
    }

    if (masterKey.size() > 5) {
        masterKey.erase(masterKey.begin(), masterKey.begin() + 5);
    }

    DATA_BLOB inData = { static_cast<DWORD>(masterKey.size()), masterKey.data() };
    DATA_BLOB outData;

    if (CryptUnprotectData(&inData, nullptr, nullptr, nullptr, nullptr, 0, &outData)) {
        std::vector<BYTE> result(outData.pbData, outData.pbData + outData.cbData);
        LocalFree(outData.pbData);
        return result;
    } else {
        return {};
    }
}

std::string GetKey::DecryptWithKey(const std::vector<BYTE>& encryptedData, const std::vector<BYTE>& masterKey) {
    std::vector<BYTE> iv(12, 0);
    std::copy(encryptedData.begin() + 3, encryptedData.begin() + 15, iv.begin());

    std::vector<BYTE> buffer(encryptedData.begin() + 15, encryptedData.end());
    std::vector<BYTE> tag(buffer.end() - 16, buffer.end());
    buffer.resize(buffer.size() - 16);

    std::vector<BYTE> data(buffer.begin(), buffer.end());

    return AesGcm::Decrypt(masterKey, iv, {}, data, tag);
}

std::string AesGcm::Decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& iv, const std::vector<BYTE>& aad, const std::vector<BYTE>& cipherText, const std::vector<BYTE>& authTag) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::runtime_error("Invalid key size");
    }
    if (iv.size() != 12) {
        throw std::runtime_error("Invalid IV size");
    }
    if (authTag.size() != 16) {
        throw std::runtime_error("Invalid authentication tag size");
    }
    if (cipherText.empty()) {
        throw std::runtime_error("Cipher text is empty");
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status != 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed with error code: " + std::to_string(status));

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) throw std::runtime_error("BCryptSetProperty failed with error code: " + std::to_string(status));

    DWORD keyObjectSize = 0, dataSize = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectSize, sizeof(DWORD), &dataSize, 0);
    if (status != 0) throw std::runtime_error("BCryptGetProperty failed with error code: " + std::to_string(status));

    std::vector<BYTE> keyObject(keyObjectSize);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), keyObjectSize, (PUCHAR)key.data(), key.size(), 0);
    if (status != 0) throw std::runtime_error("BCryptGenerateSymmetricKey failed with error code: " + std::to_string(status));

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv.data();
    authInfo.cbNonce = iv.size();
    authInfo.pbTag = (PUCHAR)authTag.data();
    authInfo.cbTag = authTag.size();
    authInfo.pbAuthData = (PUCHAR)aad.data();
    authInfo.cbAuthData = aad.size();

    DWORD plainTextSize = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)cipherText.data(), cipherText.size(), &authInfo, nullptr, 0, nullptr, 0, &plainTextSize, 0x0);
    if (status != 0) throw std::runtime_error("BCryptDecrypt failed with error code: " + std::to_string(status));

    std::vector<BYTE> plainText(plainTextSize);
    status = BCryptDecrypt(hKey, (PUCHAR)cipherText.data(), cipherText.size(), &authInfo, nullptr, 0, plainText.data(), plainTextSize, &plainTextSize, 0x0);
    if (status != 0) throw std::runtime_error("BCryptDecrypt failed with error code: " + std::to_string(status));

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return std::string(plainText.begin(), plainText.end());
}

std::string cookies::PathCookie(const std::string &cookie_path) {
    try {
        std::string tempFilePath = cookie_path + ".tmp";

        if (!std::filesystem::exists(cookie_path)) {
            throw std::runtime_error("Original file does not exist: " + cookie_path);
        }

        if (std::filesystem::exists(tempFilePath)) {
            std::filesystem::remove(tempFilePath);
        }

        const int maxRetries = 5;
        const int retryDelayMs = 1000;
        for (int attempt = 0; attempt < maxRetries; ++attempt) {
            if (CopyFileEx(cookie_path.c_str(), tempFilePath.c_str(), nullptr, nullptr, nullptr, COPY_FILE_COPY_SYMLINK)) {
                return tempFilePath;
            } else {
                DWORD error = GetLastError();
                std::cerr << "Attempt " << (attempt + 1) << " failed with error code: " << error << std::endl;
                if (error == ERROR_SHARING_VIOLATION) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(retryDelayMs));
                } else {
                    throw std::runtime_error("Failed to perform shadow copy: " + std::to_string(error));
                }
            }
        }

        throw std::runtime_error("Failed to perform shadow copy after multiple attempts");
    } catch (const std::filesystem::filesystem_error &e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return "";
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return "";
    }
}

void cookies::GetCookies(const std::string &chrome_cookie_path, const std::string &chrome_state_file) {
    try {
        std::string cookie_data_tempFile = PathCookie(chrome_cookie_path);
        std::vector<std::string> Jsonheader = { "domain", "expirationDate", "hostOnly", "httpOnly", "name", "path", "sameSite", "secure", "session", "storeId", "value" };
        std::vector<std::vector<std::string>> Jsondata;

        std::vector<std::string> header = { "HOST", "COOKIE", "Path", "IsSecure", "Is_httponly", "HasExpire", "IsPersistent", "CreateDate", "ExpireDate", "AccessDate" };
        std::vector<std::vector<std::string>> data;

        std::filesystem::create_directory("out");
        std::string fileName = "out/" + browser_name + "_cookie";
        sqlite3 *db;
        sqlite3_open(cookie_data_tempFile.c_str(), &db);
        const char *sql = "SELECT cast(creation_utc as text) as creation_utc, host_key, name, path, cast(expires_utc as text) as expires_utc, cast(last_access_utc as text) as last_access_utc, encrypted_value, is_secure, is_httponly,has_expires,is_persistent,samesite FROM cookies;";
        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            std::vector<BYTE> masterKey = GetKey::GetMasterKey(chrome_state_file);

            unsigned int num = 0;
            printf("    ---------------------------------------------------------\n");
            std::cout << "    Exporting cookies..." << std::endl;

            while (sqlite3_step(stmt) == SQLITE_ROW) {
                std::string host_key = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
                std::string name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
                std::string http_only = is_true_false(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 8)));
                std::string IsPersistent = is_true_false(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 10)));
                std::string IsSecure = is_true_false(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 7)));
                std::string HasExpire = is_true_false(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 9)));
                const BYTE *cookieBytes = reinterpret_cast<const BYTE *>(sqlite3_column_blob(stmt, 6));
                std::string cookie_value;

                std::string expDate = TypeUtil::TimeEpoch(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4)));
                std::string lastDate = TypeUtil::TimeEpoch(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5)));
                std::string creDate = TypeUtil::TimeEpoch(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));

                std::string sameSiteString = TryParsesameSite(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 11)));

                std::string path = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));


                cookie_value = GetKey::DecryptWithKey(std::vector<BYTE>(cookieBytes, cookieBytes + sqlite3_column_bytes(stmt, 6)), masterKey);

                std::string cookie = name.append("=" + cookie_value);

                Jsondata.push_back({ host_key, expDate, "false", http_only, name, path, sameSiteString, IsSecure, "true", "0", cookie_value });
                data.push_back({ host_key, cookie, path, IsSecure, http_only, HasExpire, IsPersistent, creDate, expDate, lastDate });

                std::cout << "    Exported " << ++num << " cookies" << std::endl;
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);

        //将data写入文件
        std::ofstream out(fileName + ".csv");
        for (auto &i : header) {
            out << i << ",";
        }
        out << std::endl;
        for (auto &i : data) {
            for (auto &j : i) {
                out << j << ",";
            }
            out << std::endl;
        }
        out.close();

        //将Jsondata写入文件
        nlohmann::json json;
        for (auto &i : Jsonheader) {
            json[i] = Jsondata;
        }
        std::ofstream outJson(fileName + ".json");
        outJson << json.dump(4);
        outJson.close();




        std::remove(cookie_data_tempFile.c_str());
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        printf("Cookies File Not Found OR Not Administrator Privileges!");
    }
    std::cout << std::endl;
}