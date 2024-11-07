//
// Created by athbe on 2024/10/25.
//

#ifndef COOKIES_H
#define COOKIES_H

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <regex>
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <sqlite3/sqlite3.h>
#include <thread>
#include <chrono>


class GetKey {
public:
    static std::vector<BYTE> GetMasterKey(const std::string& filePath);
    static std::string DecryptWithKey(const std::vector<BYTE>& encryptedData, const std::vector<BYTE>& masterKey);
};

class AesGcm {
public:
    static std::string Decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& iv, const std::vector<BYTE>& aad, const std::vector<BYTE>& cipherText, const std::vector<BYTE>& authTag);
};

class cookies {
private:
    std::string browser_name = "chrome";
public:
    void GetCookies(const std::string &chrome_cookie_path, const std::string &chrome_state_file);
    static std::string PathCookie(const std::string &cookie_path);
    static std::string is_true_false(const std::string& value) {
        return (value == "1" || value == "true") ? "true" : "false";
    }
    static std::string TryParsesameSite(const std::string& value) {
        if (value == "0") {
            return "None";
        } else if (value == "1") {
            return "Lax";
        } else if (value == "2") {
            return "Strict";
        } else {
            return "Unknown";
        }
    }
};




#endif // COOKIES_H