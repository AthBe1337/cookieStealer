//
// Created by athbe on 2024/10/25.
//

#include "TypeUtil.h"

std::string TypeUtil::TimeEpoch(const std::string& epochTimeStr) {
    const long long maxTime = 99633311740000000;
    long long epoch = std::stoll(epochTimeStr);
    if (epoch > maxTime) {
        std::tm tm = {};
        tm.tm_year = 2049 - 1900;
        tm.tm_mon = 0;
        tm.tm_mday = 1;
        tm.tm_hour = 1;
        tm.tm_min = 1;
        tm.tm_sec = 1;

        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    long long epochTicks = epoch * 10;

    std::chrono::system_clock::time_point epochStart = std::chrono::system_clock::from_time_t(-11644473600LL);

    std::chrono::system_clock::time_point epochDateTime = epochStart + std::chrono::microseconds(epochTicks / 10);

    std::time_t time = std::chrono::system_clock::to_time_t(epochDateTime);

    std::tm tm{};
    localtime_s(&tm, &time);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}