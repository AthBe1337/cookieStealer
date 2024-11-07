//
// Created by athbe on 2024/10/25.
//

#ifndef TYPEUTIL_H
#define TYPEUTIL_H

#include <iostream>
#include <ctime>
#include <iomanip>
#include <windows.h>
#include <sstream>
#include <chrono>

class TypeUtil {
public:
    static std::string TimeEpoch(const std::string& filetimeStr);
};

#endif //TYPEUTIL_H
