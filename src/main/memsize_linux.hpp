// SPDX-License-Identifier: CC-BY-SA-2.5
#pragma once
// from https://stackoverflow.com/a/671389/2289509
// see https://stackoverflow.com/help/licensing

#include <fstream>
#include <ios>
#include <iostream>
#include <string>
#include <unistd.h>

namespace prevail {

const std::string VMHWM = "VmHWM:";
const std::string VMRSS = "VmRSS:";

inline long resident_set_size_kb() {
    long rss = 0;
    {
        std::string _{};
        unsigned long __{};
        std::ifstream stat_stream("/proc/self/stat", std::ios_base::in);
        stat_stream >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >>
            _ >> _ >> _ >> __ >> rss; // don't care about the rest
    }

    const long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024; // in case x86-64 is configured to use 2MB pages
    return rss * page_size_kb;
}

inline long hwm_kb() {
    long peak_rss = 0;
    std::string field;

    {
        std::ifstream status_stream("/proc/self/status", std::ios_base::in);
        while(status_stream >> field) {
            //depending on the kernel, VmHWM isnt at the same index
            if(field == VMHWM)
                break;
        }
        status_stream >> peak_rss;
    }

    return peak_rss;
}

} // namespace prevail
