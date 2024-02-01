#pragma once

#define LOG_INFO(format, ...)                          \
    DbgPrint("[+] Information (%s:%d) | " format "\n", \
             __func__,                                 \
             __LINE__,                                 \
             __VA_ARGS__)

#define LOG_WARNING(format, ...)                     \
    DbgPrint("[-] Warning (%s:%d) | " format "\n",   \
             __func__,                               \
             __LINE__,                               \
             __VA_ARGS__)

#define LOG_ERROR(format, ...)                       \
    DbgPrint("[!] Error (%s:%d) | " format "\n",     \
                 __func__,                           \
                 __LINE__,                           \
                 __VA_ARGS__);                       \
        //DbgBreakPoint()