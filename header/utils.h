/* utils.h
 *
 * define common functionalities
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#ifndef PUMP_UTILS
#define PUMP_UTILS

#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>

static const uint32_t FNV_PRIME = 16777619u;
static const uint32_t OFFSET_BASIS = 2166136261u;

static const uint32_t IN_LIMIT = 1073741824u;
static const int maxbuf = 256;
static const long MEMORY_LIMIT = 8*1024*1024;

namespace pump
{

    struct ScalarBuffer
    {
        uint8_t* buffer;
        size_t len;
    };

    template<typename T>
    struct numeric_stat
    {
        T M = 0;
        T m = (T)-1;
        uint64_t s = 0;
    };

    struct time_stat
    {
        timeval M = {0, 0};
        timeval m = {(long)IN_LIMIT, (long)IN_LIMIT};
        timeval s = {0, 0};
    };

    uint32_t fnv_hash(ScalarBuffer vec[], size_t vecSize);

    void parseIPV4(char* s, uint32_t ip_addr);

    void update_ts(time_stat* ts, timeval* tv);

    bool time_cmp(timeval* tv1, timeval* tv2);

    int64_t time_diff(timeval* tv1, timeval* tv2);

    int64_t time_tot(timeval* btv1, timeval* btv2, timeval* ltv1, timeval* ltv2);

    bool time_isZero(timeval* tv);

    int64_t time_raw(timeval* tv);

    double time_raws(timeval* tv);

    void time_delta(timeval* delta, timeval* tv1, timeval* tv2);

    void time_update(timeval* tv1, timeval* tv2);

    void print_progressM(uint32_t c);

    void print_progressA(uint32_t s, uint32_t ts);

    template<typename T> void update_ns(numeric_stat<T>* ns, T val)
    {
        ns->s += val;
        if (ns->M < val) ns->M = val;
        if (ns->m > val) ns->m = val;
    }

}

#endif