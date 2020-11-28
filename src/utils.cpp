/* utils.cpp
 *
 * define common functionalities
 *  
 * NetFI - a fast and simple tool to analyze the network flow (Internet Protocol family) 
 */

#include <stdio.h>

#include "utils.h"

namespace pump
{

    void update_ts(time_stat* ts, timeval* tv)
    {
        ts->s.tv_sec += tv->tv_sec;
        ts->s.tv_usec += tv->tv_usec;
        if (ts->s.tv_usec < 0)
        {
            ts->s.tv_sec--;
            ts->s.tv_usec += 1000000;
        }
        else if (ts->s.tv_usec >= 1000000)
        {
            ts->s.tv_sec++;
            ts->s.tv_usec -= 1000000;
        }

        if (time_cmp(tv, &ts->M)) time_update(&ts->M, tv);
        if (time_cmp(&ts->m, tv)) time_update(&ts->m, tv);
    }

    uint32_t fnv_hash(ScalarBuffer vec[], size_t vecSize)
    {
        uint32_t hash = OFFSET_BASIS;
        for (size_t i = 0; i < vecSize; i++)
        {
            for (size_t j = 0; j < vec[i].len; j++)
            {
                hash *= FNV_PRIME;
                hash ^= vec[i].buffer[j];
            }
        }
        return hash;
    }

    void parseIPV4(char* s, uint32_t ip_addr)
    {
        sprintf(s, "%d.%d.%d.%d", ip_addr & 0xFF, (ip_addr >> 8) & 0xFF, (ip_addr >> 16) & 0xFF, (ip_addr >> 24) & 0xFF);
    }

    bool time_cmp(timeval* tv1, timeval* tv2)
    {
        if (tv1->tv_sec == tv2->tv_sec) return tv1->tv_usec > tv2->tv_usec;
        return tv1->tv_sec > tv2->tv_sec;
    }

    int64_t time_diff(timeval* tv1, timeval* tv2)
    {
        return time_raw(tv1) - time_raw(tv2);
    }

    int64_t time_tot(timeval* btv1, timeval* btv2, timeval* ltv1, timeval* ltv2)
    {
        if(time_cmp(btv1, btv2))
        {
            return time_cmp(ltv1, ltv2) ? time_diff(ltv1, btv2) : time_diff(ltv2, btv2);
        }
        else
        {
            return time_cmp(ltv1, ltv2) ? time_diff(ltv1, btv1) : time_diff(ltv2, btv1);
        }
    }

    bool time_isZero(timeval* tv)
    {
        return (tv->tv_sec == 0 && tv->tv_usec == 0);
    }

    int64_t time_raw(timeval* tv)
    {
        return 1000000 * (int64_t)tv->tv_sec + (int64_t)tv->tv_usec;
    }

    double time_raws(timeval* tv)
    {
        return (double)time_raw(tv)/1000000;
    }

    void time_delta(timeval* delta, timeval* tv1, timeval* tv2)
    {
        if (tv1->tv_sec == tv2->tv_sec)
        {
            delta->tv_sec = (tv1->tv_usec < tv2->tv_usec ? -1 : 0);
            delta->tv_usec = (tv1->tv_usec - tv2->tv_usec + 1000000)%1000000;
        }
        else if (tv1->tv_sec < tv2->tv_sec)
        {
            delta->tv_sec = tv1->tv_sec - tv2->tv_sec;
            delta->tv_usec = tv1->tv_usec - tv2->tv_usec;

            if (delta->tv_usec > 0) 
            {
                delta->tv_usec -= 1000000;
                delta->tv_sec++;
            }
        }
        else
        {
            delta->tv_sec = tv1->tv_sec - tv2->tv_sec;
            delta->tv_usec = tv1->tv_usec - tv2->tv_usec;

            if (delta->tv_usec < 0) 
            {
                delta->tv_usec += 1000000;
                delta->tv_sec--;
            }
        }
    }

    void time_update(timeval* tv1, timeval* tv2)
    {
        tv1->tv_usec = tv2->tv_usec;
        tv1->tv_sec = tv2->tv_sec;
    }

    void print_progressM(uint32_t c)
    {
        printf("\r**Capture Packets**========================================= (%u)", c);
        fflush(stdout);
    }

    void print_progressA(uint32_t s, uint32_t ts)
    {
        printf("\r**Calculate Flow Stat**===================================== (%d/%d) ", s, ts);
        fflush(stdout);
    }

}