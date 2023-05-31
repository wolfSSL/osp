#include <stddef.h>

#include <time.h>
#include "rng.h"
#include "rtc.h"
#include "shared/timeutils/timeutils.h"


extern void *m_tracked_calloc(size_t nmemb, size_t size);
extern void m_tracked_free(void *ptr);


void *myMalloc(size_t n, void* heap, int type)
{
    return m_tracked_calloc(n, 1);
}


void myFree(void *p, void* heap, int type)
{
    return m_tracked_free(p);
}


//void *myRealloc(void *p, size_t n, void* heap, int type)
//{
//}


//int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
int my_rng_seed_gen(void) {
    return rng_get();
}

time_t XTIME(time_t *timer) {
    rtc_init_finalise();
    RTC_DateTypeDef date;
    RTC_TimeTypeDef time;
    HAL_RTC_GetTime(&RTCHandle, &time, RTC_FORMAT_BIN);
    HAL_RTC_GetDate(&RTCHandle, &date, RTC_FORMAT_BIN);
    return timeutils_seconds_since_epoch(2000 + date.Year, date.Month, date.Date, time.Hours, time.Minutes, time.Seconds);
}

struct tm *XGMTIME(const time_t *timep, struct tm* tmp) {
    static struct tm tm;
    timeutils_struct_time_t tm_buf = {0};
    timeutils_seconds_since_epoch_to_struct_time(*timep, &tm_buf);

    tm.tm_sec = tm_buf.tm_sec;
    tm.tm_min = tm_buf.tm_min;
    tm.tm_hour = tm_buf.tm_hour;
    tm.tm_mday = tm_buf.tm_mday;
    tm.tm_mon = tm_buf.tm_mon - 1;
    tm.tm_year = tm_buf.tm_year - 1900;
    tm.tm_wday = tm_buf.tm_wday;
    tm.tm_yday = tm_buf.tm_yday;
    tm.tm_isdst = -1;

    return &tm;
}
