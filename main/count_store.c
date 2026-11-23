#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"

#include "count_store.h"

static const char *TAG = "count_store";

#define CS_NVS_NS   "hist"
#define CS_NVS_KEY  "hist_v2"

/* 运行时计数存储，整体放 PSRAM；周/月汇总与本周天明细定期落 NVS */
typedef struct {
    uint32_t today[CS_BTN];
    int32_t  today_key;                          /* 今日 YYYYMMDD，0=未同步 */
    int32_t  cur_monday;                         /* 当前周周一 YYYYMMDD */
    cs_bucket_t days[CS_BTN][CS_DAYS];           /* 本周内天明细（入周后清除） */
    cs_bucket_t weeks[CS_BTN][CS_WEEKS];         /* 已完成周，0=最近一周 */
    cs_bucket_t months[CS_BTN][CS_MONTHS];       /* 近 6 个月汇总，0=最近一月 */
    uint32_t month_acc[CS_BTN];                  /* 当前月桶已累计周计数 */
    uint8_t  month_weeks[CS_BTN];                /* 当前月桶已累计周数 */
} cs_store_t;

static cs_store_t       *s_store = NULL;
static SemaphoreHandle_t s_lock = NULL;

static uint8_t s_mac[CS_BTN][6];
static bool    s_mac_set[CS_BTN];

/* ---------------- 时间 ---------------- */

static int32_t key_of(const struct tm *tm)
{
    return (tm->tm_year + 1900) * 10000 + (tm->tm_mon + 1) * 100 + tm->tm_mday;
}

static bool local_tm(struct tm *tm)
{
    time_t now;
    time(&now);
    if (now < 1700000000) return false;
    localtime_r(&now, tm);
    return true;
}

static int32_t current_day_key(void)
{
    struct tm tm;
    if (!local_tm(&tm)) return 0;
    return key_of(&tm);
}

static int32_t current_monday_key(void)
{
    struct tm tm;
    if (!local_tm(&tm)) return 0;
    struct tm m = tm;
    int delta = (m.tm_wday + 6) % 7;             /* 周日=0，回到周一 */
    m.tm_mday -= delta;
    m.tm_hour = 12;
    mktime(&m);
    return key_of(&m);
}

/* ---------------- 报文关键字判定（V50，忽略大小写） ---------------- */

static bool payload_is_v50(const uint8_t *data, int len)
{
    if (!data || len <= 0) return false;
    char s[256];
    int j = 0;
    for (int i = 0; i < len && j < (int)sizeof(s) - 1; i++) {
        char c = (char)data[i];
        if (c >= 32 && c < 127) s[j++] = c;
    }
    s[j] = '\0';
    char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    char *e = p + strlen(p);
    while (e > p && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) e[-1] = '\0';
    return strcasecmp(p, "V50") == 0;
}

/* ---------------- NVS ---------------- */

static void hist_load(void)
{
    nvs_handle_t h;
    if (nvs_open(CS_NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    size_t n = sizeof(*s_store);
    /* today 不持久化；载入时按偏移跳过 today 段，这里整体读入后清零今日段 */
    if (nvs_get_blob(h, CS_NVS_KEY, s_store, &n) != ESP_OK) {
        memset(s_store, 0, sizeof(*s_store));
    }
    nvs_close(h);
    /* 今日计数与当日/当周标记属运行时态，不回载入 */
    memset(s_store->today, 0, sizeof(s_store->today));
    s_store->today_key = 0;
    s_store->cur_monday = 0;
}

static void hist_save(void)
{
    nvs_handle_t h;
    if (nvs_open(CS_NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_blob(h, CS_NVS_KEY, s_store, sizeof(*s_store));
    nvs_commit(h);
    nvs_close(h);
}

/* ---------------- 桶滚动 ---------------- */

static void push_day(int btn, int32_t key, uint32_t count)
{
    if (key == 0) return;
    cs_bucket_t *d = s_store->days[btn];
    for (int i = 0; i < CS_DAYS; i++) {
        if (d[i].key == key) { d[i].count += count; return; }
    }
    for (int i = 0; i < CS_DAYS; i++) {
        if (d[i].key == 0) { d[i].key = key; d[i].count = count; return; }
    }
}

static uint32_t sum_days(int btn)
{
    uint32_t s = 0;
    for (int i = 0; i < CS_DAYS; i++) s += s_store->days[btn][i].count;
    return s;
}

static void clear_days(int btn)
{
    memset(s_store->days[btn], 0, sizeof(s_store->days[btn]));
}

static void push_week(int btn, int32_t key, uint32_t count)
{
    cs_bucket_t *w = s_store->weeks[btn];
    w[1] = w[0];                                 /* 丢弃更早一周，仅保留 2 周 */
    w[0].key = key;
    w[0].count = count;
}

static void push_month(int btn, int32_t key, uint32_t count)
{
    cs_bucket_t *m = s_store->months[btn];
    for (int i = CS_MONTHS - 1; i > 0; i--) m[i] = m[i - 1];
    m[0].key = key;
    m[0].count = count;
}

/* ---------------- 归档 ---------------- */

static void archive_locked(void)
{
    int32_t dk  = current_day_key();
    int32_t mon = current_monday_key();
    if (dk == 0 || mon == 0) return;

    if (s_store->today_key == 0) {
        s_store->today_key = dk;
        s_store->cur_monday = mon;
        return;
    }

    /* 跨天：昨日今日计数并入天明细 */
    if (dk != s_store->today_key) {
        for (int b = 0; b < CS_BTN; b++) {
            push_day(b, s_store->today_key, s_store->today[b]);
            s_store->today[b] = 0;
        }
        s_store->today_key = dk;
    }

    /* 跨周：本周天明细汇总为一条已完成周，清天明细；累计满 4 周入月 */
    if (mon != s_store->cur_monday) {
        for (int b = 0; b < CS_BTN; b++) {
            uint32_t finished = sum_days(b);
            push_week(b, s_store->cur_monday, finished);
            clear_days(b);

            s_store->month_acc[b] += finished;
            s_store->month_weeks[b]++;
            if (s_store->month_weeks[b] >= CS_WEEKS_PER_MONTH) {
                push_month(b, s_store->cur_monday, s_store->month_acc[b]);
                s_store->month_acc[b] = 0;
                s_store->month_weeks[b] = 0;
            }
        }
        s_store->cur_monday = mon;
        hist_save();
        ESP_LOGI(TAG, "跨周归档完成，新周一 %d", mon);
    }
}

/* ---------------- 对外接口 ---------------- */

void count_store_init(void)
{
    s_lock = xSemaphoreCreateMutex();

    s_store = heap_caps_malloc(sizeof(cs_store_t),
                               MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_store) {
        ESP_LOGW(TAG, "PSRAM 分配失败，回退内部 RAM");
        s_store = calloc(1, sizeof(cs_store_t));
    } else {
        memset(s_store, 0, sizeof(*s_store));
    }
    memset(s_mac_set, 0, sizeof(s_mac_set));

    hist_load();

    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_store->today_key = current_day_key();
    s_store->cur_monday = current_monday_key();
    xSemaphoreGive(s_lock);
}

void count_store_bind_mac(int btn, const uint8_t *mac)
{
    if (btn < 0 || btn >= CS_BTN) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (mac && mac[0] != 0) {
        memcpy(s_mac[btn], mac, 6);
        s_mac_set[btn] = true;
    } else {
        s_mac_set[btn] = false;
        memset(s_mac[btn], 0, 6);
    }
    xSemaphoreGive(s_lock);
}

void count_store_record(const uint8_t *mac, const uint8_t *data, int len)
{
    if (!s_store || !mac) return;
    int btn = -1;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    /* 先匹配来源 MAC 是否为已保存（绑定）的按钮对端 */
    for (int b = 0; b < CS_BTN; b++) {
        if (s_mac_set[b] && memcmp(s_mac[b], mac, 6) == 0) { btn = b; break; }
    }
    if (btn < 0) { xSemaphoreGive(s_lock); return; }   /* 未绑定 MAC：不再检查报文 */
    /* 命中绑定按钮后，再检查报文内容 */
    bool match = payload_is_v50(data, len);
    if (match) s_store->today[btn]++;
    xSemaphoreGive(s_lock);
    ESP_LOGI(TAG, "绑定按钮%d 报文%s V50", btn, match ? "为" : "非");
}

uint32_t count_store_today(int btn)
{
    if (btn < 0 || btn >= CS_BTN || !s_store) return 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t v = s_store->today[btn];
    xSemaphoreGive(s_lock);
    return v;
}

void count_store_archive_tick(void)
{
    if (!s_store) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    archive_locked();
    xSemaphoreGive(s_lock);
}

void count_store_days(int btn, cs_bucket_t *out)
{
    if (btn < 0 || btn >= CS_BTN || !out || !s_store) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(out, s_store->days[btn], sizeof(cs_bucket_t) * CS_DAYS);
    xSemaphoreGive(s_lock);
}

void count_store_week(int btn, uint32_t *this_week, uint32_t *last_week, int32_t *diff)
{
    if (btn < 0 || btn >= CS_BTN || !s_store) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t tw = sum_days(btn) + s_store->today[btn];
    uint32_t lw = s_store->weeks[btn][0].count;
    if (this_week) *this_week = tw;
    if (last_week) *last_week = lw;
    if (diff) *diff = (int32_t)tw - (int32_t)lw;
    xSemaphoreGive(s_lock);
}

uint32_t count_store_month_acc(int btn)
{
    if (btn < 0 || btn >= CS_BTN || !s_store) return 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t v = s_store->month_acc[btn];
    xSemaphoreGive(s_lock);
    return v;
}

void count_store_months(int btn, cs_bucket_t *out)
{
    if (btn < 0 || btn >= CS_BTN || !out || !s_store) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(out, s_store->months[btn], sizeof(cs_bucket_t) * CS_MONTHS);
    xSemaphoreGive(s_lock);
}

void count_store_clear(int btn)
{
    if (btn < 0 || btn >= CS_BTN || !s_store) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_store->today[btn] = 0;
    memset(s_store->days[btn], 0, sizeof(s_store->days[btn]));
    memset(s_store->weeks[btn], 0, sizeof(s_store->weeks[btn]));
    memset(s_store->months[btn], 0, sizeof(s_store->months[btn]));
    s_store->month_acc[btn] = 0;
    s_store->month_weeks[btn] = 0;
    xSemaphoreGive(s_lock);
    hist_save();
}
