#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CS_BTN      2
#define CS_DAYS     7
#define CS_WEEKS    2
#define CS_MONTHS   6
#define CS_WEEKS_PER_MONTH 4

/* 通用汇总桶；key 为日期键（天/周=YYYYMMDD，月=起始周一 YYYYMMDD），0 表示空槽 */
typedef struct {
    int32_t  key;
    uint32_t count;
} cs_bucket_t;

/* 初始化：从 NVS 载入周/月汇总，今日计数缓冲放 PSRAM */
void count_store_init(void);

/* 注册按钮与从机 MAC 的绑定关系（保存按钮时调用） */
void count_store_bind_mac(int btn, const uint8_t *mac);

/* 收到一帧 ESP-NOW 报文：先匹配来源 MAC 命中已绑定按钮，再检查报文内容为 V50（忽略大小写），命中则该按钮今日计数 +1 */
void count_store_record(const uint8_t *mac, const uint8_t *data, int len);

/* 取某按钮今日计数（PSRAM） */
uint32_t count_store_today(int btn);

/* 周期调用：检测跨天/跨周，归档并按层汇总（低层明细汇总后清除） */
void count_store_archive_tick(void);

/* 复制本周内天明细（最多 CS_DAYS 条，index 0 = 周一方向） */
void count_store_days(int btn, cs_bucket_t *out);

/* 取周汇总：this_week 本周累计，last_week 上周累计，diff = 本周 - 上周 */
void count_store_week(int btn, uint32_t *this_week, uint32_t *last_week, int32_t *diff);

/* 复制近 CS_MONTHS 个月汇总（index 0 = 最近一月） */
void count_store_months(int btn, cs_bucket_t *out);

/* 当前进行中月桶已归档周累计（不含本周），本月至今 = 该值 + 本周累计 */
uint32_t count_store_month_acc(int btn);

/* 清空某按钮今日与各层历史计数（保留 MAC 绑定） */
void count_store_clear(int btn);

#ifdef __cplusplus
}
#endif
