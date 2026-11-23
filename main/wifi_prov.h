#pragma once

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROV_AP_SSID   "S3-ESPNOW"

/* 功率内部按 0.25 dBm/格（ESP-IDF 单位）存储与应用 */
#define POWER_MIN_Q    32    /* 8.0 dBm  */
#define POWER_MAX_Q    80    /* 20.0 dBm */
#define POWER_DEFAULT_Q 34   /* 8.5 dBm */

typedef struct {
    bool     sta_connected;
    char     sta_ssid[33];
    char     sta_ip[16];
    char     sta_gw[16];
    char     sta_mask[16];
    int8_t   sta_rssi;
    uint8_t  sta_channel;
    float    power_dbm;   /* 实际 dBm，0.5 步进 */
    bool     provisioning;   // true: 仍在配网热点阶段；false: 已切纯 STA
} wifi_status_t;

/* 初始化 NVS/事件/WiFi，按持久化凭据决定起 STA 还是临时配网 AP */
void wifi_prov_start(void);

void wifi_prov_get_status(wifi_status_t *out);

/* 网页状态请求驱动：每次刷新且 STA 已联网时主动重测一次 RSSI，无请求不采样 */
void wifi_prov_update_rssi(void);

/* 保存上游凭据并发起连接（配网提交时调用） */
esp_err_t wifi_prov_save_upstream(const char *ssid, const char *pass);

/* 设置发射功率 dBm（8.0~20.0，0.5 步进），存 NVS 并应用 */
esp_err_t wifi_prov_set_power(float dbm);

float wifi_prov_get_power(void);

#ifdef __cplusplus
}
#endif
