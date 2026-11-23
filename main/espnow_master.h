#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ESPNOW_MAX_PEERS   20
#define ESPNOW_PAYLOAD_LEN 250

typedef struct {
    uint8_t  mac[6];
    int8_t   rssi;
    uint32_t last_seen_ms;      // esp_timer 毫秒时间戳
    uint16_t data_len;
    uint8_t  data[ESPNOW_PAYLOAD_LEN];
    bool     online;
    uint32_t run_count;         // 今日已接收报文次数
    int      day;               // 计数所属的 tm_yday，-1 表示未初始化
} enow_peer_t;

/* WiFi 启动后初始化 ESP-NOW 主机（接收模式） */
void espnow_master_init(void);

/* 手动注册一个对端 MAC（用于主动回发），返回 ESP_OK / 参数错误 */
esp_err_t espnow_master_add_peer(const uint8_t *mac);

/* 移除一个对端 MAC，并在本机表中标记为离线 */
esp_err_t espnow_master_remove_peer(const uint8_t *mac);

/* 仅清空该对端已上报的数据缓存，保留在线状态与 MAC 绑定 */
esp_err_t espnow_master_clear_data(const uint8_t *mac);

/* 向指定对端发送一帧 ESP-NOW 数据 */
esp_err_t espnow_master_send(const uint8_t *mac, const uint8_t *data, int len);

/* 取从机列表快照，返回数量；out 容量至少 ESPNOW_MAX_PEERS */
void espnow_master_get_peers(enow_peer_t *out, int *count);

#ifdef __cplusplus
}
#endif
