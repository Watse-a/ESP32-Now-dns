#include <string.h>
#include <stdio.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_now.h"
#include "esp_mac.h"
#include "esp_timer.h"

#include "espnow_master.h"
#include "count_store.h"

static const char *TAG = "espnow_host";

static enow_peer_t s_peers[ESPNOW_MAX_PEERS];
static int s_count = 0;
static SemaphoreHandle_t s_lock = NULL;

static void lock(void)   { xSemaphoreTake(s_lock, portMAX_DELAY); }
static void unlock(void) { xSemaphoreGive(s_lock); }

/* 当前本地日期的年内天数（用于跨天清零运行次数）；未同步 NTP 时返回固定基准 */
static int today_yday(void)
{
    time_t now;
    struct tm tm;
    time(&now);
    localtime_r(&now, &tm);
    return tm.tm_yday;
}

static void peer_upsert(const uint8_t *mac, int8_t rssi,
                        const uint8_t *data, int len)
{
    lock();
    int today = today_yday();
    for (int i = 0; i < s_count; i++) {
        if (memcmp(s_peers[i].mac, mac, 6) == 0) {
            s_peers[i].rssi = rssi;
            s_peers[i].last_seen_ms = (uint32_t)(esp_timer_get_time() / 1000);
            s_peers[i].data_len = (uint16_t)(len < ESPNOW_PAYLOAD_LEN ? len : ESPNOW_PAYLOAD_LEN);
            memcpy(s_peers[i].data, data, s_peers[i].data_len);
            s_peers[i].online = true;
            if (s_peers[i].day != today) {
                s_peers[i].day = today;
                s_peers[i].run_count = 0;
            }
            s_peers[i].run_count++;
            unlock();
            return;
        }
    }
    if (s_count < ESPNOW_MAX_PEERS) {
        enow_peer_t *p = &s_peers[s_count++];
        memcpy(p->mac, mac, 6);
        p->rssi = rssi;
        p->last_seen_ms = (uint32_t)(esp_timer_get_time() / 1000);
        p->data_len = (uint16_t)(len < ESPNOW_PAYLOAD_LEN ? len : ESPNOW_PAYLOAD_LEN);
        memcpy(p->data, data, p->data_len);
        p->online = true;
        p->day = today;
        p->run_count = 1;

        /* 登记为非加密对端，便于后续向其回发（不影响接收） */
        esp_now_peer_info_t peer = {0};
        memcpy(peer.peer_addr, mac, 6);
        peer.channel = 0;
        peer.encrypt = false;
        esp_now_add_peer(&peer);
    }
    unlock();
}

static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    if (!info || !info->src_addr) return;
    int8_t rssi = info->rx_ctrl ? info->rx_ctrl->rssi : 0;
    peer_upsert(info->src_addr, rssi, data, len);
    count_store_record(info->src_addr, data, len);
    ESP_LOGI(TAG, "收到从机 " MACSTR " RSSI=%d len=%d",
             MAC2STR(info->src_addr), rssi, len);
}

void espnow_master_init(void)
{
    s_lock = xSemaphoreCreateMutex();

    esp_err_t e = esp_now_init();
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "ESP-NOW 初始化失败: %s", esp_err_to_name(e));
        return;
    }
    esp_now_register_recv_cb(on_recv);
    ESP_LOGI(TAG, "ESP-NOW 主机已启动，监听底下设备");
}

void espnow_master_get_peers(enow_peer_t *out, int *count)
{
    if (!out || !count) return;
    lock();
    memcpy(out, s_peers, sizeof(enow_peer_t) * s_count);
    *count = s_count;
    unlock();
}

esp_err_t espnow_master_add_peer(const uint8_t *mac)
{
    if (!mac) return ESP_ERR_INVALID_ARG;
    lock();
    for (int i = 0; i < s_count; i++) {
        if (memcmp(s_peers[i].mac, mac, 6) == 0) {
            unlock();
            return ESP_OK;
        }
    }
    if (s_count < ESPNOW_MAX_PEERS) {
        enow_peer_t *p = &s_peers[s_count++];
        memset(p, 0, sizeof(*p));
        memcpy(p->mac, mac, 6);
        p->online = false;
    }
    esp_now_peer_info_t peer = {0};
    memcpy(peer.peer_addr, mac, 6);
    peer.channel = 0;
    peer.encrypt = false;
    esp_err_t e = esp_now_add_peer(&peer);
    unlock();
    ESP_LOGI(TAG, "手动注册对端 " MACSTR " -> %s", MAC2STR(mac), esp_err_to_name(e));
    return e;
}

esp_err_t espnow_master_remove_peer(const uint8_t *mac)
{
    if (!mac) return ESP_ERR_INVALID_ARG;
    lock();
    esp_now_del_peer(mac);
    for (int i = 0; i < s_count; i++) {
        if (memcmp(s_peers[i].mac, mac, 6) == 0) {
            s_peers[i].online = false;
        }
    }
    unlock();
    ESP_LOGI(TAG, "移除对端 " MACSTR, MAC2STR(mac));
    return ESP_OK;
}

esp_err_t espnow_master_clear_data(const uint8_t *mac)
{
    if (!mac) return ESP_ERR_INVALID_ARG;
    lock();
    for (int i = 0; i < s_count; i++) {
        if (memcmp(s_peers[i].mac, mac, 6) == 0) {
            s_peers[i].data_len = 0;
            s_peers[i].rssi = 0;
            s_peers[i].online = false;
            s_peers[i].run_count = 0;
            s_peers[i].day = -1;
            memset(s_peers[i].data, 0, ESPNOW_PAYLOAD_LEN);
        }
    }
    unlock();
    ESP_LOGI(TAG, "清空对端上报数据 " MACSTR, MAC2STR(mac));
    return ESP_OK;
}

/* 向指定对端发送一帧 ESP-NOW 数据；确保已登记为对端后再发送 */
esp_err_t espnow_master_send(const uint8_t *mac, const uint8_t *data, int len)
{
    if (!mac || !data || len <= 0) return ESP_ERR_INVALID_ARG;

    if (!esp_now_is_peer_exist(mac)) {
        esp_now_peer_info_t peer = {0};
        memcpy(peer.peer_addr, mac, 6);
        peer.channel = 0;
        peer.encrypt = false;
        esp_now_add_peer(&peer);
    }
    esp_err_t e = esp_now_send(mac, data, len);
    ESP_LOGI(TAG, "向 " MACSTR " 发送 %d 字节: %s",
             MAC2STR(mac), len, esp_err_to_name(e));
    return e;
}
