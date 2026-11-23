#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"

#include "wifi_prov.h"

static const char *TAG = "wifi_prov";

#define NVS_NS      "host"
#define KEY_UP_SSID "up_ssid"
#define KEY_UP_PASS "up_pass"
#define KEY_POWER   "power_dbm"
#define MAX_RETRY   5

static esp_netif_t *s_ap  = NULL;
static esp_netif_t *s_sta = NULL;
static SemaphoreHandle_t s_lock = NULL;
static wifi_status_t s_status;
static int s_power_q = POWER_DEFAULT_Q;

/* 连接任务：同名 SSID 有多个 AP 时，扫一遍全部信道、挑信号最强的那个去连 */
static SemaphoreHandle_t s_conn_req = NULL;
static char    s_up_ssid[33] = {0};
static char    s_up_pass[65] = {0};
static uint8_t s_up_bssid[6] = {0};
static bool    s_up_bssid_valid = false;
static int     s_up_best_rssi = 0;
static TickType_t s_last_req = 0;    /* 连接请求节流：断开重连不要打闪电战 */

/* ---------------- NVS ---------------- */

static bool nvs_read_str(const char *key, char *buf, size_t len)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return false;
    size_t n = len;
    esp_err_t e = nvs_get_str(h, key, buf, &n);
    nvs_close(h);
    return e == ESP_OK;
}

static esp_err_t nvs_write_str(const char *key, const char *val)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    e = nvs_set_str(h, key, val ? val : "");
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

static int16_t nvs_read_q(const char *key, int16_t def)
{
    nvs_handle_t h;
    int16_t v = def;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_i16(h, key, &v);
        nvs_close(h);
    }
    return v;
}

static esp_err_t nvs_write_q(const char *key, int16_t v)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    e = nvs_set_i16(h, key, v);
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

/* ---------------- 状态 ---------------- */

static void status_lock(void)   { xSemaphoreTake(s_lock, portMAX_DELAY); }
static void status_unlock(void) { xSemaphoreGive(s_lock); }

static void apply_power_q(int q)
{
    esp_wifi_set_max_tx_power(q);   /* 0.25 dBm/格 */
    ESP_LOGI(TAG, "发射功率 %.1f dBm（寄存器 %d）", q / 4.0f, q);
}

/* ---------------- 配置 ---------------- */

static void apply_ap_config(void)
{
    wifi_config_t ap = {0};
    strncpy((char *)ap.ap.ssid, PROV_AP_SSID, sizeof(ap.ap.ssid));
    ap.ap.ssid_len = strlen(PROV_AP_SSID);
    ap.ap.channel = 1;
    ap.ap.max_connection = 4;
    ap.ap.authmode = WIFI_AUTH_OPEN;
    ap.ap.pmf_cfg.required = false;
    esp_wifi_set_config(WIFI_IF_AP, &ap);
}

static void apply_sta_config(const char *ssid, const char *pass, bool pin_bssid)
{
    wifi_config_t sta = {0};
    strncpy((char *)sta.sta.ssid, ssid, sizeof(sta.sta.ssid));
    strncpy((char *)sta.sta.password, pass ? pass : "", sizeof(sta.sta.password));
    sta.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;            /* 全信道扫描，别在第一颗同名 AP 上就停 */
    sta.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;        /* 同名多 AP 时按信号强度排序 */
    sta.sta.failure_retry_cnt = MAX_RETRY;
    sta.sta.threshold.authmode = (pass && pass[0]) ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    if (pin_bssid) {                                        /* 直接锁定扫到的最强 BSSID */
        memcpy(sta.sta.bssid, s_up_bssid, 6);
        sta.sta.bssid_set = 1;
    }
    esp_wifi_set_config(WIFI_IF_STA, &sta);
}

/* 扫描同名 SSID 的全部 AP，挑 RSSI 最大的一个；成功返回 true 并填 s_up_bssid/s_up_best_rssi */
static bool pick_strongest_ap(const char *ssid)
{
    static wifi_ap_record_t recs[16];
    wifi_scan_config_t sc = {0};
    sc.ssid = (uint8_t *)ssid;
    sc.show_hidden = false;
    sc.scan_type = WIFI_SCAN_TYPE_ACTIVE;

    s_up_bssid_valid = false;
    if (esp_wifi_scan_start(&sc, true) != ESP_OK) {
        ESP_LOGW(TAG, "扫描同名 AP 失败，改用默认排序连接");
        return false;
    }
    uint16_t n = sizeof(recs) / sizeof(recs[0]);
    esp_err_t e = esp_wifi_scan_get_ap_records(&n, recs);
    esp_wifi_clear_ap_list();
    if (e != ESP_OK || n == 0) {
        ESP_LOGW(TAG, "同名 AP 扫描到 0 个（%s），改用默认排序连接", ssid);
        return false;
    }
    int best = 0;
    for (int i = 1; i < (int)n; i++)
        if (recs[i].rssi > recs[best].rssi) best = i;
    memcpy(s_up_bssid, recs[best].bssid, 6);
    s_up_bssid_valid = true;
    s_up_best_rssi = recs[best].rssi;
    ESP_LOGI(TAG, "同名 AP 共 %d 个，选最强 " MACSTR " RSSI=%d dBm 信道=%d",
             (int)n, MAC2STR(s_up_bssid), recs[best].rssi, recs[best].primary);
    return true;
}

/* 连接任务：收到请求就重扫一次、锁最强 BSSID 再连；断线后也由它重试 */
static void conn_task(void *arg)
{
    while (1) {
        xSemaphoreTake(s_conn_req, portMAX_DELAY);
        if (!s_up_ssid[0]) continue;
        bool found = pick_strongest_ap(s_up_ssid);
        apply_sta_config(s_up_ssid, s_up_pass, found);
        esp_wifi_disconnect();
        esp_wifi_connect();
        ESP_LOGI(TAG, "发起连接 %s%s", s_up_ssid, found ? "（已锁定最强 BSSID）" : "");
    }
}

/* ---------------- 事件 ---------------- */

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *e = data;
        ESP_LOGI(TAG, "配网手机接入 " MACSTR "，AID=%d", MAC2STR(e->mac), e->aid);

    } else if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *e = data;
        ESP_LOGI(TAG, "配网手机离开 " MACSTR "，原因=%d", MAC2STR(e->mac), e->reason);

    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        status_lock();
        bool has = s_status.sta_ssid[0];
        status_unlock();
        if (has) {
            ESP_LOGI(TAG, "STA 启动，交给连接任务挑最强 AP");
            if (s_conn_req) xSemaphoreGive(s_conn_req);
        }

    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *e = data;
        status_lock();
        s_status.sta_connected = false;
        memset(s_status.sta_ip, 0, sizeof(s_status.sta_ip));
        memset(s_status.sta_gw, 0, sizeof(s_status.sta_gw));
        memset(s_status.sta_mask, 0, sizeof(s_status.sta_mask));
        status_unlock();
        ESP_LOGW(TAG, "STA 断开，原因码=%d，重试中", e->reason);

        /* 断开后重扫重连：同名 AP 可能换了更强的一颗，也可能换了位置 */
        TickType_t now = xTaskGetTickCount();
        if (s_conn_req && (now - s_last_req) >= pdMS_TO_TICKS(3000)) {
            s_last_req = now;
            xSemaphoreGive(s_conn_req);
        }

    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = data;
        status_lock();
        s_status.sta_connected = true;
        s_status.provisioning  = false;
        snprintf(s_status.sta_ip,   sizeof(s_status.sta_ip),   IPSTR, IP2STR(&e->ip_info.ip));
        snprintf(s_status.sta_mask, sizeof(s_status.sta_mask), IPSTR, IP2STR(&e->ip_info.netmask));
        snprintf(s_status.sta_gw,   sizeof(s_status.sta_gw),   IPSTR, IP2STR(&e->ip_info.gw));
        status_unlock();

        /* 配网成功：关闭配网 AP，切纯 STA */
        if (s_ap) {
            esp_netif_dhcps_stop(s_ap);
            esp_wifi_set_mode(WIFI_MODE_STA);
            apply_power_q(s_power_q);   /* 切模式后功率可能被复位，重新应用 */
            ESP_LOGI(TAG, "已联网，关闭配网热点，切纯 STA");
        }

        wifi_ap_record_t info;
        if (esp_wifi_sta_get_ap_info(&info) == ESP_OK) {
            status_lock();
            s_status.sta_rssi = info.rssi;
            s_status.sta_channel = info.primary;
            strncpy(s_status.sta_ssid, (char *)info.ssid, sizeof(s_status.sta_ssid) - 1);
            status_unlock();
            ESP_LOGI(TAG, "上游 RSSI=%d dBm，信道=%d", info.rssi, info.primary);
        }
        ESP_LOGI(TAG, "STA 已联网 IP=%s 网关=%s", s_status.sta_ip, s_status.sta_gw);
    }
}

/* ---------------- 对外接口 ---------------- */

void wifi_prov_get_status(wifi_status_t *out)
{
    if (!out) return;
    status_lock();
    memcpy(out, &s_status, sizeof(*out));
    status_unlock();
}

/* 由网页状态请求驱动：每次网页刷新（status 请求）且 STA 已联网时，主动重测一次信号强度。
   没有网页请求就不会调用，不在后台常驻定时采样。 */
void wifi_prov_update_rssi(void)
{
    bool conn;
    status_lock();
    conn = s_status.sta_connected;
    status_unlock();
    if (!conn) return;

    wifi_ap_record_t info;
    if (esp_wifi_sta_get_ap_info(&info) == ESP_OK) {
        status_lock();
        s_status.sta_rssi = info.rssi;
        s_status.sta_channel = info.primary;
        status_unlock();
    }
}

esp_err_t wifi_prov_save_upstream(const char *ssid, const char *pass)
{
    if (!ssid || !ssid[0]) return ESP_ERR_INVALID_ARG;
    esp_err_t e = nvs_write_str(KEY_UP_SSID, ssid);
    if (e != ESP_OK) return e;
    e = nvs_write_str(KEY_UP_PASS, pass ? pass : "");
    if (e != ESP_OK) return e;

    status_lock();
    strncpy(s_status.sta_ssid, ssid, sizeof(s_status.sta_ssid) - 1);
    status_unlock();

    snprintf(s_up_ssid, sizeof(s_up_ssid), "%s", ssid);
    snprintf(s_up_pass, sizeof(s_up_pass), "%s", pass ? pass : "");
    if (s_conn_req) {
        s_last_req = xTaskGetTickCount();
        xSemaphoreGive(s_conn_req);
    } else {                                  /* 任务还没起来时退化为直接连 */
        apply_sta_config(ssid, pass, false);
        esp_wifi_disconnect();
        esp_wifi_connect();
    }
    ESP_LOGI(TAG, "已保存上游凭据，交连接任务挑最强 AP：%s", ssid);
    return ESP_OK;
}

esp_err_t wifi_prov_set_power(float dbm)
{
    int q = (int)lroundf(dbm * 4.0f);
    if (q < POWER_MIN_Q) q = POWER_MIN_Q;
    if (q > POWER_MAX_Q) q = POWER_MAX_Q;
    s_power_q = q;
    esp_err_t e = nvs_write_q(KEY_POWER, (int16_t)q);
    if (e != ESP_OK) return e;
    status_lock();
    s_status.power_dbm = q / 4.0f;
    status_unlock();
    apply_power_q(q);
    return ESP_OK;
}

float wifi_prov_get_power(void)
{
    status_lock();
    float p = s_status.power_dbm;
    status_unlock();
    return p;
}

void wifi_prov_start(void)
{
    s_lock = xSemaphoreCreateMutex();

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler, NULL, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    /* 读取持久化凭据与功率 */
    char up_ssid[33] = {0}, up_pass[65] = {0};
    nvs_read_str(KEY_UP_SSID, up_ssid, sizeof(up_ssid));
    nvs_read_str(KEY_UP_PASS, up_pass, sizeof(up_pass));
    int16_t power_q = nvs_read_q(KEY_POWER, POWER_DEFAULT_Q);
    if (power_q < POWER_MIN_Q || power_q > POWER_MAX_Q) power_q = POWER_DEFAULT_Q;

    bool has_creds = up_ssid[0];

    s_sta = esp_netif_create_default_wifi_sta();

    snprintf(s_up_ssid, sizeof(s_up_ssid), "%s", up_ssid);
    snprintf(s_up_pass, sizeof(s_up_pass), "%s", up_pass);
    s_conn_req = xSemaphoreCreateBinary();
    xTaskCreatePinnedToCore(conn_task, "wifi_conn", 4096, NULL, 4, NULL, 0);

    if (has_creds) {
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        apply_sta_config(up_ssid, up_pass, false);
    } else {
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
        s_ap = esp_netif_create_default_wifi_ap();
        apply_ap_config();
    }

    status_lock();
    memset(&s_status, 0, sizeof(s_status));
    s_status.power_dbm = power_q / 4.0f;
    s_status.provisioning = !has_creds;
    if (has_creds) strncpy(s_status.sta_ssid, up_ssid, sizeof(s_status.sta_ssid) - 1);
    status_unlock();
    s_power_q = power_q;

    ESP_ERROR_CHECK(esp_wifi_start());

    /* wifi_start 会复位发射功率，必须在启动后再应用 */
    apply_power_q(s_power_q);

    if (s_ap) {
        esp_netif_dhcps_start(s_ap);
        ESP_LOGI(TAG, "配网 AP DHCP 已启动，地址 192.168.4.1");
    }

    ESP_LOGI(TAG, "启动完成，%s", has_creds ? "已配置上游，STA 连接中" : "进入配网热点 " PROV_AP_SSID);
}
