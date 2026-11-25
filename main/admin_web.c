#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "wifi_prov.h"
#include "espnow_master.h"
#include "dns_adblock.h"
#include "count_store.h"

static const char *TAG = "admin_web";

extern const char _binary_prov_html_start[]  asm("_binary_prov_html_start");
extern const char _binary_prov_html_end[]    asm("_binary_prov_html_end");
extern const char _binary_done_html_start[]  asm("_binary_done_html_start");
extern const char _binary_done_html_end[]    asm("_binary_done_html_end");
extern const char _binary_admin_html_start[]  asm("_binary_admin_html_start");
extern const char _binary_admin_html_end[]    asm("_binary_admin_html_end");
extern const char _binary_button_html_start[] asm("_binary_button_html_start");
extern const char _binary_button_html_end[]   asm("_binary_button_html_end");

static httpd_handle_t s_server = NULL;

/* ---------- JSON 小工具 ---------- */

static bool json_get_str(const char *body, const char *key, char *out, size_t len)
{
    char pat[40];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return false;
    p = strchr(p + strlen(pat), ':');
    if (!p) return false;
    p = strchr(p + 1, '"');
    if (!p) return false;
    p++;
    const char *e = strchr(p, '"');
    if (!e) return false;
    size_t n = (size_t)(e - p);
    if (n >= len) n = len - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static bool json_get_float(const char *body, const char *key, float *out)
{
    char pat[40];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return false;
    p = strchr(p + strlen(pat), ':');
    if (!p) return false;
    *out = (float)atof(p + 1);
    return true;
}

static void json_escape_ssid(const char *in, char *out, size_t len)
{
    size_t j = 0;
    for (size_t i = 0; in[i] && j < len - 2; i++) {
        if (in[i] == '"' || in[i] == '\\') out[j++] = '\\';
        out[j++] = in[i];
    }
    out[j] = '\0';
}

static esp_err_t send_json(httpd_req_t *req, const char *str)
{
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_sendstr(req, str);
    return ESP_OK;
}

static esp_err_t send_embed(httpd_req_t *req, const char *start, const char *end, const char *type)
{
    httpd_resp_set_type(req, type);
    httpd_resp_send(req, start, end - start);
    return ESP_OK;
}

/* ---------- 四宫格按钮标题（NVS 持久化） ---------- */

#define BTN_COUNT     2
#define BTN_TITLE_LEN 24
#define BTN_MAC_LEN   18
#define BTN_NVS_NS    "host"

static const char *button_key(int i)
{
    static const char *keys[BTN_COUNT] = { "btn_t1", "btn_t2" };
    return keys[i];
}

static const char *button_mac_key(int i)
{
    static const char *keys[BTN_COUNT] = { "btn_m1", "btn_m2" };
    return keys[i];
}

static void button_title_get(int i, char *out, size_t len)
{
    nvs_handle_t h;
    bool ok = false;
    if (out && len > 0) out[0] = '\0';
    if (nvs_open(BTN_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        size_t n = len;
        if (nvs_get_str(h, button_key(i), out, &n) == ESP_OK && out[0]) ok = true;
        nvs_close(h);
    }
    if (!ok) snprintf(out, len, "按钮%d", i + 1);
}

static esp_err_t button_title_set(int i, const char *title)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(BTN_NVS_NS, NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    e = nvs_set_str(h, button_key(i), title ? title : "");
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

static void button_mac_get(int i, char *out, size_t len)
{
    nvs_handle_t h;
    if (out && len > 0) out[0] = '\0';
    if (nvs_open(BTN_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        size_t n = len;
        if (nvs_get_str(h, button_mac_key(i), out, &n) != ESP_OK) out[0] = '\0';
        nvs_close(h);
    }
}

static esp_err_t button_mac_set(int i, const char *mac)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(BTN_NVS_NS, NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    e = nvs_set_str(h, button_mac_key(i), mac ? mac : "");
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

static bool mac_str_to_bytes(const char *str, uint8_t mac[6])
{
    if (!str || sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        return false;
    }
    return true;
}

/* ---------- 页面 ---------- */

/* captive portal：配网阶段任意未注册路径 302 回根配网页；联网后保持默认 404 */
static esp_err_t portal_404_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (err != HTTPD_404_NOT_FOUND) return ESP_OK;
    wifi_status_t wst;
    wifi_prov_get_status(&wst);
    if (!wst.provisioning) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, NULL);
        return ESP_FAIL;
    }
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t root_get(httpd_req_t *req)
{
    wifi_status_t st;
    wifi_prov_get_status(&st);
    ESP_LOGI(TAG, "GET /  provisioning=%d -> %s", st.provisioning,
             st.provisioning ? "prov.html" : "admin.html");
    if (st.provisioning) {
        return send_embed(req, _binary_prov_html_start, _binary_prov_html_end,
                          "text/html; charset=utf-8");
    }
    return send_embed(req, _binary_admin_html_start, _binary_admin_html_end,
                      "text/html; charset=utf-8");
}

static esp_err_t done_get(httpd_req_t *req)
{
    return send_embed(req, _binary_done_html_start, _binary_done_html_end,
                      "text/html; charset=utf-8");
}

static esp_err_t button_page_get(httpd_req_t *req)
{
    return send_embed(req, _binary_button_html_start, _binary_button_html_end,
                      "text/html; charset=utf-8");
}

/* ---------- 配网提交 ---------- */

static esp_err_t submit_post(httpd_req_t *req)
{
    char body[512];
    int r = httpd_req_recv(req, body, sizeof(body) - 1);
    if (r <= 0) return send_json(req, "{\"success\":false,\"error\":\"no body\"}");
    body[r] = '\0';

    char ssid[33] = {0}, pass[65] = {0};
    if (!json_get_str(body, "ssid", ssid, sizeof(ssid)) || !ssid[0]) {
        return send_json(req, "{\"success\":false,\"error\":\"ssid empty\"}");
    }
    json_get_str(body, "password", pass, sizeof(pass));
    ESP_LOGI(TAG, "POST /submit ssid=%s", ssid);

    esp_err_t e = wifi_prov_save_upstream(ssid, pass);
    return send_json(req, e == ESP_OK ? "{\"success\":true}"
                                      : "{\"success\":false,\"error\":\"save failed\"}");
}

/* ---------- 已存网络（占位，返回空） ---------- */

static esp_err_t saved_list(httpd_req_t *req)      { return send_json(req, "[]"); }
static esp_err_t saved_del(httpd_req_t *req)       { return send_json(req, "{}"); }
static esp_err_t saved_default(httpd_req_t *req)   { return send_json(req, "{}"); }

/* ---------- 高级配置（功率） ---------- */

static esp_err_t advanced_config_get(httpd_req_t *req)
{
    char json[256];
    snprintf(json, sizeof(json),
        "{\"show_ota_config\":false,\"show_sleep_config\":false,"
        "\"ota_url\":\"\",\"max_tx_power\":%.1f,\"remember_bssid\":false,\"sleep_mode\":false}",
        wifi_prov_get_power());
    return send_json(req, json);
}

static esp_err_t advanced_submit_post(httpd_req_t *req)
{
    char body[256];
    int r = httpd_req_recv(req, body, sizeof(body) - 1);
    if (r <= 0) return send_json(req, "{\"success\":false,\"error\":\"no body\"}");
    body[r] = '\0';
    float p = wifi_prov_get_power();
    json_get_float(body, "max_tx_power", &p);
    wifi_prov_set_power(p);
    return send_json(req, "{\"success\":true}");
}

/* ---------- 后台状态 / 功率 ---------- */

static void hex_dump(const uint8_t *data, uint16_t len, char *out, size_t out_len)
{
    size_t j = 0;
    for (uint16_t i = 0; i < len && j + 3 < out_len; i++) {
        j += snprintf(out + j, out_len - j, "%02x", data[i]);
    }
    out[j] = '\0';
}

static void ascii_dump(const uint8_t *data, uint16_t len, char *out, size_t out_len)
{
    size_t j = 0;
    for (uint16_t i = 0; i < len && j < out_len - 1; i++) {
        uint8_t c = data[i];
        out[j++] = (c >= 32 && c < 127) ? c : '.';
    }
    out[j] = '\0';
}

/* 取板子本地时间 HH:MM；未同步 NTP 时返回空串，由前端回退浏览器时间 */
static void local_time_hm(char *out, size_t len)
{
    time_t now;
    struct tm tm;
    time(&now);
    if (now < 1700000000) { out[0] = '\0'; return; }
    localtime_r(&now, &tm);
    snprintf(out, len, "%02d:%02d", tm.tm_hour, tm.tm_min);
}

static esp_err_t status_get(httpd_req_t *req)
{
    wifi_prov_update_rssi();
    wifi_status_t st;
    wifi_prov_get_status(&st);

    /* httpd 任务栈较小，从机表与 JSON 用静态缓冲，避免栈溢出 */
    static enow_peer_t peers[ESPNOW_MAX_PEERS];
    static char json[4096];
    int count = 0;
    espnow_master_get_peers(peers, &count);

    char hm[6] = {0};
    local_time_hm(hm, sizeof(hm));
    int n = snprintf(json, sizeof(json),
        "{\"wifi\":{\"connected\":%s,\"provisioning\":%s,\"ssid\":\"%s\","
        "\"ip\":\"%s\",\"gw\":\"%s\",\"mask\":\"%s\",\"rssi\":%d,\"channel\":%d,"
        "\"power_dbm\":%.1f},\"localtime\":\"%s\",\"peers\":[",
        st.sta_connected ? "true" : "false",
        st.provisioning ? "true" : "false",
        st.sta_ssid, st.sta_ip, st.sta_gw, st.sta_mask,
        st.sta_rssi, st.sta_channel, st.power_dbm, hm);
    ESP_LOGI(TAG, "/api/status connected=%d prov=%d ssid=%s ip=%s peers=%d",
             st.sta_connected, st.provisioning, st.sta_ssid, st.sta_ip, count);

    uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);
    for (int i = 0; i < count && n < (int)sizeof(json) - 200; i++) {
        char mac[18], hex[ESPNOW_PAYLOAD_LEN * 2 + 1], asc[ESPNOW_PAYLOAD_LEN + 1];
        hex_dump(peers[i].data, peers[i].data_len, hex, sizeof(hex));
        ascii_dump(peers[i].data, peers[i].data_len, asc, sizeof(asc));
        snprintf(mac, sizeof(mac), MACSTR, MAC2STR(peers[i].mac));
        uint32_t age = now_ms > peers[i].last_seen_ms ? now_ms - peers[i].last_seen_ms : 0;
        n += snprintf(json + n, sizeof(json) - n,
            "%s{\"mac\":\"%s\",\"rssi\":%d,\"age_ms\":%u,\"data_len\":%u,\"data_hex\":\"%s\",\"data_ascii\":\"%s\"}",
            i ? "," : "", mac, peers[i].rssi, (unsigned)age, (unsigned)peers[i].data_len, hex, asc);
    }
    n += snprintf(json + n, sizeof(json) - n, "]");

    /* 四宫格按钮标题与绑定 MAC（NVS 持久化） */
    n += snprintf(json + n, sizeof(json) - n, ",\"buttons\":[");
    for (int i = 0; i < BTN_COUNT; i++) {
        char t_raw[BTN_TITLE_LEN + 1], t_esc[BTN_TITLE_LEN * 2 + 2];
        char m_raw[BTN_MAC_LEN + 1],  m_esc[BTN_MAC_LEN * 2 + 2];
        button_title_get(i, t_raw, sizeof(t_raw));
        button_mac_get(i, m_raw, sizeof(m_raw));
        json_escape_ssid(t_raw, t_esc, sizeof(t_esc));
        json_escape_ssid(m_raw, m_esc, sizeof(m_esc));
        /* 按绑定 MAC 匹配在线从机；今日计数取自计数存储（V50 帧口径） */
        bool online = false;
        uint8_t btnmac[6] = {0};
        if (m_raw[0] && mac_str_to_bytes(m_raw, btnmac)) {
            for (int j = 0; j < count; j++) {
                uint32_t age = now_ms > peers[j].last_seen_ms ? now_ms - peers[j].last_seen_ms : 0;
                if (peers[j].online && age < 30000 && memcmp(peers[j].mac, btnmac, 6) == 0) {
                    online = true;
                    break;
                }
            }
        }
        uint32_t today = count_store_today(i);
        cs_bucket_t days[CS_DAYS];
        count_store_days(i, days);
        uint32_t this_w = 0, last_w = 0;
        int32_t diff = 0;
        count_store_week(i, &this_w, &last_w, &diff);
        cs_bucket_t months[CS_MONTHS];
        count_store_months(i, months);
        uint32_t month_now = count_store_month_acc(i) + this_w;   /* 本月至今：已归档周 + 本周实时 */

        char days_arr[360], months_arr[360];
        int dn = 0, mn = 0;
        dn += snprintf(days_arr + dn, sizeof(days_arr) - dn, "[");
        for (int d = 0; d < CS_DAYS; d++) {
            dn += snprintf(days_arr + dn, sizeof(days_arr) - dn, "%s{\"d\":%ld,\"c\":%u}",
                           d ? "," : "", (long)days[d].key, (unsigned)days[d].count);
        }
        dn += snprintf(days_arr + dn, sizeof(days_arr) - dn, "]");
        /* index 0 = 本月至今（d=0 标记），其后为最近 5 个已归档月 */
        mn += snprintf(months_arr + mn, sizeof(months_arr) - mn, "[{\"d\":0,\"c\":%u}",
                       (unsigned)month_now);
        for (int m = 0; m < CS_MONTHS - 1; m++) {
            mn += snprintf(months_arr + mn, sizeof(months_arr) - mn, ",{\"d\":%ld,\"c\":%u}",
                           (long)months[m].key, (unsigned)months[m].count);
        }
        mn += snprintf(months_arr + mn, sizeof(months_arr) - mn, "]");

        n += snprintf(json + n, sizeof(json) - n,
                      "%s{\"title\":\"%s\",\"mac\":\"%s\",\"online\":%s,\"count\":%u,"
                      "\"week\":{\"this\":%u,\"last\":%u,\"diff\":%d},\"days\":%s,\"months\":%s}",
                      i ? "," : "", t_esc, m_esc, online ? "true" : "false",
                      (unsigned)today, (unsigned)this_w, (unsigned)last_w, (int)diff,
                      days_arr, months_arr);
    }
    n += snprintf(json + n, sizeof(json) - n, "]}");
    return send_json(req, json);
}

/* ---------- 系统占用率 ---------- */

static uint64_t s_prev_idle = 0, s_prev_all = 0;

static float cpu_usage(void)
{
#if defined(CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS) && defined(CONFIG_FREERTOS_USE_TRACE_FACILITY)
    static TaskStatus_t ts[24];
    uint32_t n = uxTaskGetSystemState(ts, 24, NULL);
    uint64_t idle = 0, all = 0;
    for (uint32_t i = 0; i < n; i++) {
        all += ts[i].ulRunTimeCounter;
        if (strncmp(ts[i].pcTaskName, "IDLE", 4) == 0) idle += ts[i].ulRunTimeCounter;
    }
    float r = 0.0f;
    if (s_prev_all && all > s_prev_all && idle >= s_prev_idle) {
        r = 100.0f * (1.0f - (float)(idle - s_prev_idle) / (float)(all - s_prev_all));
        if (r < 0) r = 0;
        if (r > 100) r = 100;
    }
    s_prev_all = all; s_prev_idle = idle;
    return r;
#else
    return -1.0f;
#endif
}

static esp_err_t sys_get(httpd_req_t *req)
{
    static char out[256];
    size_t in_tot  = heap_caps_get_total_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    size_t in_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    size_t ps_tot  = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    size_t ps_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    float ram = in_tot ? 100.0f * (float)(in_tot - in_free) / (float)in_tot : 0;
    float psram = ps_tot ? 100.0f * (float)(ps_tot - ps_free) / (float)ps_tot : -1;

    snprintf(out, sizeof(out),
             "{\"cpu\":%.1f,\"ram\":%.1f,\"ram_free_kb\":%u,\"psram\":%.1f,\"psram_total_kb\":%u}",
             cpu_usage(), ram, (unsigned)(in_free / 1024), psram, (unsigned)(ps_tot / 1024));
    return send_json(req, out);
}

static esp_err_t power_post(httpd_req_t *req)
{
    char body[128];
    int r = httpd_req_recv(req, body, sizeof(body) - 1);
    if (r <= 0) return send_json(req, "{\"ok\":0,\"err\":\"no body\"}");
    body[r] = '\0';
    float p = wifi_prov_get_power();
    json_get_float(body, "dbm", &p);
    esp_err_t e = wifi_prov_set_power(p);
    char out[128];
    snprintf(out, sizeof(out), "{\"ok\":%d,\"power_dbm\":%.1f}", e == ESP_OK ? 1 : 0, wifi_prov_get_power());
    return send_json(req, out);
}

static esp_err_t add_peer_post(httpd_req_t *req)
{
    char body[128];
    int r = httpd_req_recv(req, body, sizeof(body) - 1);
    if (r <= 0) return send_json(req, "{\"ok\":0,\"err\":\"no body\"}");
    body[r] = '\0';
    char macstr[32] = {0};
    if (!json_get_str(body, "mac", macstr, sizeof(macstr))) {
        return send_json(req, "{\"ok\":0,\"err\":\"mac missing\"}");
    }
    uint8_t mac[6];
    if (sscanf(macstr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        return send_json(req, "{\"ok\":0,\"err\":\"bad mac\"}");
    }
    esp_err_t e = espnow_master_add_peer(mac);
    char out[128];
    snprintf(out, sizeof(out), "{\"ok\":%d}", e == ESP_OK ? 1 : 0);
    return send_json(req, out);
}

/* ---------- 四宫格按钮标题 ---------- */

static esp_err_t button_get(httpd_req_t *req)
{
    char q[64] = {0};
    int i = 0;
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        char v[8] = {0};
        if (httpd_query_key_value(q, "i", v, sizeof(v)) == ESP_OK) i = atoi(v);
    }
    if (i < 0 || i >= BTN_COUNT) i = 0;
    char title[BTN_TITLE_LEN + 1], t_esc[BTN_TITLE_LEN * 2 + 2];
    char mac[BTN_MAC_LEN + 1],  m_esc[BTN_MAC_LEN * 2 + 2];
    button_title_get(i, title, sizeof(title));
    button_mac_get(i, mac, sizeof(mac));
    json_escape_ssid(title, t_esc, sizeof(t_esc));
    json_escape_ssid(mac, m_esc, sizeof(m_esc));
    static char out[200];
    snprintf(out, sizeof(out), "{\"ok\":1,\"index\":%d,\"title\":\"%s\",\"mac\":\"%s\"}",
             i, t_esc, m_esc);
    return send_json(req, out);
}

static esp_err_t button_post(httpd_req_t *req)
{
    char body[160];
    int r = httpd_req_recv(req, body, sizeof(body) - 1);
    if (r <= 0) return send_json(req, "{\"ok\":0,\"err\":\"no body\"}");
    body[r] = '\0';
    float fi = 0;
    json_get_float(body, "index", &fi);
    int i = (int)fi;
    char title[BTN_TITLE_LEN + 1] = {0};
    char macstr[BTN_MAC_LEN + 1] = {0};
    bool has_title = json_get_str(body, "title", title, sizeof(title));
    bool has_mac   = json_get_str(body, "mac", macstr, sizeof(macstr));
    if (i < 0 || i >= BTN_COUNT) return send_json(req, "{\"ok\":0,\"err\":\"bad index\"}");

    /* 去掉 MAC 首尾空白并转大写 */
    char mac_clean[BTN_MAC_LEN + 1] = {0};
    const char *p = macstr;
    while (*p == ' ') p++;
    snprintf(mac_clean, sizeof(mac_clean), "%s", p);
    size_t ml = strlen(mac_clean);
    while (ml > 0 && mac_clean[ml - 1] == ' ') mac_clean[--ml] = '\0';
    for (char *c = mac_clean; *c; c++) *c = (char)toupper((unsigned char)*c);

    uint8_t mac[6] = {0};
    if (mac_clean[0] && !mac_str_to_bytes(mac_clean, mac)) {
        return send_json(req, "{\"ok\":0,\"err\":\"bad mac\"}");
    }

    esp_err_t e = ESP_OK;
    if (has_title) e = button_title_set(i, title);   /* 显式携带 title 时更新标题 */
    /* 仅当请求显式携带 mac 字段时才更新绑定；未携带则保留原 NVS 绑定，避免被清空 */
    if (e == ESP_OK && has_mac) e = button_mac_set(i, mac_clean);
    if (e == ESP_OK) {
        uint8_t bmac[6] = {0};
        bool bind = false;
        if (has_mac) {
            if (mac_clean[0] && mac_str_to_bytes(mac_clean, bmac)) bind = true;
        } else {
            char old[BTN_MAC_LEN + 1] = {0};
            button_mac_get(i, old, sizeof(old));
            if (old[0] && mac_str_to_bytes(old, bmac)) bind = true;
        }
        count_store_bind_mac(i, bind ? bmac : NULL);
        if (bind) espnow_master_add_peer(bmac);   /* 注册为 ESP-NOW 对端，失败不阻断保存 */
    }

    char cur_t[BTN_TITLE_LEN + 1], t_esc[BTN_TITLE_LEN * 2 + 2];
    char cur_m[BTN_MAC_LEN + 1],  m_esc[BTN_MAC_LEN * 2 + 2];
    button_title_get(i, cur_t, sizeof(cur_t));
    button_mac_get(i, cur_m, sizeof(cur_m));
    json_escape_ssid(cur_t, t_esc, sizeof(t_esc));
    json_escape_ssid(cur_m, m_esc, sizeof(m_esc));
    static char out[220];
    snprintf(out, sizeof(out), "{\"ok\":%d,\"index\":%d,\"title\":\"%s\",\"mac\":\"%s\"}",
             e == ESP_OK ? 1 : 0, i, t_esc, m_esc);
    return send_json(req, out);
}

static esp_err_t button_clear(httpd_req_t *req)
{
    char body[128];
    int r = httpd_req_recv(req, body, sizeof(body) - 1);
    if (r <= 0) return send_json(req, "{\"ok\":0,\"err\":\"no body\"}");
    body[r] = '\0';
    float fi = 0;
    json_get_float(body, "index", &fi);
    int i = (int)fi;
    if (i < 0 || i >= BTN_COUNT) return send_json(req, "{\"ok\":0,\"err\":\"bad index\"}");

    /* 清空该按钮的上报数据与绑定 MAC；标题保留 */
    char old[BTN_MAC_LEN + 1] = {0};
    button_mac_get(i, old, sizeof(old));
    uint8_t mac[6] = {0};
    bool has_mac = old[0] && mac_str_to_bytes(old, mac);
    if (has_mac) {
        espnow_master_clear_data(mac);
        espnow_master_remove_peer(mac);
    }
    count_store_clear(i);
    count_store_bind_mac(i, NULL);
    button_mac_set(i, "");   /* 解绑并清空 NVS 中的 MAC；标题不动 */
    return send_json(req, "{\"ok\":1}");
}

static esp_err_t button_send_post(httpd_req_t *req)
{
    char body[128];
    int r = httpd_req_recv(req, body, sizeof(body) - 1);
    if (r <= 0) return send_json(req, "{\"ok\":0,\"err\":\"no body\"}");
    body[r] = '\0';
    float fi = 0;
    json_get_float(body, "index", &fi);
    int i = (int)fi;
    if (i < 0 || i >= BTN_COUNT) return send_json(req, "{\"ok\":0,\"err\":\"bad index\"}");

    char old[BTN_MAC_LEN + 1] = {0};
    button_mac_get(i, old, sizeof(old));
    if (!old[0]) return send_json(req, "{\"ok\":0,\"err\":\"no mac\"}");
    uint8_t mac[6] = {0};
    if (!mac_str_to_bytes(old, mac)) return send_json(req, "{\"ok\":0,\"err\":\"bad mac\"}");

    const char *payload = "open";
    esp_err_t e = espnow_master_send(mac, (const uint8_t *)payload, strlen(payload));
    char out[128];
    snprintf(out, sizeof(out), "{\"ok\":%d}", e == ESP_OK ? 1 : 0);
    return send_json(req, out);
}

static esp_err_t dns_status_get(httpd_req_t *req)
{
    static char buf[10240];   /* 含 20 条拦截记录 + 白/黑各 64 条 + 20 条无应答域名（带次数），过小会截断导致 JSON 解析失败 */
    dns_adblock_status(buf, sizeof(buf));
    return send_json(req, buf);
}

static esp_err_t dns_toggle_post(httpd_req_t *req)
{
    char body[64];
    int r = httpd_req_recv(req, body, sizeof(body)-1);
    if (r <= 0) return send_json(req, "{\"ok\":0}");
    body[r]='\0';
    float on=0; json_get_float(body,"on",&on);
    dns_adblock_set_on(on>0?true:false);
    return send_json(req, "{\"ok\":1}");
}


static esp_err_t dns_wl_post(httpd_req_t *req)
{
    char body[256];
    int r = httpd_req_recv(req, body, sizeof(body)-1);
    if (r <= 0) return send_json(req, "{\"ok\":0,\"msg\":\"no body\"}");
    body[r] = '\0';
    char op[16] = "", dom[80] = "", type[8] = "";
    json_get_str(body, "op", op, sizeof(op));
    json_get_str(body, "domain", dom, sizeof(dom));
    json_get_str(body, "type", type, sizeof(type));
    if (!dom[0]) return send_json(req, "{\"ok\":0,\"msg\":\"域名为空\"}");
    bool is_bl = (strcmp(type, "bl") == 0);
    esp_err_t e;
    if (strcmp(op, "del") == 0)
        e = is_bl ? dns_adblock_bl_del(dom) : dns_adblock_wl_del(dom);
    else
        e = is_bl ? dns_adblock_bl_add(dom) : dns_adblock_wl_add(dom);
    static char buf[128];
    snprintf(buf, sizeof(buf), "{\"ok\":%s,\"msg\":\"%s\"}",
             e==ESP_OK?"1":"0", e==ESP_OK?"已处理":(e==ESP_ERR_NOT_FOUND?"未找到":"失败"));
    return send_json(req, buf);
}
static esp_err_t dns_update_post(httpd_req_t *req)
{
    esp_err_t e = dns_adblock_update_async();   /* 大栈后台任务拉取，接口立刻返回 */
    static char buf[512];
    if (e == ESP_ERR_INVALID_STATE) {
        snprintf(buf, sizeof(buf), "{\"ok\":0,\"msg\":\"正在更新中\"}");
    } else if (e != ESP_OK) {
        snprintf(buf, sizeof(buf), "{\"ok\":0,\"msg\":\"任务创建失败\"}");
    } else {
        snprintf(buf, sizeof(buf), "{\"ok\":1,\"msg\":\"已开始拉取\"}");
    }
    return send_json(req, buf);
}

static esp_err_t dns_clear_post(httpd_req_t *req)
{
    dns_adblock_clear_blocked();
    return send_json(req, "{\"ok\":1}");
}

/* 三个独立清除：只清累计拦截总数 / 本次拦截域名列表 / 本次上游无应答列表 */
static esp_err_t dns_clear_total_post(httpd_req_t *req)
{
    dns_adblock_clear_total();
    return send_json(req, "{\"ok\":1}");
}

static esp_err_t dns_clear_blocks_post(httpd_req_t *req)
{
    dns_adblock_clear_blocks();
    return send_json(req, "{\"ok\":1}");
}

static esp_err_t dns_clear_fails_post(httpd_req_t *req)
{
    dns_adblock_clear_fails();
    return send_json(req, "{\"ok\":1}");
}

/* ---------- OTA：网页直接上传 App bin ---------- */

static void ota_reboot_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(800));    /* 先让 HTTP 应答发出去 */
    ESP_LOGI(TAG, "OTA 完成，重启进入新固件");
    esp_restart();
}

static esp_err_t ota_post(httpd_req_t *req)
{
    size_t total = (size_t)req->content_len;
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part)
        return send_json(req, "{\"ok\":0,\"msg\":\"没有可写的 OTA 分区（分区表未改成双 app）\"}");
    if (total == 0)
        return send_json(req, "{\"ok\":0,\"msg\":\"空包\"}");
    if (total > part->size) {
        char b[160];
        snprintf(b, sizeof(b), "{\"ok\":0,\"msg\":\"固件 %u 字节，超出目标分区 %u 字节\"}",
                 (unsigned)total, (unsigned)part->size);
        return send_json(req, b);
    }
    ESP_LOGW(TAG, "开始 OTA：目标 %s @0x%x，%u 字节", part->label, (unsigned)part->address, (unsigned)total);

    esp_ota_handle_t h = 0;
    esp_err_t e = esp_ota_begin(part, total, &h);
    if (e != ESP_OK) {
        char b[160];
        snprintf(b, sizeof(b), "{\"ok\":0,\"msg\":\"OTA begin 失败 %s\"}", esp_err_to_name(e));
        return send_json(req, b);
    }

    const int CH = 4096;
    char *buf = (char *)malloc(CH);
    size_t got = 0;
    int idle = 0;
    if (!buf) e = ESP_ERR_NO_MEM;
    while (e == ESP_OK && buf && got < total) {
        int r = httpd_req_recv(req, buf, CH);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) {          /* 慢链路：最多容忍 50 次 */
            if (++idle > 50) { e = ESP_ERR_TIMEOUT; break; }
            continue;
        }
        if (r <= 0) { e = ESP_FAIL; break; }
        idle = 0;
        e = esp_ota_write(h, buf, (size_t)r);
        got += (size_t)r;
    }
    free(buf);
    if (e == ESP_OK && got != total) e = ESP_ERR_INVALID_SIZE;
    if (e == ESP_OK) e = esp_ota_end(h);
    else            esp_ota_abort(h);
    if (e == ESP_OK) e = esp_ota_set_boot_partition(part);

    char b[192];
    if (e == ESP_OK) {
        snprintf(b, sizeof(b), "{\"ok\":1,\"msg\":\"已写入 %u 字节并设为启动分区，正在重启\"}", (unsigned)got);
        send_json(req, b);
        xTaskCreatePinnedToCore(ota_reboot_task, "ota_reboot", 3072, NULL, 3, NULL, 0);
    } else {
        snprintf(b, sizeof(b), "{\"ok\":0,\"msg\":\"OTA 失败 %s，已回滚\"}", esp_err_to_name(e));
        send_json(req, b);
    }
    return ESP_OK;
}

/* ---------- 启动 ---------- */

static void bind_saved_macs(void)
{
    for (int i = 0; i < BTN_COUNT; i++) {
        char mraw[BTN_MAC_LEN + 1] = {0};
        uint8_t mac[6] = {0};
        button_mac_get(i, mraw, sizeof(mraw));
        if (mraw[0] && mac_str_to_bytes(mraw, mac)) count_store_bind_mac(i, mac);
        else count_store_bind_mac(i, NULL);
    }
}

void admin_web_start(void)
{
    bind_saved_macs();

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_uri_handlers = 32;
    config.core_id = 0;          /* 网页服务固定核 0，不跟 DNS 抢核 1 */
    config.task_priority = 5;
    config.max_open_sockets = 7;
    config.lru_purge_enable = true;  /* 连接占满时淘汰最久未用会话，避免 accept (23) */

    if (httpd_start(&s_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "网页服务启动失败");
        return;
    }

    httpd_register_err_handler(s_server, HTTPD_404_NOT_FOUND, portal_404_handler);

    httpd_uri_t root   = {.uri = "/",              .method = HTTP_GET,  .handler = root_get};
    httpd_uri_t done   = {.uri = "/done.html",     .method = HTTP_GET,  .handler = done_get};
    httpd_uri_t sub    = {.uri = "/submit",        .method = HTTP_POST, .handler = submit_post};
    httpd_uri_t slist  = {.uri = "/saved/list",   .method = HTTP_GET,  .handler = saved_list};
    httpd_uri_t sdel   = {.uri = "/saved/delete",  .method = HTTP_GET,  .handler = saved_del};
    httpd_uri_t sdef   = {.uri = "/saved/set_default", .method = HTTP_GET, .handler = saved_default};
    httpd_uri_t advc   = {.uri = "/advanced/config",   .method = HTTP_GET,  .handler = advanced_config_get};
    httpd_uri_t advs   = {.uri = "/advanced/submit",   .method = HTTP_POST, .handler = advanced_submit_post};
    httpd_uri_t status = {.uri = "/api/status",   .method = HTTP_GET,  .handler = status_get};
    httpd_uri_t sysst  = {.uri = "/api/sys",      .method = HTTP_GET,  .handler = sys_get};
    httpd_uri_t power  = {.uri = "/api/power",    .method = HTTP_POST, .handler = power_post};
    httpd_uri_t addpeer = {.uri = "/api/add_peer", .method = HTTP_POST, .handler = add_peer_post};
    httpd_uri_t dnsst = {.uri = "/api/dns",        .method = HTTP_GET,  .handler = dns_status_get};
    httpd_uri_t dnsto = {.uri = "/api/dns/toggle", .method = HTTP_POST, .handler = dns_toggle_post};
    httpd_uri_t dnsup = {.uri = "/api/dns/update", .method = HTTP_POST, .handler = dns_update_post};
    httpd_uri_t dnswl = {.uri = "/api/dns/whitelist", .method = HTTP_POST, .handler = dns_wl_post};
    httpd_uri_t dnsclr = {.uri = "/api/dns/clear", .method = HTTP_POST, .handler = dns_clear_post};
    httpd_uri_t dnsclrt = {.uri = "/api/dns/clear_total",  .method = HTTP_POST, .handler = dns_clear_total_post};
    httpd_uri_t dnsclrb = {.uri = "/api/dns/clear_blocks", .method = HTTP_POST, .handler = dns_clear_blocks_post};
    httpd_uri_t dnsclrf = {.uri = "/api/dns/clear_fails",  .method = HTTP_POST, .handler = dns_clear_fails_post};
    httpd_uri_t ota    = {.uri = "/api/ota",        .method = HTTP_POST, .handler = ota_post};
    httpd_uri_t btnpg = {.uri = "/button.html",    .method = HTTP_GET,  .handler = button_page_get};
    httpd_uri_t btng  = {.uri = "/api/button",     .method = HTTP_GET,  .handler = button_get};
    httpd_uri_t btnp  = {.uri = "/api/button",     .method = HTTP_POST, .handler = button_post};
    httpd_uri_t btnc  = {.uri = "/api/button/clear", .method = HTTP_POST, .handler = button_clear};
    httpd_uri_t btns = {.uri = "/api/button/send", .method = HTTP_POST, .handler = button_send_post};

    httpd_register_uri_handler(s_server, &root);
    httpd_register_uri_handler(s_server, &done);
    httpd_register_uri_handler(s_server, &sub);
    httpd_register_uri_handler(s_server, &slist);
    httpd_register_uri_handler(s_server, &sdel);
    httpd_register_uri_handler(s_server, &sdef);
    httpd_register_uri_handler(s_server, &advc);
    httpd_register_uri_handler(s_server, &advs);
    httpd_register_uri_handler(s_server, &status);
    httpd_register_uri_handler(s_server, &sysst);
    httpd_register_uri_handler(s_server, &power);
    httpd_register_uri_handler(s_server, &addpeer);
    httpd_register_uri_handler(s_server, &dnsst);
    httpd_register_uri_handler(s_server, &dnsto);
    httpd_register_uri_handler(s_server, &dnsup);
    httpd_register_uri_handler(s_server, &dnswl);
    httpd_register_uri_handler(s_server, &dnsclr);
    httpd_register_uri_handler(s_server, &dnsclrt);
    httpd_register_uri_handler(s_server, &dnsclrb);
    httpd_register_uri_handler(s_server, &dnsclrf);
    httpd_register_uri_handler(s_server, &ota);
    httpd_register_uri_handler(s_server, &btnpg);
    httpd_register_uri_handler(s_server, &btng);
    httpd_register_uri_handler(s_server, &btnp);
    httpd_register_uri_handler(s_server, &btnc);
    httpd_register_uri_handler(s_server, &btns);

    ESP_LOGI(TAG, "网页服务已启动（配网页 / 后台页 / 接口）");
}
