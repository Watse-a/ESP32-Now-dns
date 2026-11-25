#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "esp_http_client.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_partition.h"
#include "esp_crt_bundle.h"
#include "esp_tls.h"

#include "dns_adblock.h"
#include "dns_rules.h"
#include "wifi_prov.h"
#include "esp_sntp.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"

static const char *TAG = "dns_adblock";
#define AP_IP_STR "192.168.4.1"   /* 配网热点默认网关，captive portal 劫持目标 */
#define NVS_NS "host"
#define KEY_DNS_ON "dns_on"
#define KEY_BLK_TOTAL "blk_total"   /* 已拦截总数，掉电/重启保留 */
#define UPSTREAM_HOST "dns.18bit.cn"
#define DOT_PORT      853            /* 上游走 DNS-over-TLS（RFC 853），TCP 853 */
#define DOT_TIMEOUT_MS 3000          /* 单次 DoT 握手超时压到 3s：转发在独立任务里，不能让慢节点拖住接包 */
/* 解析出该域名的全部 A 记录，按顺序试，无应答换下一个 IP */
#define UP_MAX 8
static uint32_t up_ips[UP_MAX];
static int up_n = 0;
static int up_idx = 0;
/* 上游表由独立的解析任务写、转发任务读，用小临界区保护；只在切换表时短暂占用，不阻塞转发 */
static portMUX_TYPE s_up_mux = portMUX_INITIALIZER_UNLOCKED;

/* 到上游的复用 DoT/TLS 长连接；dns_task 单线程串行访问，无需加锁 */
static esp_tls_t *dot_tls = NULL;
static uint32_t   dot_ip  = 0;

static void build_probe_query(uint8_t *buf, int *len);
static int  probe_upstream(uint32_t ip);   /* 成功返回耗时 ms(>0)，失败返回 -1 */
static void ip4_str(uint32_t saddr, char *out, size_t n);

static void up_resolve(void)
{
    ESP_LOGI(TAG, "开始解析上游 %s", UPSTREAM_HOST);
    struct addrinfo h = {.ai_family=AF_INET, .ai_socktype=SOCK_STREAM}, *r = NULL;
    if (getaddrinfo(UPSTREAM_HOST, NULL, &h, &r) != 0 || !r) {
        ESP_LOGW(TAG, "%s 解析失败，保留现有 %d 个上游 IP", UPSTREAM_HOST, up_n);
        return;
    }
    uint32_t cand[UP_MAX];
    int cn = 0;
    for (struct addrinfo *p = r; p && cn < UP_MAX; p = p->ai_next)
        cand[cn++] = ((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(r);

    for (int i = 0; i < cn; i++) {
        char sip[16]; ip4_str(cand[i], sip, sizeof(sip));
        ESP_LOGI(TAG, "候选上游 %s", sip);
    }

    /* 逐个 DoT 探测可用性，记录耗时；全部不可用则沿用旧表 */
    uint32_t ok_ip[UP_MAX];
    int ok_ms[UP_MAX];
    int on = 0;
    for (int i = 0; i < cn; i++) {
        int dt = probe_upstream(cand[i]);
        if (dt > 0) { ok_ip[on] = cand[i]; ok_ms[on] = dt; on++; }
    }

    /* 按探测耗时升序：快节点排前优先复用，慢节点兜底轮换 */
    for (int i = 0; i < on - 1; i++)
        for (int j = i + 1; j < on; j++)
            if (ok_ms[j] < ok_ms[i]) {
                uint32_t t_ip = ok_ip[i]; ok_ip[i] = ok_ip[j]; ok_ip[j] = t_ip;
                int t_ms = ok_ms[i]; ok_ms[i] = ok_ms[j]; ok_ms[j] = t_ms;
            }

    if (on > 0) {
        /* 当前在用的节点如果还可用，就把它排到第一位并保持 up_idx=0：
           换表不换节点，避免 dot_tls 因 IP 变化重建连接、首条查询多等一次握手 */
        uint32_t cur = 0;
        portENTER_CRITICAL(&s_up_mux);
        if (up_n) cur = up_ips[up_idx];
        portEXIT_CRITICAL(&s_up_mux);
        int pos = -1;
        for (int i = 0; i < on; i++) if (ok_ip[i] == cur) { pos = i; break; }
        if (pos > 0) {
            uint32_t t_ip = ok_ip[0]; ok_ip[0] = ok_ip[pos]; ok_ip[pos] = t_ip;
            int t_ms = ok_ms[0]; ok_ms[0] = ok_ms[pos]; ok_ms[pos] = t_ms;
            pos = 0;
        }

        portENTER_CRITICAL(&s_up_mux);
        memcpy(up_ips, ok_ip, (size_t)on * sizeof(uint32_t));
        up_n = on;
        up_idx = 0;
        portEXIT_CRITICAL(&s_up_mux);
        if (pos == 0) ESP_LOGI(TAG, "%s 可用上游 %d/%d 个（保持原节点 %dms）", UPSTREAM_HOST, on, cn, ok_ms[0]);
        else          ESP_LOGI(TAG, "%s 可用上游 %d/%d 个（最快 %dms）", UPSTREAM_HOST, on, cn, ok_ms[0]);
    } else {
        ESP_LOGW(TAG, "%s 全部 %d 个上游 IP 不可用，保留现有 %d 个", UPSTREAM_HOST, cn, up_n);
    }
}

static SemaphoreHandle_t s_lock;
static bool s_on = false;
static bool s_running = false;
static int s_user_count = 0;
static int s_block_count = 0;
static int s_run_blocked = 0;   /* 本次运行（开机以来）拦截次数，不落盘 */
static int s_run_fails = 0;     /* 本次运行（开机以来）上游无应答次数，不落盘 */
static char s_last_update[32] = "--";
static int s_last_day = -1;
static volatile bool s_updating = false;
static char s_upd_msg[96] = "";
static void blk_total_load(void);
static void blk_total_save(void);

/* ---- 规则存活区：优先 PSRAM，退回内部 RAM ---- */
static void *r_alloc(size_t sz)
{
    void *p = heap_caps_malloc(sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) p = heap_caps_malloc(sz, MALLOC_CAP_8BIT);
    return p;
}

#define CACHE_N        100
#define CACHE_TTL_MS   60000

typedef struct {
    char     name[96];
    uint16_t qtype;
    uint16_t len;
    int64_t  exp_ms;
    uint32_t use;
    uint8_t  pkt[512];
} centry_t;

static centry_t *s_cache = NULL;
static SemaphoreHandle_t s_cache_mux = NULL;   /* 收包任务只读、转发任务写入，需加锁 */
static int s_cache_used = 0;
static uint32_t s_cache_seq = 0;
static int s_cache_hits = 0;
static int s_cache_store = 0;   /* 累计成功存入条数（含过期覆盖） */
static int s_cache_skip = 0;    /* 累计因报文原因跳过缓存的条数 */

/* ---- 客户端统计（最多 8 个）---- */
#define CLI_N 8
typedef struct {
    char     ip[16];
    uint32_t n;
    int64_t  last_ms;
} client_t;
static client_t s_cli[CLI_N];
static int s_cli_n = 0;

static void ip_str(const struct sockaddr_in *addr, char *ip, size_t n)
{
    uint32_t a = ntohl(addr->sin_addr.s_addr);
    snprintf(ip, n, "%u.%u.%u.%u",
             (unsigned)(a >> 24) & 0xFF, (unsigned)(a >> 16) & 0xFF,
             (unsigned)(a >> 8) & 0xFF, (unsigned)a & 0xFF);
}

/* 网络序 IP 转点分字符串，用于日志 */
static void ip4_str(uint32_t saddr, char *out, size_t n)
{
    uint32_t a = ntohl(saddr);
    snprintf(out, n, "%u.%u.%u.%u",
             (unsigned)(a >> 24) & 0xFF, (unsigned)(a >> 16) & 0xFF,
             (unsigned)(a >> 8) & 0xFF, (unsigned)a & 0xFF);
}

/* ---- 最近拦截记录（环形，20 条）---- */
#define BLOCK_LOG_N 20
typedef struct {
    char ip[16];
    char domain[64];
    uint32_t n;
} block_log_t;
static block_log_t s_blog[BLOCK_LOG_N];
static int s_blog_idx = 0;
static int s_blog_cnt = 0;
static portMUX_TYPE s_blog_mux = portMUX_INITIALIZER_UNLOCKED;

static void block_log_add(const char *ip, const char *domain)
{
    portENTER_CRITICAL(&s_blog_mux);
    /* 同一个 IP + 同一个域名不重复占位，只累加次数 */
    for (int i = 0; i < s_blog_cnt; i++) {
        if (strcmp(s_blog[i].ip, ip) == 0 && strcmp(s_blog[i].domain, domain) == 0) {
            if (s_blog[i].n < 99999) s_blog[i].n++;
            portEXIT_CRITICAL(&s_blog_mux);
            return;
        }
    }
    block_log_t *e = &s_blog[s_blog_idx];
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    snprintf(e->domain, sizeof(e->domain), "%s", domain);
    e->n = 1;
    s_blog_idx = (s_blog_idx + 1) % BLOCK_LOG_N;
    if (s_blog_cnt < BLOCK_LOG_N) s_blog_cnt++;
    portEXIT_CRITICAL(&s_blog_mux);
}

/* ---- 上游无应答域名（环形，最多 20 条）：DoT/网关全部失败、未拿到应答 ---- */
#define FAIL_LOG_N 20
typedef struct {
    char     domain[64];
    uint32_t n;
} fail_log_t;
static fail_log_t s_fail[FAIL_LOG_N];
static int s_fail_idx = 0;
static int s_fail_cnt = 0;
static portMUX_TYPE s_fail_mux = portMUX_INITIALIZER_UNLOCKED;

static void fail_log_add(const char *domain)
{
    if (!domain || !*domain) return;
    s_run_fails++;
    portENTER_CRITICAL(&s_fail_mux);
    for (int i = 0; i < s_fail_cnt; i++) {
        if (strcmp(s_fail[i].domain, domain) == 0) {
            if (s_fail[i].n < 99999) s_fail[i].n++;
            portEXIT_CRITICAL(&s_fail_mux);
            return;
        }
    }
    fail_log_t *e = &s_fail[s_fail_idx];
    snprintf(e->domain, sizeof(e->domain), "%s", domain);
    e->n = 1;
    s_fail_idx = (s_fail_idx + 1) % FAIL_LOG_N;
    if (s_fail_cnt < FAIL_LOG_N) s_fail_cnt++;
    portEXIT_CRITICAL(&s_fail_mux);
}

static void client_touch(const struct sockaddr_in *addr, int64_t now_ms)
{
    char ip[16];
    ip_str(addr, ip, sizeof(ip));
    for (int i = 0; i < s_cli_n; i++) {
        if (strcmp(s_cli[i].ip, ip) == 0) { s_cli[i].n++; s_cli[i].last_ms = now_ms; return; }
    }
    int slot = s_cli_n < CLI_N ? s_cli_n : 0;
    if (s_cli_n < CLI_N) s_cli_n++;
    else {  /* 满了就替换最少使用的 */
        for (int i = 1; i < CLI_N; i++) if (s_cli[i].n < s_cli[slot].n) slot = i;
    }
    strcpy(s_cli[slot].ip, ip);
    s_cli[slot].n = 1;
    s_cli[slot].last_ms = now_ms;
}

static void cache_init(void)
{
    if (!s_cache_mux) s_cache_mux = xSemaphoreCreateMutex();
    size_t sz = sizeof(centry_t) * CACHE_N;
    s_cache = heap_caps_malloc(sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_cache) s_cache = heap_caps_malloc(sz, MALLOC_CAP_8BIT);
    if (!s_cache) { ESP_LOGW(TAG, "缓存分配失败，缓存关闭"); return; }
    memset(s_cache, 0, sz);
    ESP_LOGI(TAG, "DNS 缓存 %d 条已启用（%u 字节）", CACHE_N, (unsigned)sz);
}

static void cache_flush(void)
{
    if (!s_cache) return;
    if (s_cache_mux) xSemaphoreTake(s_cache_mux, portMAX_DELAY);
    memset(s_cache, 0, sizeof(centry_t) * CACHE_N);
    s_cache_used = 0;
    if (s_cache_mux) xSemaphoreGive(s_cache_mux);
}

/* 命中则把报文拷给调用者（不放指针，避免拷贝过程中被 LRU 覆盖），返回报文长度 */
static int cache_get_copy(const char *name, uint16_t qtype, int64_t now, uint8_t *out, int outcap)
{
    if (!s_cache) return 0;
    int got = 0;
    if (s_cache_mux) xSemaphoreTake(s_cache_mux, portMAX_DELAY);
    for (int i = 0; i < CACHE_N; i++) {
        centry_t *e = &s_cache[i];
        if (e->len && e->qtype == qtype && now < e->exp_ms && strcmp(e->name, name) == 0) {
            e->use = ++s_cache_seq;
            if ((int)e->len <= outcap) { memcpy(out, e->pkt, e->len); got = e->len; }
            break;
        }
    }
    if (s_cache_mux) xSemaphoreGive(s_cache_mux);
    return got;
}

static void cache_put(const char *name, uint16_t qtype, const uint8_t *pkt, int len, int64_t now)
{
    if (!s_cache) { ESP_LOGW(TAG, "缓存未初始化，丢弃 %s", name); return; }
    if (len <= 0 || len > (int)sizeof(s_cache[0].pkt)) { s_cache_skip++; return; }
    /* TC 截断：应答不完整，不缓存，避免把截断结果回给客户端 */
    if ((pkt[2] & 0x02) != 0) { s_cache_skip++; return; }
    int rcode = pkt[3] & 0x0F;
    /* SERVFAIL(2) / REFUSED(5) 是上游临时故障，不缓存，下次重新查询 */
    if (rcode == 2 || rcode == 5) { s_cache_skip++; return; }
    bool no_answer = (pkt[6] == 0 && pkt[7] == 0);
    /* 负应答（无记录 NO DATA / NXDOMAIN）也缓存，但用较短 TTL，避免长时间挡住恢复的域名 */
    int ttl_ms = (no_answer || rcode == 3) ? 30000 : CACHE_TTL_MS;
    if (strlen(name) >= sizeof(s_cache[0].name)) { s_cache_skip++; return; }
    ESP_LOGI(TAG, "缓存存入 %s (type %u, %d 字节, rcode=%d, %s)", name, qtype, len, rcode,
             no_answer ? "负应答" : "正应答");

    /* 先找同名槽位，没有再找空槽 / 最久未用槽（LRU） */
    if (s_cache_mux) xSemaphoreTake(s_cache_mux, portMAX_DELAY);
    centry_t *slot = NULL;
    for (int i = 0; i < CACHE_N; i++) {
        centry_t *e = &s_cache[i];
        if (e->len && e->qtype == qtype && strcmp(e->name, name) == 0) { slot = e; break; }
    }
    if (!slot) {
        for (int i = 0; i < CACHE_N; i++) {
            if (!s_cache[i].len) { slot = &s_cache[i]; s_cache_used++; break; }
        }
    }
    if (!slot) {
        slot = &s_cache[0];
        for (int i = 1; i < CACHE_N; i++)
            if (s_cache[i].use < slot->use) slot = &s_cache[i];
    }
    strcpy(slot->name, name);
    slot->qtype = qtype;
    slot->len   = (uint16_t)len;
    slot->exp_ms = now + ttl_ms;
    slot->use   = ++s_cache_seq;
    memcpy(slot->pkt, pkt, len);
    s_cache_store++;
    if (s_cache_mux) xSemaphoreGive(s_cache_mux);
}

/* 每 7 天自动更新一次规则：每天 10:00 检查，距上次成功更新满 7 天才真拉 */
static time_t upd_ts_load(void)
{
    nvs_handle_t h;
    int32_t v = 0;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_i32(h, "upd_ts", &v);
        nvs_close(h);
    }
    return (time_t)v;
}

static void upd_ts_save(time_t t)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_i32(h, "upd_ts", (int32_t)t);
        nvs_commit(h);
        nvs_close(h);
    }
}

static void sched_cb(void *arg)
{
    time_t now; struct tm tm;
    time(&now);
    localtime_r(&now, &tm);
    if (tm.tm_hour == 10 && s_last_day != tm.tm_yday) {
        s_last_day = tm.tm_yday;
        time_t last = upd_ts_load();
        if (last == 0 || (now - last) >= 7 * 86400) {
            ESP_LOGI(TAG, "定时更新：已满7天，开始拉取");
            dns_adblock_update_now();
        } else {
            ESP_LOGI(TAG, "定时更新：距上次 %ld 天，跳过", (long)((now - last) / 86400));
        }
    }
}

static void sntp_start(void)
{
    setenv("TZ", "CST-8", 1);   /* 北京时间，否则 strftime 打出来是 UTC（慢 8 小时） */
    tzset();
    esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG("ntp.aliyun.com");
    esp_netif_sntp_init(&cfg);
}

typedef struct rnode {
    char *domain;
    int suffix;
    int glob;            /* 含 * 通配，按 glob 匹配 */
    struct rnode *next;
} rnode_t;
static rnode_t *s_rules = NULL;

/* ---- 仓库白名单：这些域名/子域永远不拦（内嵌与在线规则都套用）---- */
/* config/whitelist.txt 原文 16 条（连同子域一起保护） */
static const char *const WHITELIST[] = {
    "qznovelvod.com", "douyincdn.com", "douyinliving.com", "fqnovelpic.com",
    "douyinpic.com", "bytefcdn.com", "volcgslb.com", "bytegecko.com",
    "ixigua.com", "amemv.com", "is.snssdk.com", "gecko.snssdk.com",
    "api3-normal-sinfonlinea.fqnovel.com", "apple.com", "icloud.com",
    "tz.sec.xiaomi.com",
};

/* for-agents.md §3.1 点名禁拦，但不在 whitelist.txt 里：只放行该域名本身，不整片保护 */
static const char *const NEVER_BLOCK_EXACT[] = {
    "fqnovelvod.com",                     /* 正片 CDN 主域（子域 v*-reading-ad 仍要拦） */
    "api5-normal-sinfonlinea.fqnovel.com",/* 反作弊，同 api3 */
    "volcengineapi.com",
    "utoken.umeng.com",                   /* 友盟推送鉴权 */
};

static bool glob_match(const char *s, const char *p)
{
    const char *st = NULL, *pt = NULL;
    while (*s) {
        if (*p == '*') { pt = p++; st = s; }
        else if (*p == *s) { p++; s++; }
        else if (pt) { p = pt + 1; s = ++st; }
        else return false;
    }
    while (*p == '*') p++;
    return *p == 0;
}

static bool is_whitelisted(const char *q)
{
    size_t ql = strlen(q);
    for (size_t i = 0; i < sizeof(WHITELIST)/sizeof(WHITELIST[0]); i++) {
        const char *w = WHITELIST[i];
        size_t dl = strlen(w);
        if (ql == dl && strcmp(q, w) == 0) return true;
        if (ql > dl && q[ql-dl-1] == '.' && strcmp(q + ql - dl, w) == 0) return true;
    }
    for (size_t i = 0; i < sizeof(NEVER_BLOCK_EXACT)/sizeof(NEVER_BLOCK_EXACT[0]); i++)
        if (strcmp(q, NEVER_BLOCK_EXACT[i]) == 0) return true;
    return false;
}

static bool match_domain(const char *q)
{
    for (rnode_t *r = s_rules; r; r = r->next) {
        if (r->glob) { if (glob_match(q, r->domain)) return true; }
        else if (r->suffix) {
            size_t ql = strlen(q), dl = strlen(r->domain);
            if (ql > dl && q[ql-dl-1]=='.' && strcmp(q+ql-dl, r->domain)==0) return true;
            if (strcmp(q, r->domain)==0) return true;
        } else if (strcmp(q, r->domain)==0) return true;
    }
    return false;
}

static void load_embedded(void)
{
    while (s_rules) { rnode_t *n=s_rules->next; heap_caps_free(s_rules->domain); heap_caps_free(s_rules); s_rules=n; }
    s_user_count = 0;
    for (size_t i=0;i<EMBEDDED_RULES_N;i++) {
        rnode_t *n = r_alloc(sizeof(rnode_t));
        char *d = r_alloc(strlen(EMBEDDED_RULES[i].domain) + 1);
        strcpy(d, EMBEDDED_RULES[i].domain);
        n->domain = d;
        n->suffix = EMBEDDED_RULES[i].suffix;
        n->glob = (strchr(d, '*') != NULL);
        n->next = s_rules; s_rules = n; s_user_count++;
    }
    /* 按项目规范只用 config 目录下原文，不额外造通配模式 */
}

/* 从拉到的原文里抽取 address=/domain/ 规则（不做哈希，保留原文域） */
static void parse_and_load(const char *text)
{
    if (!text) return;
    const char *p = text;
    while ((p = strstr(p, "address=/")) != NULL) {
        p += 9;
        const char *e = strchr(p, '/');
        if (!e || e==p) continue;
        size_t n = e-p;
        if (n >= 128) continue;
        char buf[128]; memcpy(buf,p,n); buf[n]=0;
        if (is_whitelisted(buf)) continue;   /* 白名单域名不入表 */
        int suffix = (strchr(buf,'.') && strstr(buf,".com")==buf+strlen(buf)-4 && strchr(buf,'.')==buf);
        rnode_t *r = r_alloc(sizeof(rnode_t));
        char *d = r_alloc(n + 1);
        memcpy(d, buf, n); d[n] = 0;
        r->domain = d; r->suffix = suffix; r->glob = (strchr(d, '*') != NULL);
        r->next = s_rules; s_rules=r; s_user_count++;
    }
}

static const esp_partition_t *rules_part(void);
/* ---- 自定义名单：白名单（走网关放行）+ 黑名单（强制拦截），独立 whitelist 分区 ---- */
#define WL_MAGIC      "DNSWL2"
#define WL_MAGIC_OLD  "DNSWL1"
#define BL_MAGIC      "DNSBL1"
#define WL_MAX        64
#define BL_MAX        64
#define BL_OFF        0x2000        /* 黑名单段在分区内 8KB 偏移（白段自身要占 8+64*64=4.1KB，故让到第二扇区组） */
static char *s_wl[WL_MAX];
static int   s_wl_n = 0;
static char *s_bl[BL_MAX];
static int   s_bl_n = 0;

/* 域名归一化：去首尾空白/尾部点、去协议前缀与路径、转小写，避免脏条目匹配不上 */
static void norm_domain(char *d)
{
    if (!d || !*d) return;
    char *p = d;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != d) memmove(d, p, strlen(p) + 1);
    if (strncasecmp(d, "https://", 8) == 0) memmove(d, d + 8, strlen(d + 8) + 1);
    else if (strncasecmp(d, "http://", 7) == 0) memmove(d, d + 7, strlen(d + 7) + 1);
    char *slash = strchr(d, '/');
    if (slash) *slash = '\0';
    for (char *q = d; *q; q++) *q = (char)tolower((unsigned char)*q);
    size_t l = strlen(d);
    while (l > 0 && (d[l-1] == '.' || isspace((unsigned char)d[l-1]))) d[--l] = '\0';
}

/* 名单条目优先放 PSRAM，PSRAM 不足再退回内部 RAM */
static char *list_alloc(void){
    char *c = heap_caps_malloc(64, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!c) c = heap_caps_malloc(64, MALLOC_CAP_8BIT);
    return c;
}

/* 优先独立 whitelist 分区；分区表没刷过时回退规则分区尾部（仅白名单可落盘） */
static const esp_partition_t *list_part(void)
{
    return esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "whitelist");
}

static void list_free_all(char *slots[], int *n)
{
    for (int i = 0; i < *n; i++) heap_caps_free(slots[i]);
    *n = 0;
}

static void wl_read(void)
{
    const esp_partition_t *p = list_part();
    if (!p) return;
    uint8_t hdr[8];
    if (esp_partition_read(p, 0, hdr, sizeof(hdr)) != ESP_OK) return;
    if (memcmp(hdr, WL_MAGIC, 6) != 0 && memcmp(hdr, WL_MAGIC_OLD, 6) != 0) return;
    uint16_t n; memcpy(&n, hdr + 6, 2);
    if (n > WL_MAX) return;
    static char buf[WL_MAX * 64];
    if (esp_partition_read(p, 8, buf, (size_t)n * 64) != ESP_OK) return;
    list_free_all(s_wl, &s_wl_n);
    for (int i = 0; i < n; i++) {
        if (buf[i * 64]) {
            s_wl[s_wl_n] = list_alloc();
            if (!s_wl[s_wl_n]) break;
            memcpy(s_wl[s_wl_n], buf + i * 64, 64);
            s_wl_n++;
        }
    }
}

static void bl_read(void)
{
    const esp_partition_t *p = list_part();
    if (!p) return;
    uint8_t hdr[8];
    if (esp_partition_read(p, BL_OFF, hdr, sizeof(hdr)) != ESP_OK) return;
    if (memcmp(hdr, BL_MAGIC, 6) != 0) return;
    uint16_t n; memcpy(&n, hdr + 6, 2);
    if (n > BL_MAX) return;
    static char buf[BL_MAX * 64];
    if (esp_partition_read(p, BL_OFF + 8, buf, (size_t)n * 64) != ESP_OK) return;
    list_free_all(s_bl, &s_bl_n);
    for (int i = 0; i < n; i++) {
        if (buf[i * 64]) {
            s_bl[s_bl_n] = list_alloc();
            if (!s_bl[s_bl_n]) break;
            memcpy(s_bl[s_bl_n], buf + i * 64, 64);
            s_bl_n++;
        }
    }
}

static void list_write(const esp_partition_t *p, size_t off, const char *magic,
                       char *slots[], int n)
{
    if (!p) return;   /* 无独立分区时不落盘，仅内存生效 */
    uint8_t hdr[8] = {0};
    memcpy(hdr, magic, 6);
    uint16_t nn = (uint16_t)n;
    memcpy(hdr + 6, &nn, 2);
    static char buf[WL_MAX * 64];
    memset(buf, 0, sizeof(buf));
    for (int i = 0; i < n; i++) memcpy(buf + i * 64, slots[i], 64);
    esp_partition_erase_range(p, off, 8192);   /* 一段 8KB：8 字节头 + 64 条 × 64 字节 = 4104 字节，擦 4KB 会写进未擦除区 */
    esp_partition_write(p, off, hdr, sizeof(hdr));
    esp_partition_write(p, off + 8, buf, (size_t)n * 64);
}

static void wl_write(void) { list_write(list_part(), 0, WL_MAGIC, s_wl, s_wl_n); }
static void bl_write(void) { list_write(list_part(), BL_OFF, BL_MAGIC, s_bl, s_bl_n); }

static bool list_match(const char *q, char *slots[], int n)
{
    for (int i = 0; i < n; i++) {
        const char *d = slots[i];
        size_t ql = strlen(q), dl = strlen(d);
        if (ql == dl && strcmp(q, d) == 0) return true;
        if (ql > dl && q[ql - dl - 1] == '.' && strcmp(q + ql - dl, d) == 0) return true;
    }
    return false;
}

static bool wl_match(const char *q) { return list_match(q, s_wl, s_wl_n); }
static bool bl_match(const char *q) { return list_match(q, s_bl, s_bl_n); }

static int list_out(char *slots[], int n, char *out, size_t cap)
{
    out[0] = '\0';
    int k = 0;
    for (int i = 0; i < n; i++) {
        k += snprintf(out + k, cap - (size_t)k, "%s\"%s\"", i ? "," : "", slots[i]);
    }
    return k;
}

static esp_err_t list_add(char *slots[], int *n, int max, const char *d, void (*save)(void))
{
    char norm[64] = {0};
    if (d) { snprintf(norm, sizeof(norm), "%s", d); norm_domain(norm); }
    if (!norm[0] || strlen(norm) >= 63) return ESP_ERR_INVALID_ARG;
    for (int i = 0; i < *n; i++)
        if (strcmp(slots[i], norm) == 0) return ESP_OK;
    if (*n >= max) return ESP_ERR_NO_MEM;
    char *c = list_alloc();
    if (!c) return ESP_ERR_NO_MEM;
    memset(c, 0, 64);
    strncpy(c, norm, 63);
    slots[(*n)++] = c;
    save();
    cache_flush();   /* 名单变更后清旧缓存，避免旧正应答/负应答拖住新规则 */
    return ESP_OK;
}

static esp_err_t list_del(char *slots[], int *n, const char *d, void (*save)(void))
{
    char norm[64] = {0};
    if (d) { snprintf(norm, sizeof(norm), "%s", d); norm_domain(norm); }
    if (!norm[0]) return ESP_ERR_INVALID_ARG;
    for (int i = 0; i < *n; i++) {
        if (strcmp(slots[i], norm) == 0) {
            heap_caps_free(slots[i]);
            for (int j = i; j < *n - 1; j++) slots[j] = slots[j + 1];
            (*n)--;
            save();
            cache_flush();
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

int dns_adblock_wl_list(char *out, size_t cap) { return list_out(s_wl, s_wl_n, out, cap); }
int dns_adblock_bl_list(char *out, size_t cap) { return list_out(s_bl, s_bl_n, out, cap); }

esp_err_t dns_adblock_wl_add(const char *d) { return list_add(s_wl, &s_wl_n, WL_MAX, d, wl_write); }
esp_err_t dns_adblock_wl_del(const char *d) { return list_del(s_wl, &s_wl_n, d, wl_write); }
esp_err_t dns_adblock_bl_add(const char *d) { return list_add(s_bl, &s_bl_n, BL_MAX, d, bl_write); }
esp_err_t dns_adblock_bl_del(const char *d) { return list_del(s_bl, &s_bl_n, d, bl_write); }

/* ---- 规则分区（rules, 0x100000 = 1MB）---- */
#define RULES_LABEL "rules"
#define RULES_MAGIC "DNSRULES1"

static const esp_partition_t *rules_part(void)
{
    return esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, RULES_LABEL);
}

/* 把三份原文合并后写入分区；成功返回写入字节数 */
static esp_err_t rules_save(const char *fq, const char *extra, const char *up)
{
    const esp_partition_t *p = rules_part();
    if (!p) return ESP_ERR_NOT_FOUND;

    size_t l1 = fq ? strlen(fq) : 0, l2 = extra ? strlen(extra) : 0, l3 = up ? strlen(up) : 0;
    size_t total = 12 + l1 + l2 + l3;
    if (total > p->size) return ESP_ERR_INVALID_SIZE;

    uint8_t *blob = r_alloc(total + 8);
    if (!blob) return ESP_ERR_NO_MEM;
    memcpy(blob, RULES_MAGIC, 9);
    memcpy(blob + 9, &total, 4);
    size_t o = 13;
    if (l1) { memcpy(blob + o, fq, l1); o += l1; }
    if (l2) { memcpy(blob + o, extra, l2); o += l2; }
    if (l3) { memcpy(blob + o, up, l3); o += l3; }

    esp_err_t e = esp_partition_erase_range(p, 0, p->size);
    if (e == ESP_OK) e = esp_partition_write(p, 0, blob, o);
    heap_caps_free(blob);
    ESP_LOGI(TAG, "规则已写入分区 %u 字节 (e=%s)", (unsigned)o, esp_err_to_name(e));
    return e;
}

/* 开机从分区读规则到 PSRAM 并解析；无有效数据返回 false */
static bool rules_load(void)
{
    const esp_partition_t *p = rules_part();
    if (!p) return false;

    uint8_t hdr[16] = {0};
    if (esp_partition_read(p, 0, hdr, sizeof(hdr)) != ESP_OK) return false;
    if (memcmp(hdr, RULES_MAGIC, 9) != 0) return false;
    uint32_t total = 0;
    memcpy(&total, hdr + 9, 4);
    if (total < 16 || total > p->size) return false;

    char *text = r_alloc(total + 1);
    if (!text) return false;
    if (esp_partition_read(p, 13, text, total) != ESP_OK) { heap_caps_free(text); return false; }
    text[total] = 0;

    while (s_rules) { rnode_t *n=s_rules->next; heap_caps_free(s_rules->domain); heap_caps_free(s_rules); s_rules=n; }
    s_user_count = 0;
    parse_and_load(text);
    ESP_LOGI(TAG, "开机从分区载入规则 %d 条（%u 字节）", s_user_count, (unsigned)total);
    heap_caps_free(text);
    return s_user_count > 0;
}


/* ---- DNS 报文工具 ---- */
/* 从 question 段提取小写域名，返回 qtype 位置；失败返回 -1 */
static int extract_qname(const uint8_t *pkt, int len, char *out, int outlen)
{
    int off = 12;
    int o = 0;
    while (off+1 < len) {
        uint8_t l = pkt[off];
        if (l==0) { off++; break; }
        if (o) out[o++]='.';
        off++;
        for (uint8_t i=0;i<l && off<len;i++) out[o++]=tolower(pkt[off++]);
    }
    out[o]=0;
    if (off+4 > len) return -1;
    return off;
}

/* 拦截应答：A/ANY 回 NOERROR + 1 条 A=0.0.0.0（TTL 10s），其它类型回 NOERROR 空应答(NODATA)。
   NXDOMAIN 在部分客户端会被当成"DNS 答不上来"从而换服务器/切 HTTPDNS，实测拦不住；
   回 0.0.0.0 是明确解析到不可用地址，客户端不会再换服务器重试。 */
static int build_blocked(uint8_t *out, const uint8_t *in, int question_end, uint16_t qtype)
{
    memcpy(out, in, question_end);     /* 回显 Header + Question，不带 EDNS OPT */
    out[2]=0x81; out[3]=0x80;          /* QR=1, RD=1, RA=1, RCODE=NOERROR */
    out[4]= in[4]; out[5]= in[5];      /* QDCOUNT 保留请求值 */
    out[8]=0; out[9]=0;                 /* NSCOUNT=0 */
    out[10]=0; out[11]=0;               /* ARCOUNT=0 */
    if (qtype == 1 || qtype == 255) {   /* A / ANY：给一条 0.0.0.0 */
        out[6]=0; out[7]=1;
        int o = question_end;
        out[o++]=0xC0; out[o++]=0x0C;   /* NAME 指针指向 question */
        out[o++]=0x00; out[o++]=0x01;   /* TYPE A */
        out[o++]=0x00; out[o++]=0x01;   /* CLASS IN */
        uint32_t ttl = htonl(10);
        memcpy(out + o, &ttl, 4); o += 4;
        out[o++]=0x00; out[o++]=0x04;   /* RDLENGTH=4 */
        out[o++]=0x00; out[o++]=0x00; out[o++]=0x00; out[o++]=0x00;  /* 0.0.0.0 */
        return o;
    }
    out[6]=0; out[7]=0;                 /* 其它类型：NODATA，无记录 */
    return question_end;
}

/* 无记录应答：NOERROR/NODATA 只回 Header+Question（不带 EDNS OPT） */
static int build_rcode(uint8_t *out, const uint8_t *in, int question_end, int rcode)
{
    memcpy(out, in, question_end);
    out[2] = 0x81;                  /* QR=1, RD=1 */
    out[3] = (uint8_t)(0x80 | (rcode & 0x0F));   /* RA=1 + RCODE */
    out[4] = in[4]; out[5] = in[5]; /* QDCOUNT 保留请求值 */
    out[6] = 0; out[7] = 0;         /* ANCOUNT=0 */
    out[8] = 0; out[9] = 0;         /* NSCOUNT=0 */
    out[10] = 0; out[11] = 0;       /* ARCOUNT=0 */
    return question_end;
}

/* captive portal 劫持应答：把域名 A 记录指到 AP 地址，返回应答长度 */
static int build_redirect_a(uint8_t *out, const uint8_t *in, int qlen, int qend, uint32_t ip)
{
    memcpy(out, in, qlen);
    out[2]=0x81; out[3]=0x80;          /* 标准应答，NOERROR */
    out[6]=0; out[7]=1;                /* ANCOUNT=1 */
    int o = qend;
    out[o++]=0xC0; out[o++]=0x0C;      /* 指针指向 question name */
    out[o++]=0x00; out[o++]=0x01;      /* TYPE A */
    out[o++]=0x00; out[o++]=0x01;      /* CLASS IN */
    uint32_t ttl = htonl(64);
    memcpy(out+o, &ttl, 4); o+=4;
    out[o++]=0x00; out[o++]=0x04;      /* RDLENGTH=4 */
    memcpy(out+o, &ip, 4); o+=4;        /* RDATA，ip 为网络序 */
    return o;
}

/* 向指定网关 IP 以普通 UDP 53 转发一条请求（仅自定义白名单域名走网关），返回应答长度 */
static int upstream_send(int fs, const uint8_t *req, int reqlen, uint32_t ip,
                         uint8_t *rpl, int rplcap)
{
    struct sockaddr_in up = {0};
    up.sin_family = AF_INET;
    up.sin_port = htons(53);
    up.sin_addr.s_addr = ip;
    sendto(fs, req, reqlen, 0, (struct sockaddr*)&up, sizeof(up));
    struct timeval tv = {1, 500000};   /* 单次 1.5 秒超时 */
    setsockopt(fs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return recv(fs, rpl, rplcap, 0);
}

/* ---- DoT（DNS-over-TLS, RFC 853）上游通道：TCP 853 + mbedTLS ---- */

/* 关闭并释放当前复用的 DoT 连接 */
static void dot_close(void)
{
    if (dot_tls) {
        esp_tls_conn_destroy(dot_tls);
        dot_tls = NULL;
    }
    dot_ip = 0;
}

/* 连到指定上游 IP:853 建立 TLS 会话；成功返回句柄，失败返回 NULL */
static esp_tls_t *dot_open(uint32_t ip)
{
    char sip[16]; ip4_str(ip, sip, sizeof(sip));
    esp_tls_cfg_t cfg = {0};
    cfg.crt_bundle_attach   = esp_crt_bundle_attach;  /* 用系统 CA 包校验上游证书 */
    cfg.common_name        = UPSTREAM_HOST;           /* SNI 与证书 CN/SAN 校验名 */
    cfg.timeout_ms         = DOT_TIMEOUT_MS;
    cfg.skip_common_name   = false;

    esp_tls_t *tls = esp_tls_init();
    if (!tls) { ESP_LOGW(TAG, "DoT %s: tls 初始化失败", sip); return NULL; }

    int r = esp_tls_conn_new_sync(sip, (int)strlen(sip), DOT_PORT, &cfg, tls);
    if (r != 1) {
        ESP_LOGW(TAG, "DoT %s:%d 连接失败 (r=%d)", sip, DOT_PORT, r);
        esp_tls_conn_destroy(tls);
        return NULL;
    }
    ESP_LOGI(TAG, "DoT 已连接 %s:%d", sip, DOT_PORT);
    return tls;
}

/* 在指定 TLS 连接上发一条 DNS 查询并读回应答；返回应答长度，<=0 表示出错 */
static int dot_query(esp_tls_t *tls, const uint8_t *req, int reqlen,
                     uint8_t *rpl, int rplcap)
{
    if (!tls || reqlen <= 0 || reqlen > 512) return -1;

    /* RFC 853 帧：2 字节大端长度前缀 + DNS 消息 */
    uint8_t frame[514];
    frame[0] = (uint8_t)((reqlen >> 8) & 0xFF);
    frame[1] = (uint8_t)(reqlen & 0xFF);
    memcpy(frame + 2, req, reqlen);
    int framelen = reqlen + 2;

    int w = 0;
    while (w < framelen) {
        int n = esp_tls_conn_write(tls, frame + w, framelen - w);
        if (n <= 0) return -1;
        w += n;
    }

    /* 读 2 字节长度前缀 */
    uint8_t lenbuf[2];
    int r = 0;
    while (r < 2) {
        int n = esp_tls_conn_read(tls, lenbuf + r, 2 - r);
        if (n <= 0) return -1;
        r += n;
    }
    int msglen = ((int)lenbuf[0] << 8) | lenbuf[1];
    if (msglen <= 0 || msglen > rplcap) return -1;

    int got = 0;
    while (got < msglen) {
        int n = esp_tls_conn_read(tls, rpl + got, msglen - got);
        if (n <= 0) return -1;
        got += n;
    }
    return got;
}

/* 复用常驻 DoT 连接转发一条查询；连接所连 IP 与目标不符时重建。失败则关闭连接。 */
static int dot_forward(uint32_t ip, const uint8_t *req, int reqlen,
                       uint8_t *rpl, int rplcap)
{
    if (!dot_tls || dot_ip != ip) {
        dot_close();
        dot_tls = dot_open(ip);
        if (!dot_tls) return -1;
        dot_ip = ip;
    }
    int m = dot_query(dot_tls, req, reqlen, rpl, rplcap);
    if (m <= 0) dot_close();   /* 链路异常，下条查询重新握手 */
    return m;
}

/* 构造一条对内网稳定域名的 A 记录测试查询，用于探测上游 IP 是否可用 */
static void build_probe_query(uint8_t *buf, int *len)
{
    buf[0] = 0x12; buf[1] = 0x34;
    buf[2] = 0x01; buf[3] = 0x00;      /* RD=1，标准递归查询 */
    buf[4] = 0; buf[5] = 1;             /* QDCOUNT=1 */
    buf[6] = 0; buf[7] = 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
    int o = 12;
    const char *d = "www.baidu.com";
    const char *p = d;
    while (*p) {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        buf[o++] = (uint8_t)l;
        memcpy(buf + o, p, l); o += l;
        p += l + (dot ? 1 : 0);
    }
    buf[o++] = 0;                      /* name 结束 */
    buf[o++] = 0; buf[o++] = 1;         /* QTYPE=A */
    buf[o++] = 0; buf[o++] = 1;        /* QCLASS=IN */
    *len = o;
}

/* 探测某个上游 IP：DoT 握手成功且应答不是 SERVFAIL/REFUSED 即视为可用；
   成功返回耗时 ms(>0)，失败返回 -1 */
static int probe_upstream(uint32_t ip)
{
    uint8_t q[64], rpl[512];
    int qlen;
    build_probe_query(q, &qlen);
    int64_t t0 = esp_timer_get_time();
    esp_tls_t *tls = dot_open(ip);
    if (!tls) return -1;
    int m = dot_query(tls, q, qlen, rpl, sizeof(rpl));
    int dt = (int)((esp_timer_get_time() - t0) / 1000);
    char sip[16]; ip4_str(ip, sip, sizeof(sip));
    esp_tls_conn_destroy(tls);
    if (m < 12) {
        ESP_LOGW(TAG, "探测上游 %s DoT 无应答 (m=%d, %dms)", sip, m, dt);
        return -1;
    }
    int rcode = rpl[3] & 0x0F;
    int ok = (rcode != 2 && rcode != 5);
    if (ok) ESP_LOGI(TAG, "探测上游 %s 可用 (rcode=%d, %dms, %d 字节)", sip, rcode, dt, m);
    else ESP_LOGW(TAG, "探测上游 %s 不可用 rcode=%d (%dms)", sip, rcode, dt);
    return ok ? dt : -1;
}

/* 上游解析/探测独立任务：表空时 5 秒重试，表建立后每 30 分钟重探一次。
   8 个节点逐个 DoT 探测可能耗时十几秒，放在这里执行，绝不占用转发任务。 */
static void dns_res_task(void *arg)
{
    int64_t last_ms = 0;
    while (s_running) {
        int n;
        portENTER_CRITICAL(&s_up_mux);
        n = up_n;
        portEXIT_CRITICAL(&s_up_mux);
        int64_t interval = (n == 0) ? 5 * 1000 : 30 * 60 * 1000;
        int64_t now_ms = esp_timer_get_time() / 1000;
        if (last_ms == 0 || now_ms - last_ms >= interval) {
            wifi_status_t wst;
            wifi_prov_get_status(&wst);
            if (!wst.provisioning && wst.sta_connected) {
                last_ms = now_ms;
                up_resolve();
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

/* 收包与转发拆成两个任务：收包任务只做能秒回的事（配网劫持、拦截、缓存），
   需要上游的查询丢进队列交给转发任务。这样慢上游（DoT 握手慢/超时）不会把拦截和
   缓存应答堵在队列后面——否则客户端先超时、把板子判成坏 DNS，转而用自带 HTTPDNS。 */
#define FWD_QN 12
typedef struct {
    struct sockaddr_in cli;
    uint16_t qtype;
    int      len;
    int      qend;      /* question 段结束偏移，回 SERVFAIL 时构造报文用 */
    char     q[160];
    uint8_t  req[512];
} dns_req_t;
static QueueHandle_t s_fwd_q = NULL;
static int s_sock = -1;      /* 53 监听 socket，转发任务回包时复用 */

static void dns_rx_task(void *arg)
{
    s_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family=AF_INET; a.sin_port=htons(53); a.sin_addr.s_addr=INADDR_ANY;
    if (s_sock >= 0) {
        bind(s_sock, (struct sockaddr*)&a, sizeof(a));
        struct timeval sv = {1, 0};   /* 1 秒超时唤醒 */
        setsockopt(s_sock, SOL_SOCKET, SO_RCVTIMEO, &sv, sizeof(sv));
    }
    else ESP_LOGE(TAG, "53 监听 socket 创建失败 fd=%d", s_sock);

    uint8_t buf[512], rpl[512];
    while (s_running) {
        struct sockaddr_in cli; socklen_t cl=sizeof(cli);
        int n = recvfrom(s_sock, buf, sizeof(buf), 0, (struct sockaddr*)&cli, &cl);
        if (n < 12) continue;
        int64_t now_ms = esp_timer_get_time() / 1000;

        char q[160];
        int qend = extract_qname(buf, n, q, sizeof(q));
        if (qend < 0) continue;

        uint16_t qtype;
        memcpy(&qtype, buf + qend, 2);
        qtype = ntohs(qtype);
        client_touch(&cli, now_ms);
        char cip[16]; ip_str(&cli, cip, sizeof(cip));

        blk_total_save();

        wifi_status_t wst;
        wifi_prov_get_status(&wst);

        /* 配网阶段：captive portal 劫持，所有域名都应答到 AP 地址，不转发上游 */
        if (wst.provisioning) {
            uint32_t apip = inet_addr(AP_IP_STR);
            int rlen = build_redirect_a(rpl, buf, n, qend, apip);
            sendto(s_sock, rpl, rlen, 0, (struct sockaddr*)&cli, cl);
            continue;
        }

        bool hit_bl = bl_match(q);
        if (s_on && !is_whitelisted(q) && (hit_bl || match_domain(q))) {
            int qend_off = qend + 4;   /* question 段结束（含 qtype/qclass），之后的 EDNS OPT 不带回 */
            int plen = build_blocked(rpl, buf, qend_off, qtype);
            int sent = sendto(s_sock, rpl, plen, 0, (struct sockaddr*)&cli, cl);
            s_block_count++;
            s_run_blocked++;
            block_log_add(cip, q);
            blk_total_save();   /* 拦截后尽快落盘，避免掉电丢失累计数 */
            ESP_LOGI(TAG, "拦[%s] %s -> %s:%d 回 %d 字节(%s) 累计 %d",
                     hit_bl ? "黑名单" : "规则", q, cip, ntohs(cli.sin_port),
                     sent, (qtype==1||qtype==255) ? "0.0.0.0" : "NODATA", s_block_count);
            continue;
        }

        /* 命中缓存：直接回包（ID 用当前请求的，避免客户端对不上） */
        int clen = cache_get_copy(q, qtype, now_ms, rpl, (int)sizeof(rpl));
        if (clen > 0) {
            rpl[0] = buf[0]; rpl[1] = buf[1];
            sendto(s_sock, rpl, clen, 0, (struct sockaddr*)&cli, cl);
            s_cache_hits++;
            ESP_LOGD(TAG, "缓存命中 %s", q);
            continue;
        }

        /* 需要上游：交给转发任务，收包循环立刻回去接下一包 */
        if (s_fwd_q) {
            dns_req_t r;
            memset(&r, 0, sizeof(r));
            r.cli = cli;
            r.qtype = qtype;
            r.len = n;
            r.qend = qend + 4;
            snprintf(r.q, sizeof(r.q), "%s", q);
            memcpy(r.req, buf, n);
            /* 队列满时挤掉最旧的一条（丢旧不丢新）：客户端刚发的查询才是要紧的，
               静默丢弃会让它等满超时、把板子判成坏 DNS */
            if (xQueueSend(s_fwd_q, &r, 0) != pdTRUE) {
                dns_req_t old;
                if (xQueueReceive(s_fwd_q, &old, 0) == pdTRUE)
                    ESP_LOGW(TAG, "转发队列满，挤掉最旧 %s", old.q);
                if (xQueueSend(s_fwd_q, &r, 0) != pdTRUE)
                    ESP_LOGW(TAG, "转发入队失败 %s", q);
            }
        }
    }
}

static void dns_fwd_task(void *arg)
{
    int fs = socket(AF_INET, SOCK_DGRAM, 0);
    if (fs < 0) ESP_LOGE(TAG, "上游转发 socket 创建失败 fd=%d", fs);

    uint8_t rpl[512];
    dns_req_t r;
    while (s_running) {
        bool have = (s_fwd_q && xQueueReceive(s_fwd_q, &r, pdMS_TO_TICKS(500)) == pdTRUE);

        wifi_status_t wst;
        wifi_prov_get_status(&wst);
        /* 上游 IP 表的解析/探测全部交给 dns_res 任务，这里只管转发，永不等探测 */
        if (!have) continue;

        /* 命中自定义白名单的走网关 DNS；其余只走 dns.18bit.cn 上游，不回退网关 */
        bool gw_mode = wl_match(r.q);
        uint32_t gw = inet_addr(wst.sta_gw);
        if (gw == INADDR_NONE) gw = 0;

        int m = -1;
        if (gw_mode) {
            if (gw) {
                int64_t t0 = esp_timer_get_time();
                m = upstream_send(fs, r.req, r.len, gw, rpl, sizeof(rpl));
                int dt = (int)((esp_timer_get_time() - t0) / 1000);
                char sip[16]; ip4_str(gw, sip, sizeof(sip));
                if (m > 0) ESP_LOGI(TAG, "转发 %s 经网关 %s 应答 %dms", r.q, sip, dt);
                else ESP_LOGW(TAG, "转发 %s 经网关 %s 无应答 (m=%d, %dms)", r.q, sip, m, dt);
            }
        } else {
            uint32_t ip;
            portENTER_CRITICAL(&s_up_mux);
            ip = up_n ? up_ips[up_idx] : 0;
            portEXIT_CRITICAL(&s_up_mux);
            if (ip) {
                int64_t t0 = esp_timer_get_time();
                m = dot_forward(ip, r.req, r.len, rpl, sizeof(rpl));
                int dt = (int)((esp_timer_get_time() - t0) / 1000);
                char sip[16]; ip4_str(ip, sip, sizeof(sip));
                if (m > 0) ESP_LOGI(TAG, "转发 %s 经 DoT %s 应答 %dms", r.q, sip, dt);
                else {
                    ESP_LOGW(TAG, "上游无应答 %s (m=%d) DoT %s %dms，本条换地址", r.q, m, sip, dt);
                    portENTER_CRITICAL(&s_up_mux);            /* 下条查询换节点，不再原地重试 */
                    if (up_n) up_idx = (up_idx + 1) % up_n;
                    portEXIT_CRITICAL(&s_up_mux);
                }
            }
        }

        if (m > 0) {
            if (s_sock >= 0) sendto(s_sock, rpl, m, 0, (struct sockaddr*)&r.cli, sizeof(r.cli));
            cache_put(r.q, r.qtype, rpl, m, esp_timer_get_time() / 1000);
        } else {
            /* 上游答不上：回 SERVFAIL，让客户端重试/换路，而不是静默丢包等它超时 */
            ESP_LOGW(TAG, "转发失败 %s：上游无可用应答 (m=%d)，回 SERVFAIL", r.q, m);
            fail_log_add(r.q);
            uint8_t sf[512];
            int slen = build_rcode(sf, r.req, r.qend, 2);
            if (s_sock >= 0) sendto(s_sock, sf, slen, 0, (struct sockaddr*)&r.cli, sizeof(r.cli));
        }
    }
}

esp_err_t dns_adblock_set_on(bool on)
{
    s_on = on;
    cache_flush();   /* 开关变化后清缓存，避免旧的拦截/放行结果残留 */
    nvs_handle_t h; esp_err_t e=nvs_open(NVS_NS,NVS_READWRITE,&h);
    if(e==ESP_OK){ nvs_set_u8(h,KEY_DNS_ON,on?1:0); nvs_commit(h); nvs_close(h);}
    return e;
}

bool dns_adblock_is_on(void){ return s_on; }
int dns_adblock_rule_count(void){ return s_user_count; }

static void blk_total_load(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        uint32_t v = 0;
        if (nvs_get_u32(h, KEY_BLK_TOTAL, &v) == ESP_OK) s_block_count = (int)v;
        nvs_close(h);
    }
    ESP_LOGI(TAG, "累计拦截数(上电载入)=%d", s_block_count);
}

static void blk_total_save(void)
{
    static int saved = -1;
    if (s_block_count == saved) return;
    static int64_t last = 0;
    int64_t now = esp_timer_get_time() / 1000;
    if (now - last < 5000) return;      /* 5 秒最多写一次，兼顾掉电不丢与 flash 寿命 */
    last = now;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u32(h, KEY_BLK_TOTAL, (uint32_t)s_block_count);
        nvs_commit(h); nvs_close(h);
        saved = s_block_count;
    }
}

/* 清空累计拦截数：内存计数与 NVS 持久化值一起清零 */
/* 清除数据：累计拦截数 + 客户端列表 + 拦截域名流水 + 上游无应答流水（名单/规则不动） */
esp_err_t dns_adblock_clear_blocked(void)
{
    s_block_count = 0;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u32(h, KEY_BLK_TOTAL, 0);
        nvs_commit(h);
        nvs_close(h);
    }

    portENTER_CRITICAL(&s_blog_mux);          /* 拦截域名流水 */
    memset(s_blog, 0, sizeof(s_blog));
    s_blog_idx = 0;
    s_blog_cnt = 0;
    portEXIT_CRITICAL(&s_blog_mux);

    portENTER_CRITICAL(&s_fail_mux);          /* 上游无应答域名 */
    memset(s_fail, 0, sizeof(s_fail));
    s_fail_idx = 0;
    s_fail_cnt = 0;
    portEXIT_CRITICAL(&s_fail_mux);

    memset(s_cli, 0, sizeof(s_cli));          /* 客户端列表 */
    s_cli_n = 0;
    s_run_blocked = 0;                        /* 本次运行计数 */
    s_run_fails = 0;

    ESP_LOGI(TAG, "已清除数据：累计拦截数、客户端列表、拦截域名、上游无应答域名");
    return ESP_OK;
}

/* 只清已拦截总数（内存 + NVS），保留本次运行的域名流水 */
esp_err_t dns_adblock_clear_total(void)
{
    s_block_count = 0;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u32(h, KEY_BLK_TOTAL, 0);
        nvs_commit(h);
        nvs_close(h);
    }
    ESP_LOGI(TAG, "已清除累计拦截总数（本次运行流水保留）");
    return ESP_OK;
}

/* 只清本次运行的拦截域名列表（连同本次运行拦截次数） */
esp_err_t dns_adblock_clear_blocks(void)
{
    portENTER_CRITICAL(&s_blog_mux);
    memset(s_blog, 0, sizeof(s_blog));
    s_blog_idx = 0;
    s_blog_cnt = 0;
    portEXIT_CRITICAL(&s_blog_mux);
    s_run_blocked = 0;
    ESP_LOGI(TAG, "已清除本次运行的拦截域名列表");
    return ESP_OK;
}

/* 只清本次运行的上游无应答域名列表（连同本次运行次数） */
esp_err_t dns_adblock_clear_fails(void)
{
    portENTER_CRITICAL(&s_fail_mux);
    memset(s_fail, 0, sizeof(s_fail));
    s_fail_idx = 0;
    s_fail_cnt = 0;
    portEXIT_CRITICAL(&s_fail_mux);
    s_run_fails = 0;
    ESP_LOGI(TAG, "已清除本次运行的上游无应答域名列表");
    return ESP_OK;
}

static int cache_live_used(void)
{
    if (!s_cache) return 0;
    int64_t now = esp_timer_get_time() / 1000;
    int c = 0;
    if (s_cache_mux) xSemaphoreTake(s_cache_mux, portMAX_DELAY);
    for (int i = 0; i < CACHE_N; i++)
        if (s_cache[i].len && now < s_cache[i].exp_ms) c++;
    if (s_cache_mux) xSemaphoreGive(s_cache_mux);
    return c;
}

void dns_adblock_status(char *buf, size_t len)
{
    int n = snprintf(buf,len,"{\"on\":%s,\"rules\":%d,\"blocked\":%d,\"run_blocked\":%d,\"run_fails\":%d,\"last\":\"%s\",\"upstream\":\"%s\",\"up_ok\":%s,\"cache\":%d,\"cache_n\":%d,\"cache_hit\":%d,\"cache_store\":%d,\"cache_skip\":%d,\"cache_on\":%s,\"updating\":%s,\"msg\":\"%s\",\"clients\":[",
             s_on?"true":"false", s_user_count, s_block_count, s_run_blocked, s_run_fails,
             s_last_update, UPSTREAM_HOST,
             up_n>0?"true":"false",
             cache_live_used(), CACHE_N, s_cache_hits, s_cache_store, s_cache_skip,
             s_cache?"true":"false", s_updating?"true":"false", s_upd_msg);
    for (int i = 0; i < s_cli_n && n < (int)len - 64; i++) {
        n += snprintf(buf + n, len - n, "%s{\"ip\":\"%s\",\"n\":%u}",
                      i ? "," : "", s_cli[i].ip, (unsigned)s_cli[i].n);
    }
    n += snprintf(buf + n, len - n, "],\"blocks\":[");
    for (int i = 0; i < s_blog_cnt && n < (int)len - 100; i++) {
        int k = (s_blog_idx - 1 - i + BLOCK_LOG_N * 2) % BLOCK_LOG_N;
        n += snprintf(buf + n, len - n, "%s{\"ip\":\"%s\",\"domain\":\"%s\",\"n\":%u}",
                      i ? "," : "", s_blog[k].ip, s_blog[k].domain, (unsigned)s_blog[k].n);
    }
    n += snprintf(buf + n, len - n, "],\"wl\":[");
    for (int i = 0; i < s_wl_n && n < (int)len - 80; i++)
        n += snprintf(buf + n, len - n, "%s\"%s\"", i ? "," : "", s_wl[i]);
    n += snprintf(buf + n, len - n, "],\"bl\":[");
    for (int i = 0; i < s_bl_n && n < (int)len - 80; i++)
        n += snprintf(buf + n, len - n, "%s\"%s\"", i ? "," : "", s_bl[i]);
    n += snprintf(buf + n, len - n, "],\"fails\":[");
    for (int i = 0; i < s_fail_cnt && n < (int)len - 80; i++) {
        int idx = (s_fail_idx - 1 - i + FAIL_LOG_N * 2) % FAIL_LOG_N;
        n += snprintf(buf + n, len - n, "%s{\"d\":\"%s\",\"n\":%u}",
                      i ? "," : "", s_fail[idx].domain, (unsigned)s_fail[idx].n);
    }
    n += snprintf(buf + n, len - n, "]}");
    n = strlen(buf);
}

static char s_fetch_err[48] = "";

/* HTTPS 需要正确系统时间，否则证书校验必失败（板子无 RTC，等 SNTP 生效） */
static bool time_valid(void)
{
    time_t t = time(NULL);
    return t > 1700000000;   /* 2023-11 之后视为已对时 */
}

static esp_err_t fetch_text(const char *url, char *buf, size_t cap)
{
    esp_err_t e = ESP_FAIL;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (!time_valid()) {
            for (int i = 0; i < 12 && !time_valid(); i++) vTaskDelay(pdMS_TO_TICKS(500));
        }
        int status = 0;
        esp_http_client_config_t cfg = {
            .url = url, .timeout_ms = 20000, .buffer_size = 8192,
            .crt_bundle_attach = esp_crt_bundle_attach,
            .keep_alive_enable = false,
        };
        esp_http_client_handle_t c = esp_http_client_init(&cfg);
        if (!c) return ESP_FAIL;
        int total = 0;
        /* 必须 open/fetch_headers/read 手工读，perform 会把正文读掉丢掉 → 只能拿到 0 字节 */
        if (esp_http_client_open(c, 0) != ESP_OK) {
            e = ESP_ERR_HTTP_CONNECT;
        } else {
            int hdr = esp_http_client_fetch_headers(c);
            status = esp_http_client_get_status_code(c);
            if (hdr < 0 || status != 200) {
                e = ESP_FAIL;
            } else {
                e = ESP_OK;
                int len;
                while ((len = esp_http_client_read(c, buf+total, cap-total-1)) > 0) {
                    total += len; buf[total] = 0;
                    if (total >= (int)cap - 1) break;
                }
                if (total <= 0) e = ESP_FAIL;
            }
            esp_http_client_close(c);
        }
        ESP_LOGW(TAG, "GET %s #%d -> %s (http %d, %d 字节)", url, attempt+1, esp_err_to_name(e), status, total);
        snprintf(s_fetch_err, sizeof(s_fetch_err), "%s/http%d", esp_err_to_name(e), status);
        esp_http_client_cleanup(c);
        if (e == ESP_OK) return ESP_OK;
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    return e;
}

static esp_err_t fetch_any(const char *const *urls, int n, char *buf, size_t cap)
{
    for (int i = 0; i < n; i++) {
        memset(buf, 0, cap);
        if (fetch_text(urls[i], buf, cap) == ESP_OK) return ESP_OK;
    }
    return ESP_FAIL;
}

esp_err_t dns_adblock_update_now(void)
{
    /* 拉 fq + extra + 上游原文，全部解析合并；任一成功即用，全失败保留现有规则 */
    const size_t SZ_FQ = 8000, SZ_EX = 8000, SZ_UP = 72000;
    char *fq = r_alloc(SZ_FQ), *ex = r_alloc(SZ_EX), *up = r_alloc(SZ_UP);
    if (!fq || !ex || !up) {
        if (fq) heap_caps_free(fq);
        if (ex) heap_caps_free(ex);
        if (up) heap_caps_free(up);
        ESP_LOGW(TAG, "更新缓冲分配失败");
        return ESP_ERR_NO_MEM;
    }
    memset(fq, 0, SZ_FQ); memset(ex, 0, SZ_EX); memset(up, 0, SZ_UP);

    static const char *const fq_urls[] = {
        "https://cdn.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-fq.conf",
        "https://fastly.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-fq.conf",
        "https://gcore.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-fq.conf",
        "https://testingcf.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-fq.conf",
        "https://raw.githubusercontent.com/abclq/home-dns-adblock/main/config/adblock-fq.conf",
    };
    static const char *const ex_urls[] = {
        "https://cdn.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-extra.conf",
        "https://fastly.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-extra.conf",
        "https://gcore.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-extra.conf",
        "https://testingcf.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-extra.conf",
        "https://raw.githubusercontent.com/abclq/home-dns-adblock/main/config/adblock-extra.conf",
    };
    static const char *const up_urls[] = {
        "https://cdn.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-upstream.conf",
        "https://fastly.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-upstream.conf",
        "https://gcore.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-upstream.conf",
        "https://testingcf.jsdelivr.net/gh/abclq/home-dns-adblock@main/config/adblock-upstream.conf",
        "https://raw.githubusercontent.com/abclq/home-dns-adblock/main/config/adblock-upstream.conf",
    };
    int ok = 0, e1, e2, e3;
    e1 = fetch_any(fq_urls, 5, fq, SZ_FQ);       if (e1 == ESP_OK) ok++;
    e2 = fetch_any(ex_urls, 5, ex, SZ_EX);       if (e2 == ESP_OK) ok++;
    e3 = fetch_any(up_urls, 5, up, SZ_UP);       if (e3 == ESP_OK) ok++;
    snprintf(s_upd_msg, sizeof(s_upd_msg), "规则源 fq:%s extra:%s upstream:%s",
             e1==ESP_OK?"OK":"FAIL", e2==ESP_OK?"OK":"FAIL", e3==ESP_OK?"OK":"FAIL");

    if (ok == 0) {
        snprintf(s_upd_msg, sizeof(s_upd_msg), "拉取失败(%s)，保留原规则", s_fetch_err);
        ESP_LOGW(TAG, "更新全部失败，保留现有规则");
        heap_caps_free(fq); heap_caps_free(ex); heap_caps_free(up);
        return ESP_FAIL;
    }
    /* 清空后依次解析三份原文 */
    while (s_rules) { rnode_t *n=s_rules->next; heap_caps_free(s_rules->domain); heap_caps_free(s_rules); s_rules=n; }
    s_user_count = 0;
    parse_and_load(fq);
    parse_and_load(ex);
    parse_and_load(up);
    cache_flush();   /* 规则变了，缓存作废 */

    /* 落盘到 rules 分区，下次开机直接载入 */
    rules_save(fq, ex, up);

    /* 记录本次更新完成时刻（本地时间） */
    time_t now; struct tm tm;
    time(&now); localtime_r(&now, &tm);
    strftime(s_last_update, sizeof(s_last_update), "%m-%d %H:%M", &tm);
    upd_ts_save(now);   /* 7 天周期从这个时刻算起 */
    snprintf(s_upd_msg, sizeof(s_upd_msg), "%s 已更新 %d 条", (ok==3?"成功":"部分成功"), s_user_count);
    ESP_LOGI(TAG, "update_now ok=%d rules=%d msg=%s", ok, s_user_count, s_upd_msg);

    heap_caps_free(fq); heap_caps_free(ex); heap_caps_free(up);
    return ESP_OK;
}

/* 后台任务里拉规则：HTTP/TLS 需要大栈，不能跑在 httpd 任务上 */

static void upd_task(void *arg)
{
    dns_adblock_update_now();
    s_updating = false;
    vTaskDelete(NULL);
}

esp_err_t dns_adblock_update_async(void)
{
    if (s_updating) return ESP_ERR_INVALID_STATE;
    s_updating = true;
    if (xTaskCreatePinnedToCore(upd_task, "dns_upd", 20480, NULL, 4, NULL, 0) != pdPASS) {
        s_updating = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

bool dns_adblock_updating(void) { return s_updating; }


void dns_adblock_start(void)
{
    s_lock = xSemaphoreCreateMutex();
    load_embedded();          /* 先放内嵌基线兜底 */
    rules_load();             /* 分区里有更新过的规则就覆盖基线 */
    wl_read();               /* 载入自定义白名单 */
    bl_read();               /* 载入自定义黑名单 */
    {   /* 开机回显上次更新时刻 */
        time_t last = upd_ts_load();
        if (last > 0) {
            struct tm tm; localtime_r(&last, &tm);
            strftime(s_last_update, sizeof(s_last_update), "%m-%d %H:%M", &tm);
        }
    }

    s_on = true;  /* 默认开启过滤：NVS 无记录时按开处理 */
    nvs_handle_t h;
    if (nvs_open(NVS_NS,NVS_READONLY,&h)==ESP_OK){
        uint8_t v=0;
        if (nvs_get_u8(h,KEY_DNS_ON,&v)==ESP_OK) s_on = v?true:false;
        nvs_close(h);
    }
    s_running = true;
    blk_total_load();
    /* 每次上电/重启都清空运行期记录：缓存、拦截域名流水、上游无应答流水一律不跨重启，
       只保留 NVS 里的累计拦截总数（s_block_count）与名单/规则。 */
    memset(s_blog, 0, sizeof(s_blog));
    s_blog_idx = 0;
    s_blog_cnt = 0;
    memset(s_fail, 0, sizeof(s_fail));
    s_fail_idx = 0;
    s_fail_cnt = 0;
    s_cache_hits = 0;
    s_cache_store = 0;
    s_cache_skip = 0;
    s_run_blocked = 0;
    s_run_fails = 0;
    ESP_LOGI(TAG, "运行期记录已清零（缓存/拦截域名/上游无应答），累计拦截数保持 %d", s_block_count);
    cache_init();
    /* 收包/转发分两个任务：收包秒回拦截与缓存，转发任务独占慢上游（DoT）。
       核 1 跑 DNS，核 0 留给 WiFi/ESP-NOW/网页/拉取 */
    s_fwd_q = xQueueCreate(FWD_QN, sizeof(dns_req_t));
    if (!s_fwd_q) ESP_LOGW(TAG, "转发队列创建失败，上游转发将不可用");
    xTaskCreatePinnedToCore(dns_rx_task,  "dns_rx",  5120, NULL, 7, NULL, 1);
    xTaskCreatePinnedToCore(dns_fwd_task, "dns_fwd", 8192, NULL, 5, NULL, 1);
    xTaskCreatePinnedToCore(dns_res_task, "dns_res", 8192, NULL, 4, NULL, 1);
    sntp_start();
    esp_timer_handle_t t;
    esp_timer_create(&(esp_timer_create_args_t){.callback=sched_cb,.arg=NULL,.name="dns_sched"},&t);
    esp_timer_start_periodic(t, 3600*1000000ULL);
    ESP_LOGI(TAG,"DNS 服务启动（53端口），拦截 %d 条，开关=%s",s_user_count,s_on?"开":"关");
}
