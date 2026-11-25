#pragma once
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

void dns_adblock_start(void);
bool dns_adblock_is_on(void);
int  dns_adblock_rule_count(void);
esp_err_t dns_adblock_set_on(bool on);
esp_err_t dns_adblock_update_now(void);   /* 拉取最新规则（最佳努力，同步） */
esp_err_t dns_adblock_update_async(void); /* 后台任务拉取，立即返回 */
bool dns_adblock_updating(void);
void dns_adblock_status(char *buf, size_t len);
int  dns_adblock_wl_list(char *out, size_t cap);
esp_err_t dns_adblock_wl_add(const char *d);
esp_err_t dns_adblock_wl_del(const char *d);
int  dns_adblock_bl_list(char *out, size_t cap);
esp_err_t dns_adblock_bl_add(const char *d);
esp_err_t dns_adblock_bl_del(const char *d);
esp_err_t dns_adblock_clear_blocked(void);   /* 清空累计拦截数（内存+NVS） */
esp_err_t dns_adblock_clear_total(void);     /* 只清累计拦截总数（内存+NVS） */
esp_err_t dns_adblock_clear_blocks(void);    /* 只清本次运行拦截域名列表 */
esp_err_t dns_adblock_clear_fails(void);     /* 只清本次运行上游无应答域名列表 */

#ifdef __cplusplus
}
#endif
