#include "wifi_prov.h"
#include "espnow_master.h"
#include "admin_web.h"
#include "dns_adblock.h"
#include "count_store.h"
#include "esp_ota_ops.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* 计数归档任务固定跑在核 1，与核 0 的网页服务错开 */
static void archive_task(void *arg)
{
    (void)arg;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(60000));   /* 每分钟检查一次跨天归档 */
        count_store_archive_tick();
    }
}

void app_main(void)
{
    wifi_prov_start();
    espnow_master_init();
    count_store_init();
    dns_adblock_start();
    admin_web_start();

    /* OTA 后第一次启动的固件必须尽快"转正"，否则下次重启会被 bootloader 回滚到旧槽 */
    esp_err_t e = esp_ota_mark_app_valid_cancel_rollback();
    ESP_LOGI("main", "OTA 标记有效：%s", esp_err_to_name(e));

    xTaskCreatePinnedToCore(archive_task, "count_arch", 4096, NULL, 4, NULL, 1);
}
