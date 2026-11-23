idf_component_register(
    SRCS "main.c" "wifi_prov.c" "espnow_master.c" "admin_web.c" "dns_adblock.c" "count_store.c"
    EMBED_FILES "assets/prov.html" "assets/done.html" "assets/admin.html" "assets/button.html"
    PRIV_REQUIRES esp_wifi nvs_flash esp_netif esp_http_server esp_timer esp_http_client esp-tls mbedtls app_update
    INCLUDE_DIRS "."
)
