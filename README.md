# ESP32-Now-dns

ESP32-S3 上的一个小型「ESP-NOW 主机 + DNS 去广告网关」固件：一边收 ESP-NOW 从机上报的数据并做按键计数统计，一边给局域网提供带广告拦截的 DNS 服务，还自带手机配网和网页后台。

## 功能

- **ESP-NOW 主机**：接收从机上报的数据帧，最多 20 个对端、单帧 ≤250 字节；记录 MAC、RSSI、最后在线时间、今日收包次数，支持手动注册/删除对端、清空缓存、主动下发一帧。
- **按键计数**：2 个按钮（`btn_t1` / `btn_t2`，按绑定 MAC 归到对应从机），按天统计、跨天自动归档，保留 7 天明细 + 2 周 + 6 个月；归档任务跑在核 1，每分钟检查一次。
- **DNS 去广告**：设备在 **UDP 53** 上提供 DNS 服务，规则命中返回 `A=0.0.0.0`（TTL 10s，其它类型回空应答）；上游优先走 **DNS-over-TLS（`dns.18bit.cn:853`）**，白名单域名可改走网关普通 UDP 53；规则从 `abclq/home-dns-adblock` 的多条 jsDelivr 镜像拉取，超时自动换源；白名单/黑名单与累计拦截数持久化。
- **配网 + 后台**：未配网/配网失败时开热点 **`S3-ESPNOW`**（`192.168.4.1`），网页填 SSID/密码；支持保存多个上游网络、设默认、调发射功率（8.0–20.0 dBm，0.5 步进）。
- **OTA**：双 app 分区 + otadata，`POST /api/ota` 直接上传 bin 写入另一个槽；bootloader 开了回滚，固件启动后立即 `mark_app_valid` 转正。

## 编译

需要 ESP-IDF（工程开了 `MINIMAL_BUILD`，只编用到的组件）。`sdkconfig` 已带 `IDF_TARGET=esp32s3`：

```bash
idf.py set-target esp32s3   # 仅首次；sdkconfig 已带 target 时可跳过
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

Flash 参数默认 DIO / 80MHz / **4MB**。

## 分区表（`partitions.csv`，4MB）

| 分区 | 类型 | 地址 | 大小 |
|---|---|---|---|
| otadata | data/ota | 0x9000 | 8K |
| ota_0 | app | 0x10000 | 1.5M |
| ota_1 | app | 0x190000 | 1.5M |
| rules | data/spiffs | 0x310000 | 640K |
| whitelist | data/spiffs | 0x3B0000 | 128K |
| nvs | data/nvs | 0x3D0000 | 72K |

## 上手

1. 首次上电 → 手机连热点 **`S3-ESPNOW`** → 打开 `http://192.168.4.1` 填上游 WiFi 的 SSID/密码。
2. 连上后在同一网段访问设备 IP，进后台：
   - `/` 主后台：连接状态、ESP-NOW 对端列表、DNS 开关/规则更新/黑白名单、发射功率、OTA 上传
   - `/button.html` 按键计数页
3. **要用 DNS 去广告**：把电脑/路由器的 DNS 指向设备 IP（设备在 UDP 53 监听），不要改设备的 DNS 服务器用途。

## 主要接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 连接/配网/SSID/IP/对端数 |
| GET | `/api/sys` | 内存、CPU 等运行信息 |
| POST | `/api/power` | 发射功率（dBm） |
| POST | `/api/add_peer` | 手动注册 ESP-NOW 对端 MAC |
| GET/POST | `/api/dns` | DNS 状态 |
| POST | `/api/dns/toggle` | 开/关拦截 |
| POST | `/api/dns/update` | 拉取最新规则 |
| POST | `/api/dns/whitelist` | 白/黑名单增删 |
| POST | `/api/dns/clear` | 清零累计拦截数 |
| GET/POST | `/api/button` | 按键计数读写 |
| POST | `/api/button/send` | 给绑定的从机下发一帧 |
| POST | `/api/ota` | 上传固件 bin（写入空闲 app 槽） |
| GET/POST | `/submit`、`/saved/*`、`/advanced/*` | 配网与上游网络管理 |

## 目录

```
main/
  main.c            启动顺序：配网 → ESP-NOW → 计数 → DNS → 网页 → OTA 转正
  espnow_master.c   对端表、收包、在线状态、主动发送
  dns_adblock.c     53 监听、规则匹配、DoT 上游、黑白名单、规则拉取
  dns_rules.h       内置规则表
  count_store.c     按键计数（天/周/月分层 + NVS 落盘）
  wifi_prov.c       AP 配网 + STA 连接（多网络保存、功率管理）
  admin_web.c       80 端口网页与 JSON 接口
  assets/           配网页与后台页 HTML（button/done/prov/admin）
```
