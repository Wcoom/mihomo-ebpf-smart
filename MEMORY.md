# 核心记忆（导出 2026-08-17 20:00）

# 奶昔机场 anytls + mihomo 兼容性问题（2026-08-16 已定位根因）

## 结论
奶昔机场（anytls 协议，服务器/域名/密码/SNI 见本地完整版记忆）对新版 mihomo（1.19.21）拒绝连接：TLS 握手成功后服务器回 `[Alert from server] internal error`。根因：新 mihomo 的 anytls 客户端默认 client-metadata 为空，settings 帧 client 字段为空串，机场服务器校验该字段为空即拒绝。Clash Meta for Android 内置内核默认发非空值所以能连。

## 修复
anytls 节点加 `client-metadata: clash.meta`（已验证 clash.meta / sing-box / 1.1.12 任意非空值均可）。修复文件存 /sdcard/Download/naiXi_anytls_fix.md。

## 实验方法备忘（这台设备）
- 设备是特殊环境：/data/user/0 只能看到 gms 和 fuck.andes 两个目录，其他应用的 data 必须经 /proc/<pid>/root 访问（进程命名空间挂载遮蔽）。
- 测试 mihomo 用 busybox setuidgid 3005 + setsid 后台跑 /data/local/tmp/fuck_andes/mihomo-alpha（v1.19.21）或 mihomo-v121，显式代理模式（curl -x http://127.0.0.1:port），不要用 iptables REDIRECT 全局劫持（会断整机网络，用户明确反对）。
- 抓包 tcpdump -i any -w，Linux 环境（/workspace）已装 tshark 可解析；pcap 解析脚本 /data/local/tmp/fuck_andes/pcap_parse.py。
- 端口必须 < 65536（之前 67890/69090 超范围踩坑）。
- CMA 内核为 APK 内 libclash.so（gomobile，不可直接运行）；CMA 内核进程名 meta:background，配置在 /proc/<pid>/root/data/data/com.github.metacubex.clash.meta/files/imported/<uuid>/config.yaml。

# 设备 mihomo smart 移植状态（2026-08-17）
- /data/adb/box/bin/mihomo 已替换为移植版内核（TanakaLun/mihomo + vernesong LightGBM smart 功能，commit ba6977b，静态 arm64），原内核备份在 /data/adb/box/bin/mihomo.bak.20260817_002028
- 移植源码/补丁/二进制在 /data/local/tmp/fuck_andes/（tanaka-mihomo smart-lgbm 分支、smart_port.patch、mihomo-smart）
- box 配置目录 /data/adb/box/mihomo 已有 Model.bin；重启服务后生效

# 设备 mihomo ebpf 模式部署完成（2026-08-17 01:30）
## 最终方案（已生效）
- bin/mihomo = ebpf+smart 版（Alpha-4333，md5 ce82f843），备份 mihomo.bak.smart.20260817_011713
- settings.ini network_mode="ebpf"；config.yaml 末尾加 listeners 段（type: ebpf, mode: local, dns-mode: hijack, local.ipv6-mode: off）
- **必须加 exclude-uid-range: ["0:2999"]**（排除系统 UID）——否则系统流量被劫持 → Android Wi-Fi 验证失败 → 默认网络掉蜂窝 → mihomo 出站走 rmnet 蜂窝 → DoH 不通 → DNS 全挂
- 验证：app uid 流量劫持（connections API 显示 type=EBPF）→ google 200；root/系统流量直连；Wi-Fi validated 保持

## 关键坑（重要）
- **exclude-uid-range 分隔符是冒号 "0:2999"，不是连字符**！连字符导致 parseUIDRanges 报 missing ':'，listener 静默不启动（特征：/proc/PID/fd 无 bpf fd、无 EBPF 监听端口、connections 空）——mihomo -t 验证不报错（listener 构建在运行时）
- 用户原 nameserver 三个 DoH 中 私人DoH1(IP已抹除) 与 私人DoH2(IP已抹除) 已死，仅 私人DoH3(IP已抹除) 存活；已改为 私人DoH + 223.5.5.5 + 119.29.29.29
- box/setuidgid 环境 mihomo.log 只写"配置完成"之前的日志，后续 listener 日志不落盘（功能正常，原因未查）
- 系统 DNS(net.dns1=8.8.8.8) 直连不可用；root shell 里 curl 域名解析会失败（用 --resolve 或走 mihomo）

# 设备 mihomo DNS 全挂根因与 CA 池修复（2026-08-17 02:30 已修复）
## 根因（重要，代码级确认）
- 静态编译（GOOS=linux）mihomo 在 Android 上 **系统 CA 池为空**：Go root_linux.go 只在 GOOS=android 编译时才读 /system/etc/security/cacerts（goos.IsAndroid 编译期常量）；Android 无 /etc/ssl/certs；本仓库 component/ca/ca-certificates.crt 是 0 字节 → 空池 → 所有 DoH/DoT 证书验证失败（x509 unknown authority）
- 表现：代理正常（不依赖本地解析）、直连全挂（SERVFAIL）；curl 测试"全部可用"是 AOSP curl 内置 CA，与 mihomo 无关
- 之前 DNS 正常是 UDP 223.5.5.5 兜底，DoH 一直在悄悄失败

## 修复
- **重新编译 GOOS=android**（读系统 CA 池 149 个 CA）：`GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -tags with_ebpf -trimpath -ldflags "-w -s"`
- **必须带 -tags with_ebpf**（sing_ebpf build tag：with_ebpf && (linux||android)；不带则 bpf fd=0 无劫持）
- 当前二进制：/data/adb/box/bin/mihomo（android+with_ebpf，44.7MB，md5 667ab3a0）；linux 版备份 mihomo.bak.linux.20260817_0221（md5 ce82f843）
- DoT IP 证书：`tls://223.5.5.5#name-cert-verify=dns.alidns.com`（mihomo nameserver fragment 参数：#key=value，单值为 proxy 名；还有 skip-cert-verify=true）

## 当前 DNS（全通道验证通过）
- nameserver：UDP 223.5.5.5/119.29.29.29 + DoH dns.pub/dns.alidns.com/私人DoH组(域名已抹除) + DoT tls://223.5.5.5#name-cert-verify=dns.alidns.com
- 验证：DoH-only 8580 NOERROR、DoT-only 8580 NOERROR、baidu 直连 200、google 代理 200、bpf=17
- DoH 服务器 02:1x 后已恢复可达（之前记录的死亡列表已过时）

# 设备 mihomo ebpf bypass 评估（2026-08-17 03:35）
- **bypass_rule_set 移植 bug 已修复**：sing_ebpf 的 startBypassRuleSets 原来从未被调用（bypassRuleSetStarted 恒 false，3 秒 ticker 空转，bypass 永不刷入内核）；已在 inbound.go attach 块补调用，重编 android+with_ebpf（md5 d5cebf4a，已部署，无 bypass_rule_set 时行为与旧版一致）
- **bypass 机制确认**：bypass_rule_set 只支持 ipcidr/classical 规则集（domain 无 ToIpCidr）；text 格式 ipcidr 每行必须**纯 CIDR**（带 IP-CIDR, 前缀全部解析失败，实测 13156 条 invalid Ipcidr）；内核 LPM map 上限 65536 条；DNSRespectBypass=false（53 劫持优先）；生效后发布 EBFPBypassIPSet 给 DNS 中间件
- **规则集已生成**（/data/adb/box/mihomo/rules/）：cn_bypass_v4.list=8727 条、cn_bypass_v6.list=4428 条（cn_v4/cn_v6 ∪ ChinaMax_IP 去重）；验证刷入内核 ipv4=8372 ipv6=4047（合并重叠段后）
- **本机限制（已回滚）**：ColorOS netd ebpf 防火墙（fw_OUTPUT reject_wlan_uid/mtk_uid/qcom_uid）对**后台 app uid 直连 REJECT**（实测 10358/10381/10387/10399 直连全超时，uid 0/2000 正常）；app 上网实际依赖劫持路径（回环→mihomo uid0 出站）；bypass 会让后台 app 国内直连被系统拒 → **已回滚 config**（保留规则集文件与新二进制可随时启用）
- 完整记录：/data/local/tmp/fuck_andes/ebpf_bypass_评估记录.md

# 设备 netd 防火墙清理与后台冻结解除（2026-08-17 04:00 完成）
## 根因（重要，与直觉相反）
- app（如 Via uid10381）直连公网超时，**不是 iptables/bpf map 拒绝，而是 ColorOS 的 deviceidle 后台冻结**：`dumpsys deviceidle whitelist +包名` 后立即恢复（200@50ms）。
- netd 的 REJECT/DROP 规则（fw_OUTPUT/fw_INPUT/oplus_fw_OUTPUT/fw_OUTPUT_oplus_dns，ipv4+ipv6，含 20 条 DNS AAAA 管控）也清了，但那是辅助；netd 会周期性重建这些规则。
- 劫持路径能通的原因：出站变 uid 0（root），不受冻结限制；回环目标不在管控范围。

## 修复
- 批量 `dumpsys deviceidle whitelist +pkg` 全部 479 个包（当前生效）。
- iptables 层清空 REJECT/DROP（备份在 /data/local/tmp/fuck_andes/iptables.before_clean.*.txt）。
- 关键坑：**杀 netd 进程会导致系统死机重启（已踩），绝对不碰 netd**；只删规则。
- BPF_OBJ_GET 在本机内核返回 EINVAL，无法用 python bpf syscall 读 map，别浪费时间。

## oplus bpf map 内核保护（2026-08-17 05:00 实测，重要）
- Oplus 内核 bpf_map_info 有 40B vendor 头：name 在 offset 64，key_size/value_size 偏移不准。
- BPF_MAP_CREATE 成功（root 有 bpf 权限），但 BPF_OBJ_PIN/GET 路径操作返回 EINVAL/ENOENT；GET_FD_BY_ID 只暴露 123 个普通 map（id 2~142），oplus-netd 私有 map（drop_wlan/drop_cell/freeze_config/hans/mtk/qcom 等）全部不可见；setenforce 0 无效（非 selinux）。
- AOSP netd 的 skfilter map（skfilter_drop_c/drop_w/accept/reject/denyli/allowl/manual/automa/forwar，id 19/20/58-61/83-91/96-109）可见但实测全部为空。
- 结论：oplus 私有 map 由冻结状态动态驱动，无法直接清空（内核保护），正确解除方式 = 状态解除（deviceidle 加白/前台运行）。静态工具：/data/local/tmp/fuck_andes/bpfmap_ctl.c / bpf_skfilter.c / bpf_scan.c / bpf_listall.c（编译产物同目录，android 静态可跑）。

## 脚本（/data/adb/service.d/ 长期引用）
- `/data/adb/service.d/netd_cleanup.sh`（755）：开机等 bootanim→清 REJECT/DROP→全量 deviceidle 加白→60s 循环清重建规则+600s 循环加白新装应用。`box_service.sh` 负责启动 mihomo（保留）。
- `/data/adb/box/scripts/gen_bypass_rules.sh`（755）：从 ChinaMax_IP.yaml 等生成 cn_bypass_v4/v6.list（缺失时自动生成，sanity≥500 行），幂等。
- 旧 `/data/adb/service.d/谷歌防火墙清除.sh` 已禁用（.disabled 后缀），功能被 netd_cleanup.sh 覆盖。

## 验证（最终状态）
- app 直连 200@52ms；baidu 域名 63ms（bypass 直连生效）；google 382ms（代理）；所有 filter 链 REJECT/DROP=0；mihomo PID 8535 运行中带 bypass 配置（config.yaml bypass_rule_set=[cn_bypass_v4,cn_bypass_v6]）。

# 设备三层 doze 协同架构（2026-08-17 17:00 完成）
## 架构
- 决策层：ColorOS ELSA/HANS（/data/oplus/os/bpm/sys_elsa_config_list.xml）+ OFreezer_Tombstone_Optimizer 模块（bind mount 优化版配置，state=enabled，600s 守护重挂）
- 网络层：mihomo（tanaka-mihomo 编译版 d5cebf4a=box/bin/mihomo，smart LightGBM + ebpf bypass）接管网络维度：UID REJECT（代理流量）+ iptables FREEZE_OUTPUT owner DROP（bypass/直连兜底）
- 状态源：dumpsys activity processes 的 isFrozen=true（freezer），awk 用 index("ProcessRecord{")+"UID " 解析（busybox awk 正则 \{ \/ 均不可用）

## 关键脚本
- /data/adb/box/mihomo/scripts/freeze_sync.sh v4：60s 循环，双层冻结同步（白名单 rules/freeze_whitelist.list 可加 uid/包名豁免）
- /data/adb/service.d/netd_cleanup.sh：60s 清 netd REJECT + mihomo_guard（setsid 重启+adj=-1000）+ freeze_guard；600s deviceidle 加白
- config.yaml：rule-providers「冻结名单」+ rules 顶部 RULE-SET,冻结名单,REJECT（provider PUT /providers/rules/冻结名单 热加载）

## 重要坑（务必遵守）
- box.service 启动的 mihomo 活不过 60-90s 被静默 SIGKILL（非 LMK 非 OOM 非 tombstone），必须 setsid /data/adb/box/bin/mihomo -d /data/adb/box/mihomo 启动；oom_score_adj 会周期性被系统改回 0，需循环维护 -1000
- mihomo 的 UID 规则对 bypass 流量无效（bypass 内核层放行不进规则引擎），冻结必须 iptables owner DROP 兜底
- 杀 netd 进程 = 死机重启，永远只删规则
- via uid=10395（mark.via.gp），box app uid=10387

## tanaka-mihomo 仓库
- 已转移到 /storage/emulated/0/tanaka-mihomo（原 /workspace 位置已删）；ebpf-smart 分支，HEAD 56253904（inbound.go bypass 提前启动已提交）；Go 1.26.3 linux/arm64 工具链可用；编译产物 mihomo_android_arm64
- 编译流程：从 /storage/emulated/0/tanaka-mihomo 拷回 /workspace 后 make ebpf-smart；注意 FUSE 上 mv/cp 会 setfilecon 失败，root 大文件操作用 /data/media/0 真实路径
- smart 组件周期任务 5-30 分钟级，doze 降频收益低，勿再动

# 热点分流修复 + 多实例 flock 抢锁教训（2026-08-17 20:00）
## 根因（热点不分流）
- ColorOS 热点是"WLAN 共享"桥接模式：AP 接口 = **wlan2**（iw dev 显示 type AP, ssid 用户热点名），热点 client 与上游同网段（10.169.163.0/24），**没有独立热点网段/接口**
- 旧配置 `shared.interface: [wlan0]`（station 上游）+ `include-source-cidr: [192.168.1.0/24]` → TC 挂在错误接口、client 网段不匹配 → 热点流量完全不进拦截
- 修复：`interface: [wlan2]` + `include-source-cidr: [10.169.163.0/24]`（config.yaml 与 config.yaml.txt 模板同步改）
- 验证：热点 client 10.169.163.33 的 Microsoft 流量 type=EBPF、走香港 IEPL 专线 ✓

## "mihomo 拉不起来/attach 失败"假象的真相（重要教训）
- config 里 `log-level: silent`（18:00 box 重生成时写入）吞掉了全部 EBPF/错误日志 → 误判 attach 没发生
- 实际是 **多实例 flock 抢锁**：netd_cleanup 的 mihomo_guard（60s 循环）+ box + 手动启动互相抢 `/sys/fs/cgroup` 的 flock（LOCK_NB），后到者报 "another eBPF inbound is already active on this cgroup: lock cgroup: EBUSY"
- 表现：进程活着、API 正常、但 ebpf inbound 未启用（bpf fd=0），流量仅靠系统代理 7890 → 本机"看起来正常"、热点裸奔
- 解决：杀干净所有实例+停 guard → 单实例启动 → attach 2 秒内成功
- 排障工具：config 加 `log-level: debug` 才能看到 "[EBPF] inbound attached" 和 EBUSY 错误；busybox tc 不支持 clsact/filter 语法，TC 状态查不了，别依赖

## 当前稳定状态（20:00）
- mihomo 14153：cgroup + TC(wlan2) + 6 程序 attach 成功，log-level 已改回 info
- box.pid 手动同步当前 pid，guard 靠 pidof 非空判定不抢拉
- 冻结双层拦截（freeze_sync 12 条 REJECT + FREEZE_OUTPUT owner DROP）正常；box.service restart 会 flush FREEZE_OUTPUT 链，freeze_sync 下轮（60s）自动重建
- config.yaml.bak 已存修复版

# 上游重组同步 + 新基线部署（2026-08-28 完成）

## 上游重组（TanakaLun/mihomo force-push）
- `Alpha` 分支已被重写为纯 metacubex 线（不再含 ebpf 代码）；ebpf 特性独立到
  **`ebpf-inbound`** 分支（= 新 Alpha f295ba6d + 4347 ebpf 提交，HEAD 396e3fce：
  "port shared socket-assignment data plane, kernel TCP splice, and map janitors"）
- 旧基线 4335ce29 已不在上游任何分支历史中；**同步必须 cherry-pick 本地定制到
  新 ebpf-inbound 基线，绝不能 merge 旧线**

## 本地 4 个定制全部迁移（仅 go.mod 1 处冲突：testify v1.12.1 保留 + leaves 新增）
- a3903f1d smart LightGBM 移植（vernesong 方案）
- afaec5ed ebpf bypass_rule_set 提前启动修复
- 0c90aa90 Model.bin 原子下载加固 + uid.go 匹配语义修复/日志降噪
- 旧线完整备份：backup/ebpf-smart-pre-sync-20260828（含未提交改动已 commit e2e334c0）

## 新基线构建与部署
- 构建：GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -tags with_ebpf，产物
  44,892,513 字节 md5 3a54adbe（比旧版 44.7MB 略大）；WSL Go 1.25.0 可用
- 部署：/data/adb/box/bin/mihomo 已替换（setuid root:net_admin 保持），旧版备份
  mihomo.bak.sync20260828（md5 55e54588）
- **Text file busy 坑**：运行中二进制 cp 替换会报 Text file busy，正确顺序=先 kill
  进程再 cp；若 guard 已拉起新进程，用 `rm -f` + `cp` 绕过（运行进程映像不受影响）
- 注意 guard（netd_cleanup.sh）目前不在 service.d 中（用户 8-22/8-26 调整过部署：
  只剩 box_service.sh + .zn_cleanup.sh），mihomo 需手动 setsid 启动，oom_score_adj=0
  无循环维护（用户当前方案如此，勿擅自改）

## 真机验证（2026-08-28）
- pid 稳定；[Smart] Model file loaded successfully；bpf-map fd 50 个（attach 成功）
- google 代理 204@0.25s；baidu 走代理 200@0.075s；直连 TCP 通
- 热点 client 10.75.111.33 Microsoft 443 流量 connections type=EBPF（劫持生效）
- **启动期 [Metadata] not valid UDP 告警 ~85 条**：shared socket-assignment 数据面
  启动瞬间 flow/assignment 缓存未建，UDP 包 DstIP 空被 Drop（tunnel.go handleUDPConn
  !Valid→Drop）。30s 观察零增长，客户端重传自愈，**功能无影响，非 bug 需修**

# vernesong smart 上游修复同步 + 新部署（2026-08-29 完成）

## 上游状态核查（gh-proxy + API 权威确认）
- metacubex/Alpha = 061966e7（08-27，与本地官方线基线一致，**无新提交**）
- TanakaLun/ebpf-inbound = 396e3fce（08-24，与记忆一致，**无新提交**）
- vernesong/mihomo Alpha = b7508136（08-28，merge metacubex 061966e7 + 自有提交）

## 本地 smart 移植基点定位
- 本地 smart 移植（91b70b21）内容 ≈ vernesong **a0da2d97**（08-16 "adjust Host status check"）
  （diff 行数最小化定位；剩余差异为 gofmt 格式）
- 基点之后 vernesong 有两个 nodes filter 修复本地未包含：
  - 5664b1ba（08-18）filterProxies wtFailNodes 语义重构 + fallback UDP 过滤 + slices.Clone
  - 84ff1af2（08-26）GetHostStatus 引入 hostFailLimit 动态 blocked 判定、applyHostFailLimit 改名
- 已 port 到 official-20260828：commit **82418d06**（smart.go + stats.go），
  `git diff -w vernesong/Alpha` 仅剩 import 顺序格式差，逻辑完全一致；V4-Flash 审核通过
- 审核提示（非阻塞，上游自身设计）：UpdateHostStatus 持久化 hs.Blocked 统计含过期节点、
  GetHostStatus 动态 blocked 只统计未过期（nodeEntry > now），口径不一致但不影响运行时决策

## 新构建与部署（md5 24bcd7ec）
- 构建：GOOS=android GOARCH=arm64 CGO_ENABLED=0 -tags with_ebpf，44,892,513 字节
  md5 **24bcd7ec**（WSL Go 1.25.0 + goproxy.cn）
- 部署：/data/adb/box/bin/mihomo 已替换（chown root:net_admin + chmod 6755，注意
  **chown 会清 setuid 位，chmod 6755 要在 chown 之后**）；旧版备份
  **mihomo.bak.vernesong20260829**（md5 240c86f0）
- 启动：setsid + append 重定向 >> /data/adb/box/run/mihomo.log（保持 box 日志惯例可观测）；
  box.pid 手动同步
- 验证（pid 28199 稳定）：[Smart] Model 加载 ✓；bpf fd 45（attach ✓）；google 204@0.28s、
  baidu 200@0.16s；connections type=EBPF ✓；**Metadata not valid UDP 告警 0 条**
  （08-28 基线有 ~85 条，本次构建无此现象）

## 网络方案（重要，WSL 访问 GitHub 的可行路径）
- WSL/Windows 直连 GitHub 超时；gh-proxy.com 被解析为 198.18.0.111（fake-ip 污染，
  流量不通）。手机 mihomo 出口全通：gh-proxy/github raw/api 全部 200@0.3-0.7s
- **可行链路**：WSL → 手机 mihomo HTTP 代理（wlan0 192.168.1.177:7890，监听 *:7890）
  → gh-proxy.com → GitHub。git 用法：
  `git -c http.proxy=http://192.168.1.177:7890 ls-remote https://gh-proxy.com/https://github.com/<repo>.git`
- 包装器：**tools/git-gh-proxy.sh**（insteadOf gh-proxy 前缀 + 手机代理，PHONE_PROXY 环境变量可覆盖）
- 注意：手机 wlan0 IP 是 DHCP 动态的，IP 变了要更新 PHONE_PROXY

# 热点/USB 共享代理修复（2026-08-29 已修，重要）

## 现象
电脑连手机热点（wlan2 桥接）或 USB 网络共享（rndis0）时，google 等代理流量超时、
国内直连也断；connections API 无客户端 IP 记录。

## 根因（两个，均已代码级确认）
1. **USB 共享不劫持**：sing_ebpf sharedTCManager.reconcile() 只对 config
   `shared.interface` 固定列表挂 TC（无动态发现），列表只有 [wlan2] → rndis0 流量
   完全不进 mihomo。
2. **bypass 放行流量断（热点+USB 共性）**：`bypass_rule_set: [cn_bypass_v4, cn_bypass_v6]`
   在内核层放行 CN 流量直连，但 ColorOS netd 防火墙 REJECT 非 uid0 的放行流量
   （与 08-17 bypass 评估的"后台 app 直连被拒"同根因，对 tethering 客户端同样生效）
   → baidu 等 CN 直连全断、无任何 mihomo 日志（流量根本没进）。

## 修复（config.yaml，已真机验证）
- `shared.interface: [wlan2, rndis0]`（热点 AP + USB 共享接口都挂 TC）
- `bypass_rule_set: []`（CN 流量统一进 mihomo 由规则直连，uid 0 出站不受 netd 限制）
- **`shared.advanced.data-plane: rewrite`（必配）**：socket_assign 数据面（默认）下
  客户端（热点/USB 共享）CN 直连出站异常（google 等代理通、baidu 等直连断、
  mihomo 日志 match 直连但无响应）；切 rewrite 后客户端直连立即恢复
  （baidu 200@0.15s），手机本机直连不受影响（本机不走 shared 数据面）
- 验证：热点 google 204@0.28s/baidu 200@0.24s；USB 共享 google 204/baidu 200；
  DNS hijack 解析正常；connections 客户端 IP 全部 type=EBPF
- 诊断技巧：`--resolve` 绕过 DNS 区分 DNS/数据通路；清 bypass 单变量实验定位根因
- 备份：手机 config.yaml.bak.rndis（修复前）；部署模板 deploy/box/mihomo/
  config.yaml 与 config.yaml.txt 已同步修复版
- ⚠️ Windows adb 内联 sed 传 `[`/转义会因参数重组失效，改 config 必须用
  拉取-本地改-推回方式（曾因此修复被静默回退）

# 通用公共包打包（2026-08-29 完成）

## 产出
- **box_ebpf_smart_1.2.9.3b9fa58_20260829.zip**（52MB，421 文件，md5 a0725e9d）
  位于外层仓库根目录（*.zip 被 gitignore 不入库）
- 结构 = 参考包 box_public_1.2.9.3b9fa58_20260823.zip（box 框架 1.2.9/3b9fa58）：
  META-INF + customize.sh（官方安装器，安装时备份保留已有 box 数据）+ module.prop
  （改 id=box_for_root_ebpf_smart）+ box/（settings.ini、cfg、bin/{boxbpf,mihomo,yq}、
  scripts/box.*、sing-box、mihomo/{config.yaml 抹除版, Model.bin, ASN, GeoSite, Web,
  etc, proxy_provider/{README+proxy3 空模板}, scripts/update_bypass.sh, rules 全量}）

## 冻结定制去除（通用化）
- 删除 config.yaml「冻结名单」rule-provider（freeze_uid.list 引用）与
  `#- RULE-SET,冻结名单,REJECT` 行；rules 目录无 freeze 文件；crontab 仅保留
  update_bypass.sh（每 6h）；service.d 仅 box_service.sh（手机端此前已清理大部分）
- shared.interface: [wlan2] 设备专属 → 注释引导（本机劫持不受影响，热点分流按需填写）

## 隐私抹除（全部改为占位符+注释引导，config.yaml 44839 字节）
- proxy1/proxy2 订阅 URL → "https://请替换为您的真实订阅链接N"
- nameserver 私人 DoH（域名+UUID已抹除）→ 公共 DoH
  （223.5.5.5/119.29.29.29 dns-query）+ 私有 DoH 注释格式示例
- nameserver-policy 大陆私有 DoH（域名+token已抹除）→ 公共 DoH + 注释示例
- fake-ip-filter / rules 中私人域名（列表已抹除）→ 占位注释（your-domain.example 示例，不留真实域名）
- proxy_provider 节点缓存（proxy1/2.yaml 660KB 真实节点）与 config.yaml.bak.pre-rewrite
  **不打包**；全包 grep 扫描确认零残留（命中的仅为公共规则集/geosite 数据与
  box 默认 ghfast.top 镜像）
- 打包版 config 已真机 `mihomo -t` 验证通过

## IP 库
- update_bypass.sh（chnroutes2 v4 + APNIC delegated v6）当日 08:32 crontab 已自动
  更新，打包时 rules/cn_bypass_v4.list(60859B)/v6(30769B) 为最新，未重复更新
