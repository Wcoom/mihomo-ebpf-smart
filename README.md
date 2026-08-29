# mihomo ebpf-smart 移植版（TanakaLun/mihomo + LightGBM smart）

ColorOS 15 (Oplus13, Android 15) 上的 mihomo 透明代理全链路方案：
sing_ebpf cgroup/TC 内核级拦截 + LightGBM smart 节点自动选择 + 三层 doze 冻结协同。

---

## 一、产出文件清单（本 zip）

| 路径 | 说明 |
|---|---|
| `box_ebpf_smart_1.2.9.3b9fa58_20260829.zip` | **通用公共安装包**（52MB）：box 框架 + mihomo ebpf+smart 定制内核，冻结定制已去除，订阅/节点/私人 DNS 已抹除为注释引导（详见 MEMORY.md「通用公共包打包」） |
| `repo/` | mihomo 完整源码仓库（含 .git 与本地 commit），当前分支 `official-20260828`（官方 metacubex/Alpha 061966e7 之上 5 个本地定制 commit），HEAD 82418d06（2026-08-29） |
| `repo/dist/mihomo-ebpf-linux-arm64` | make 默认 linux 目标产物（49MB，旧基线产物，需重编） |
| `deploy/box/bin/mihomo` | **最终部署二进制**（GOOS=android + with_ebpf，44.9MB，md5 24bcd7ec，2026-08-29 同步 vernesong smart 修复版，已真机验证） |
| `deploy/box/mihomo/config.yaml` | 生效配置（ebpf listener + 冻结名单 + wlan2 热点 TC + smart） |
| `deploy/box/mihomo/config.yaml.txt` | box 配置模板（与 config.yaml 同步） |
| `deploy/box/mihomo/config.yaml.bak*` | 历史备份（freeze 版、Btest 版等） |
| `deploy/box/mihomo/Model.bin` | smart LightGBM 模型（21MB） |
| `deploy/box/mihomo/rules/` | 规则集（.mrs + cn_bypass_v4/v6 + freeze_uid 等） |
| `deploy/box/mihomo/scripts/freeze_sync.sh` | v4 双层冻结同步（60s 循环） |
| `deploy/service.d/netd_cleanup.sh` | netd 防火墙清理 + mihomo_guard + freeze_guard（开机执行） |
| `deploy/service.d/box_service.sh` | mihomo 启动脚本 |
| `tools/` | bpf 内核 map 探测工具（源码+android 静态二进制）、patch、评估记录、python 辅助 |
| `MEMORY.md` | 全部排障记忆（根因、坑、验证状态） |

## 二、构建方法

**工具链**：Go 1.25.0（go.mod 要求，WSL /usr/local/go 可用），仓库必须放在 ext4/F2FS 真实路径
（FUSE 挂载点（如 /sdcard 某些目录）上 mv/cp 会 setfilecon 失败，大文件操作用 /data/media/0）。

**上游同步拓扑（2026-08-29 核查）**：本地 `official-20260828` 分支基于官方
metacubex/Alpha（061966e7）+ 本地 ebpf/smart 定制（与 TanakaLun 已重组的
ebpf-inbound 396e3fce 平行，不 merge 旧线）。smart 功能源自 vernesong/mihomo Alpha，
移植基点 a0da2d97（08-16），2026-08-29 已同步其后两个 nodes filter 修复
（5664b1ba + 84ff1af2，commit 82418d06）。**WSL 拉取上游用 tools/git-gh-proxy.sh**
（手机 mihomo 代理 192.168.1.177:7890 + gh-proxy.com 加速，详见 MEMORY.md 网络方案）。

```bash
# 1. 准备仓库（从本 zip 解出即可）
# 2. 拉取上游（WSL 直连 GitHub 超时，用手机 mihomo 代理 + gh-proxy 加速）：
#    tools/git-gh-proxy.sh fetch <repo>（详见 MEMORY.md 网络方案）
# 3. 编译（关键：GOOS=android 才能读到 Android 系统 CA 池；with_ebpf 缺了 bpf fd=0 无劫持）
cd repo
GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
  go build -tags with_ebpf -trimpath -ldflags "-w -s" \
  -o mihomo_android_arm64 .

# 或 make ebpf-smart（产物 dist/mihomo-ebpf-linux-arm64，注意 make 默认 GOOS=linux）
```

**为什么必须 GOOS=android**：Go 静态编译（GOOS=linux）的 root_linux.go 只在 GOOS=android
时才读 /system/etc/security/cacerts；否则系统 CA 池为空 → 所有 DoH/DoT x509 unknown
authority → 代理正常但直连全挂。本仓库 component/ca/ca-certificates.crt 是 0 字节不可用。

**本地定制 commit（official-20260828 分支，共 5 个，在 metacubex/Alpha 061966e7 之上）**：
1. `7ac37238` ebpf：在官方 Alpha 之上移植 TanakaLun ebpf-inbound 特性
2. `91b70b21` smart LightGBM 移植（vernesong/mihomo 方案：component/smart + adapter/outboundgroup/smart.go + leaves 依赖）
3. `f967f71c` inbound.go 中 startBypassRuleSets 原版从未被调用（bypassRuleSetStarted 恒 false），已在 attach 块补调用，否则 bypass_rule_set 永不刷入内核
4. `53feee98` Model.bin 原子下载加固（临时文件+fsync+128MB 上限+模型校验+rename）+ uid.go 匹配语义修复与日志降噪
5. `82418d06` smart：同步 vernesong 上游 nodes filter 修复（5664b1ba+84ff1af2），GetHostStatus 动态 hostFailLimit blocked 判定（2026-08-29）

## 三、使用方法

### 部署（Magisk/KSU，/data/adb）

```bash
cp mihomo_android_arm64 /data/adb/box/bin/mihomo
chown root:net_admin /data/adb/box/bin/mihomo && chmod 6755 /data/adb/box/bin/mihomo
cp config.yaml.txt /data/adb/box/mihomo/config.yaml.txt   # box 重启时用此模板
cp config.yaml     /data/adb/box/mihomo/config.yaml
cp -r rules/*      /data/adb/box/mihomo/rules/
cp Model.bin       /data/adb/box/mihomo/Model.bin
cp scripts/freeze_sync.sh /data/adb/box/mihomo/scripts/
cp service.d/*.sh  /data/adb/service.d/   # 开机自动执行
```

### 启动（关键坑：box.service 拉起的 mihomo 活不过 60-90s 被系统静默 SIGKILL）

```bash
setsid /data/adb/box/bin/mihomo -d /data/adb/box/mihomo -f /data/adb/box/mihomo/config.yaml >/data/adb/box/run/mihomo.log 2>&1 &
echo $! > /data/adb/box/run/box.pid
# oom_score_adj 会被系统周期性改回 0，需循环维护 -1000（netd_cleanup.sh 的 mihomo_guard 自动做）
```

**config.yaml 关键段**（ebpf 透明代理）：

```yaml
listeners:
  - type: ebpf
    mode: local                # 或 shared（热点分流）
    dns-mode: hijack
    local.ipv6-mode: off
    exclude-uid-range: ["0:2999"]   # 必须排除系统 UID，否则 Wi-Fi 验证失败→网络掉蜂窝→DNS 全挂
    # bypass_rule_set: [cn_bypass_v4, cn_bypass_v6]  # 国内直连绕过内核拦截（已回滚，见记忆）

shared:                        # 热点分流（ColorOS "WLAN 共享"桥接模式）
  interface: [wlan2]           # 热点 AP 接口（iw dev 确认，不是 wlan0 上游 station）
  include-source-cidr: [10.169.163.0/24]  # 热点 client 网段（桥接=与上游同网段）
  dns-mode: hijack
```

**冻结双层拦截**（doze 冻结 app 断网）：freeze_sync.sh 每 60s 读 dumpsys
isFrozen=true → ① mihomo 规则 provider「冻结名单」PUT 热加载（REJECT 代理流量）
② iptables FREEZE_OUTPUT owner DROP（bypass/直连兜底，因 UID 规则对 bypass 流量无效）。
白名单 rules/freeze_whitelist.list 可豁免。

### 排障要点

- attach 是否成功：日志 `[EBPF] inbound attached: cgroup=/sys/fs/cgroup, programs=[sb_ebpf_conn4 ...]`；或 /proc/PID/fd 有 anon_inode:bpf-map
- **log-level 必须 info/debug**（silent 会吞掉全部 EBPF 错误日志，误判 attach 没发生）
- **多实例 flock 抢锁**：多个 mihomo 抢 /sys/fs/cgroup 的 flock(LOCK_NB)，后到者报
  "another eBPF inbound is already active on this cgroup: lock cgroup: EBUSY"。
  进程活着、API 正常、但 ebpf 未启用，流量只走系统代理 7890 → 本机看似正常、热点裸奔。
  解决：杀光所有实例+停 guard，单实例启动。
- busybox tc 不支持 clsact/filter 语法，TC 状态别依赖 busybox 查
- 杀 netd 进程 = 死机重启，永远只删规则不杀进程

## 四、适用环境

| 项 | 要求 |
|---|---|
| 设备 | Oplus13（OnePlus 13），ColorOS 15 / Android 15 |
| 内核 | 支持 BPF cgroup2 attach（cgroup/connect4 等 6 类程序）+ clsact TC，需 root bpf 权限 |
| Root | Magisk / KernelSU（/data/adb 可用） |
| 构建 | Linux arm64 工具环境 + Go 1.26.3（本机 Alpine） |
| 其他 | 同架构内核若 bpf 能力一致可移植；不同机型需重查热点接口与网段 |

**已知机型相关坑**：
- 设备命名空间遮蔽：/data/user/0 只暴露 gms 与 fuck.andes，其他应用 data 走 /proc/PID/root
- oplus bpf map 内核保护：bpf_map_info 有 40B vendor 头；oplus-netd 私有 map
  （drop_wlan/drop_cell/freeze_config/hans 等）不可见且由冻结状态动态驱动，无法直接清空
- ColorOS 后台冻结（deviceidle）会 REJECT 后台 app 直连；劫持路径出站 uid 0 不受限；
  全量 `dumpsys deviceidle whitelist +pkg` 可解

## 五、验证状态（2026-08-29 vernesong smart 修复同步版真机验证通过）

- 同步：vernesong 上游 5664b1ba + 84ff1af2 nodes filter 修复 port 至本地（commit 82418d06），
  `git diff -w vernesong/Alpha` 仅剩 import 顺序格式差；V4-Flash 独立审核通过
- 部署：/data/adb/box/bin/mihomo 已替换（md5 24bcd7ec，旧版备份 mihomo.bak.vernesong20260829，
  md5 240c86f0）；注意 chown 会清 setuid 位，chmod 6755 要在 chown 之后执行
- 运行：pid 28199 稳定；[Smart] Model.bin 加载成功；bpf fd 45 个（attach 成功）
- 代理通路：google 204@0.28s；baidu 200@0.16s；connections type=EBPF ✓
- 启动期告警：Metadata not valid UDP **0 条**（08-28 基线有 ~85 条，本次无此现象）
- 配置：ebpf listener mode=hybrid + network [tcp,udp]（用户当前方案，本次未改动）
- 2026-08-28 同步版验证：google 204@0.25s；baidu 200@0.075s；热点 client Microsoft 443
  流量 type=EBPF ✓（详见 MEMORY.md）
- 2026-08-17 旧版验证：本机 baidu 直连 200@60ms（bypass 规则集 8373 条）、热点 client
  type=EBPF、冻结双层拦截、DoH/DoT 全通道 NOERROR ✓

## 六、主要历史问题速查（详见 MEMORY.md）

1. 奶昔机场 anytls：节点加 `client-metadata: clash.meta`
2. DNS 全挂：GOOS=linux 静态编译无系统 CA 池 → GOOS=android 重编
3. bypass 不生效：startBypassRuleSets 未调用（已修，commit 56253904）
4. ebpf 未启用假象：log-level silent + 多实例 flock 抢锁
5. 热点不分流：TC 挂 wlan2 + 网段 10.169.163.0/24
6. mihomo 被静默 SIGKILL：必须 setsid 启动 + 循环维护 oom_score_adj=-1000
