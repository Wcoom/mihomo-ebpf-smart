#!/bin/bash
# 用手机 mihomo HTTP 代理 + gh-proxy.com 加速 GitHub 的 git 包装器
#
# 背景: WSL 直连 GitHub 超时、gh-proxy.com 被 fake-ip(198.18.0.111)污染;
# 手机端 mihomo(<手机IP>:7890, 监听 *:7890) 出口畅通且快。
# 经手机代理访问 gh-proxy.com → GitHub 全链路 200。
#
# 用法: ./git-gh-proxy.sh ls-remote https://github.com/MetaCubeX/mihomo.git refs/heads/Alpha
#       ./git-gh-proxy.sh clone https://github.com/xxx/yyy.git
#
# 注意: 手机 wlan0 IP 为 DHCP 动态分配, IP 变了就改 PHONE_PROXY 或传环境变量覆盖。
PHONE_PROXY="${PHONE_PROXY:-http://<手机IP>:7890}"

exec git \
  -c http.proxy="$PHONE_PROXY" \
  -c url."https://gh-proxy.com/https://github.com/".insteadOf "https://github.com/" \
  "$@"
