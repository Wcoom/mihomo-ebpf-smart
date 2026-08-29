#!/system/bin/sh
# gen_bypass_rules.sh - 生成 mihomo ebpf 模式的域名+IP 放行规则集
# 源：ChinaMax_IP.yaml（文本）+ CN_IP.mrs / CN_域.mrs（二进制，可 zstd 解压时合并）
# 产物：cn_bypass_v4.list / cn_bypass_v6.list（供 config.yaml 的 bypass_rule_set 引用）
# 幂等：已存在且非空时跳过；重新生成请先删除 list 文件再运行。

RULES=/data/adb/box/mihomo/rules
V4=$RULES/cn_bypass_v4.list
V6=$RULES/cn_bypass_v6.list
MIN=500   # sanity：生成结果少于该行数视为失败，不覆盖

[ -s "$V4" ] && [ -s "$V6" ] && { echo "list 已存在，跳过生成"; exit 0; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ---- IPv4 CIDR ----
grep -hoE "((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/[0-9]{1,2}" \
  "$RULES/ChinaMax_IP.yaml" 2>/dev/null | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$TMP/v4.txt"

# ---- IPv6 CIDR（行内含冒号）----
grep -hoE "[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){2,}/[0-9]{1,3}" \
  "$RULES/ChinaMax_IP.yaml" 2>/dev/null | grep -vE "^(25[0-5]|2[0-4][0-9]|[0-9]{1,2})\." | sort -u > "$TMP/v6.txt"

# ---- 合并二进制 mrs 源（如环境可用 zstd）----
if command -v zstd >/dev/null 2>&1; then
  for f in "$RULES/CN_IP.mrs" "$RULES/CN_域.mrs"; do
    [ -f "$f" ] || continue
    zstd -dc "$f" 2>/dev/null | grep -hoE "((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/[0-9]{1,2}" >> "$TMP/v4.txt"
    zstd -dc "$f" 2>/dev/null | grep -hoE "[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){2,}/[0-9]{1,3}" | grep -vE "^(25[0-5]|2[0-4][0-9]|[0-9]{1,2})\." >> "$TMP/v6.txt"
  done
  sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n -o "$TMP/v4.txt" "$TMP/v4.txt"
  sort -u -o "$TMP/v6.txt" "$TMP/v6.txt"
fi

# ---- sanity + 落盘 ----
if [ "$(wc -l < "$TMP/v4.txt")" -ge "$MIN" ]; then
  cp "$TMP/v4.txt" "$V4" && echo "已生成 $V4 ($(wc -l < $V4) 条)"
else
  echo "v4 生成异常（$(wc -l < $TMP/v4.txt) 行 < $MIN），保留旧文件"; exit 1
fi
if [ "$(wc -l < "$TMP/v6.txt")" -ge "$MIN" ]; then
  cp "$TMP/v6.txt" "$V6" && echo "已生成 $V6 ($(wc -l < $V6) 条)"
else
  echo "v6 生成异常（$(wc -l < $TMP/v6.txt) 行 < $MIN），保留旧文件"; exit 1
fi

# ---- 校验 config.yaml 引用 ----
grep -q "cn_bypass_v4" "$RULES/../config.yaml" 2>/dev/null && \
  grep -q "bypass_rule_set" "$RULES/../config.yaml" 2>/dev/null && \
  echo "config.yaml 已引用 bypass_rule_set，无需改动" || \
  echo "警告：config.yaml 未检测到 bypass 配置，请检查"
exit 0
