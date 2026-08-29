#!/system/bin/sh
# netd_cleanup.sh - ColorOS/netd 防火墙清理 + mihomo 网络层冻结协同（长期常驻）
# 组成:
#   1) 清理 netd 重建的 REJECT/DROP 规则 (60s)
#   2) deviceidle 加白: 解除 ColorOS 网络拦截, 让 mihomo 全权决策网络 (600s)
#   3) mihomo 守护: setsid 重启 + oom 豁免 (60s)
#   4) freeze_sync 守护: ColorOS freezer 状态 → mihomo REJECT + iptables DROP (60s)
# 绝不动 netd 进程本身（杀 netd 会导致系统死机重启）。

(
  # ---- 等系统就绪 ----
  i=0
  while [ $i -lt 120 ]; do
    [ "$(getprop init.svc.bootanim)" = "stopped" ] && break
    sleep 5
    i=$((i + 1))
  done
  sleep 25

  # ---- 0) 确保 mihomo bypass 规则集存在 ----
  [ -f /data/adb/box/scripts/gen_bypass_rules.sh ] && \
    /data/adb/box/scripts/gen_bypass_rules.sh >/dev/null 2>&1

  # ---- 1) 清理 iptables 层 REJECT/DROP（ipv4+ipv6）----
  clean_once() {
    for CH in fw_OUTPUT fw_INPUT oplus_fw_OUTPUT fw_OUTPUT_oplus_dns fw_INPUT_oplus_dns; do
      for LN in $(iptables -t filter -L "$CH" --line-numbers 2>/dev/null | grep -E "REJECT|DROP" | awk '{print $1}' | sort -rn); do
        iptables -t filter -D "$CH" "$LN" 2>/dev/null
      done
      for LN in $(ip6tables -t filter -L "$CH" --line-numbers 2>/dev/null | grep -E "REJECT|DROP" | awk '{print $1}' | sort -rn); do
        ip6tables -t filter -D "$CH" "$LN" 2>/dev/null
      done
    done
  }
  clean_once

  # ---- 2) 批量解除后台冻结 ----
  whitelist_all() {
    for p in $(pm list packages 2>/dev/null | sed 's/package://'); do
      dumpsys deviceidle whitelist +$p >/dev/null 2>&1
    done
  }
  whitelist_all

  # ---- 3) mihomo 守护 (setsid 脱会话防杀 + oom 豁免) ----
  mihomo_guard() {
    PID_FILE=/data/adb/box/run/box.pid
    LOCK_DIR=/data/adb/box/run/locks/mihomo_guard.lock

    # Respect Box's explicit stop/disable states. A missing pid file means the
    # service was intentionally stopped; the guard must not resurrect it.
    [ -f /data/adb/box/manual ] && return 0
    [ -f /data/adb/modules/box_for_root/disable ] && return 0
    [ -s "$PID_FILE" ] || return 0

    PID=$(cat "$PID_FILE" 2>/dev/null)
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
      case "$(tr '\000' ' ' < /proc/$PID/cmdline 2>/dev/null)" in
        /data/adb/box/bin/mihomo\ *) ;;
        *) PID="" ;;
      esac
    else
      PID=""
    fi

    if [ -z "$PID" ]; then
      mkdir -p /data/adb/box/run/locks
      mkdir "$LOCK_DIR" 2>/dev/null || return 0

      # Recheck after taking the lock. Box may have completed a concurrent
      # restart while this guard was waiting.
      RUNNING=$(pidof mihomo 2>/dev/null)
      if [ -n "$RUNNING" ]; then
        set -- $RUNNING
        if [ "$#" -eq 1 ]; then
          PID="$1"
        else
          echo "[$(date '+%m-%d %H:%M:%S')] guard skip: multiple mihomo pids=$RUNNING" >> /data/local/tmp/fuck_andes/guard.log
        fi
      else
        setsid /data/adb/box/bin/mihomo -d /data/adb/box/mihomo \
          -f /data/adb/box/mihomo/config.yaml \
          >/data/adb/box/run/mihomo_guard.log 2>&1 &
        PID=$!
        sleep 3
        if ! kill -0 "$PID" 2>/dev/null; then
          echo "[$(date '+%m-%d %H:%M:%S')] mihomo restart failed" >> /data/local/tmp/fuck_andes/guard.log
          PID=""
        else
          echo "$PID" > "$PID_FILE.tmp"
          mv "$PID_FILE.tmp" "$PID_FILE"
          echo "[$(date '+%m-%d %H:%M:%S')] mihomo restarted pid=$PID" >> /data/local/tmp/fuck_andes/guard.log
        fi
      fi

      # Adopt a single process started concurrently by Box so both managers
      # agree on the same PID.
      if [ -n "$PID" ]; then
        echo "$PID" > "$PID_FILE.tmp"
        mv "$PID_FILE.tmp" "$PID_FILE"
      fi
      rmdir "$LOCK_DIR" 2>/dev/null
    fi

    [ -n "$PID" ] && [ "$(cat /proc/$PID/oom_score_adj 2>/dev/null)" != "-1000" ] && \
      echo -1000 > /proc/$PID/oom_score_adj 2>/dev/null
  }

  # ---- 4) freeze_sync 守护 ----
  freeze_guard() {
    if ! pgrep -f freeze_sync.sh >/dev/null 2>&1; then
      setsid /data/adb/box/mihomo/scripts/freeze_sync.sh \
        >/dev/null 2>&1 &
    fi
  }

  # ---- 常驻循环 ----
  while true; do
    sleep 60
    clean_once
    mihomo_guard
    freeze_guard
  done &

  while true; do
    sleep 600
    whitelist_all
  done &

  wait
) &
