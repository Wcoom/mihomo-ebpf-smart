#!/system/bin/sh

(
  until [ "$(getprop init.svc.bootanim)" = "stopped" ]; do
    sleep 10
  done

  if [ -f "/data/adb/box/scripts/start.sh" ]; then
    chmod 755 /data/adb/box/scripts/*
    /data/adb/box/scripts/start.sh
  else
    echo "未找到文件 '/data/adb/box/scripts/start.sh'"
  fi

  # mihomo 调优：LMK 豁免（oom_score_adj=-1000），等待进程出现
  PID=""
  i=0
  while [ -z "$PID" ] && [ "$i" -lt 20 ]; do
    PID=$(pidof mihomo 2>/dev/null)
    [ -z "$PID" ] && sleep 3
    i=$((i+1))
  done
  for p in $PID; do
    echo -1000 > /proc/$p/oom_score_adj 2>/dev/null && echo "[mihomo_tune] oom_score_adj=-1000 pid=$p"
  done
)&
