#!/usr/bin/env python3
import urllib.request, os, sys, time, socket

URL = 'https://bkt-sgp-miui-ota-update-alisgp.oss-ap-southeast-1.aliyuncs.com/V14.0.23.4.17.DEV/miui_HAYDN_V14.0.23.4.17.DEV_c268ec09f4_13.0.zip'
OUT = '/workspace/miui_haydn_V14.0.23.4.17.DEV.zip'
TOTAL = 5581268761

def get_size():
    try:
        return os.path.getsize(OUT)
    except OSError:
        return 0

def download():
    existing = get_size()
    if existing >= TOTAL:
        print('already complete'); return True
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    if existing > 0:
        headers['Range'] = f'bytes={existing}-'
    req = urllib.request.Request(URL, headers=headers)
    last = time.time()
    with open(OUT, 'ab') as f:
        with urllib.request.urlopen(req, timeout=60) as r:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                f.flush()
                now = time.time()
                if now - last >= 30:
                    cur = get_size()
                    print(f'progress {cur}/{TOTAL} ({cur*100.0/TOTAL:.1f}%)', flush=True)
                    last = now
    return get_size() >= TOTAL

while True:
    try:
        if download():
            print('DOWNLOAD_DONE', flush=True)
            break
    except Exception as e:
        print('retry after error:', e, flush=True)
    time.sleep(3)
