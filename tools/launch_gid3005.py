import os
os.setgid(3005)
os.setuid(0)
os.execv('/workspace/mihomo-alpha', ['mihomo-alpha','-f','/workspace/mtest3.yaml','-d','/workspace/mtest3'])
