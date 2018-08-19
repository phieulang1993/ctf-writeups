#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
# cd /home/gift
./ptrace_64 /home/phieulang/2018/whitehatgrandprix/forPlayer/giftshop phieulang 1 60 50 blacklist.conf
