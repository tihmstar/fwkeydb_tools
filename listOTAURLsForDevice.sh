#!/bin/bash


device=$@

curl "https://ipsw.me/otas/${device}" 2>/dev/null | grep -o "/download/ota/${device}/[0-9a-zA-Z]*" | sort | uniq | while read p; do
  url="https://ipsw.me${p}";
  curl "${url}" 2>/dev/null | grep -o "http.*apple\.com.*\.zip"
done