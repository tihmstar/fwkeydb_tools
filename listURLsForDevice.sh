#!/bin/bash

curl https://api.ipsw.me/v2.1/firmwares.json/condensed 2>/dev/null | jq .devices.\"$@\".firmwares[].url | tr -d '"'