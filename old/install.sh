#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run this as root"
  exit
fi

cp ./sysctl.conf /etc

sysctl -p
echo "Settings updated"