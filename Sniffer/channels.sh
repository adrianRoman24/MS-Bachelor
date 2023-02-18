#!/bin/bash

while true; do
  for x in {1..14}; do
    iwconfig wlx5ca6e630bd88 channel $x;
    echo "channel set: $x"
    sleep 5
  done
  clear;
done
