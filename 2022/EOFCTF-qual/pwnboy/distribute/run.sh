#!/bin/bash
export DISPLAY=:1
stdbuf -i0 -o0 -e0 python3 /home/pwnboy/run_gameboy.py
