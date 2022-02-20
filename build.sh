#!/bin/sh
set -eu

stickytape run.py > dslite_autoconfig.py
chmod 755 dslite_autoconfig.py
