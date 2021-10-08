#!/bin/sh

for f in bin/k2sup*; do shasum -a 256 $f > $f.sha256; done
