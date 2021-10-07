
This is an awful fork of k3sup - a light-weight utility to get from zero to KUBECONFIG, originally with K3s but now with [RKE2](https://rke2.io/) instead. All you need is `ssh` access and the `k3sup` binary to get `kubectl` access fairly quickly.

RKE2 is downstream from K3s, but is just about sufficiently different in its installation approach (and probably target audience) that a fork makes sense.

The tool is written in Go and is cross-compiled for Linux, Windows, MacOS and even on Raspberry Pi.


