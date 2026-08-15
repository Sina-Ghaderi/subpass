# TUN Driver

A lightweight TUN/TAP driver for **Solaris**, **OpenIndiana**, **SmartOS**, and other **OpenSolaris** derivatives.

### Install for Solaris and Illumos

The recommended installation method is to install the pre-compiled Solaris IPS package using the Image Packaging System (IPS):

```console
# pkg install -g ./tuntap-1.3.5.p5p driver/network/tuntap
```
If you prefer to compile the driver yourself, follow [the instructions](#build-from-source) below.


### Build From Source

Install the required packages on **Solaris 11.4** by running `pkg install gcc gnu-make system/header`  
Configure the build environment and compile the driver:

```console
# cd tuntap && ./configure
# make package
```


### Verification

After installation, verify that the driver is loaded:

```console
# dmesg
# modinfo | grep tun
# modinfo | grep tap
```

If the driver is loaded successfully, the `/dev/tun` and `/dev/tap` character devices should also be present.

### Uninstall

Uninstall driver by executing `pkg uninstall driver/network/tuntap`

