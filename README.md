# keensteer

keensteer enables seamless roaming between Keenetic and OpenWrt access points.

It runs on the Keenetic as a small translation layer between Keenetic's roaming stack and usteer / usteer-ng on OpenWrt. It reports connected clients to usteer and handles the 802.11r key exchange needed for fast roaming between both sides.

# Installation

## Prerequisites

On OpenWrt:

- usteer or [usteer-ng](https://github.com/NilsRo/usteer-ng)
- A wpad package with WPA3/SAE and 802.11r support, such as wpad-basic-openssl
- The same SSID and security settings as the Keenetic AP

On Keenetic:

- [Entware](https://support.keenetic.com/hero-dsl/kn-2410/en/20980-installing-the-entware-repository-on-a-usb-drive.html)

## Install

SSH into the Keenetic Entware shell:

```sh
ssh -p 222 root@192.168.1.1
```

Replace `192.168.1.1` with your Keenetic's address. Entware uses port 222 when KeeneticOS's SSH server component is installed; otherwise Entware uses port 22.

Download the release archive matching the Entware architecture installed on the Keenetic (`mips`, `mipsel` or `aarch64`) and install it:

```sh
cd /opt/tmp
wget -O keensteer.tar.gz \
  https://github.com/mhndt/keensteer/releases/download/v1.0.6/keensteer-1.0.6-mips.tar.gz
tar -xzf keensteer.tar.gz
cd keensteer-1.0.6
./install.sh
/opt/sbin/keensteer-setup
```

The installer puts keensteer under /opt. Existing configuration and keys are left alone when upgrading.

The setup helper discovers the Keenetic radios, configures every matching access point on each OpenWrt host over SSH, writes the keensteer configuration and starts the daemon. See [SETUP.md](SETUP.md) for the guided and manual setup paths.

# Usage

```sh
/opt/etc/init.d/S99keensteer start
/opt/etc/init.d/S99keensteer stop
/opt/etc/init.d/S99keensteer restart
```

Check the installed version:

```sh
/opt/sbin/keensteerd -V
```

To uninstall:

```sh
./uninstall.sh
```

The config and keys are kept when uninstalling.

# Compatibility

keensteer has been tested on a Keenetic Hero DSL KN-2410 running KeeneticOS 5.1.3 with a TP-Link RE200 v4 running OpenWrt. Other Keenetic models may work but have not been tested yet.

[PROTOCOL.md](PROTOCOL.md) contains the protocol and reverse-engineering notes.

# Building from Source

```sh
make
make test
```

Keenetic releases need to be built with the matching Entware cross-toolchain. A native PC build will not run on the router.

# Contributing

Issues and pull requests are welcome. Reports from other Keenetic models are especially useful.

# License

GPL-3.0-only. See [LICENSE](LICENSE).

Keenetic and MediaTek are trademarks of their respective owners. This project is independent and is not affiliated with or endorsed by either company.
