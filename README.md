# privacy-protection-messenger
Messenger's client and server backend

<h2>Installation</h2>

<h3>From AUR</h3>
```bash
yay -Sy privacy-protection-messenger
```

<h3>From repository</h3>
```bash
git clone https://github.com/imperzer0/privacy-protection-messenger.git
cd privacy-protection-messenger
```

<h4>Archlinux</h4>
```bash
makepkg -sif
```

<h4>Other distributions</h4>
```bash
sudo bash -c ". ./PKGBUILD && build && notarch_package"
```

<h2>Usage</h2>

<h3>Client</h3>
Install https://github.com/imperzer0/privacy-protection-messenger-qt to use backend in client mode.

<h3>Server</h3>
```bash
sudo systemctl enable privacy-protection-messenger.service --now
```