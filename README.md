# privacy-protection-messenger
Messenger's client and server backend

## Installation

### From AUR
```bash
yay -Sy privacy-protection-messenger
```

### From repository
```bash
git clone https://github.com/imperzer0/privacy-protection-messenger.git
cd privacy-protection-messenger
```

#### Archlinux
```bash
makepkg -sif
```

#### Other distributions
```bash
sudo bash -c ". ./PKGBUILD && build && notarch_package"
```

## Usage

### Client
Install https://github.com/imperzer0/privacy-protection-messenger-qt to use backend in client mode.

### Server
```bash
sudo systemctl enable privacy-protection-messenger.service --now
```