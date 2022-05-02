pkgname="privacy-protection-messenger"
pacname="privacy-protection-messenger"
pkgver=1.3
pkgrel=0
pkgdesc="Secure messenger backend"
author="imperzer0"
url="https://github.com/$author/$pacname"
arch=("x86_64")
license=('GPL3')
depends=("openssl" "iptables-nft" "themispp>=0.14.1" "mariadb")
makedepends=("cmake>=3.0" "inet-comm>=3.9-0" "openssl" "themispp" "mariadb" "mariadb-connector-cpp-git")

_srcprefix="local:/"
_libfiles=("CMakeLists.txt" "main.cpp" "color.hpp" "messenger.hpp" "constants.hpp" "$pacname.service")

for _libfile in ${_libfiles[@]}
{
    source=(${source[@]} "$_srcprefix/$_libfile")
}

for _libfile in ${_libfiles[@]}
{
    md5sums=(${md5sums[@]} "SKIP")
}

_package_version=$pacname" ("$pkgver"-"$pkgrel")"
_var_directory="/var/lib/$pacname"
_cfg_directory="/etc/$pacname"

build()
{
	cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++\
	      -DPACKAGE_VERSION="$_package_version" -DVAR_DIRECTORY="$_var_directory" -DAPPNAME="$pacname"\
	      -DCFG_DIR="$_cfg_directory" .
	make
}

package()
{
	install -Dm755 $pacname "$pkgdir/usr/bin/$pacname"
	install -Dm644 $pacname.service "$pkgdir/etc/systemd/system/$pacname.service"
	mkdir -pm644 $pkgdir$_var_directory
	mkdir -pm644 $pkgdir$_cfg_directory
}

notarch_package()
{
	cp -f $pacname "$pkgdir/usr/bin/$pacname"
	chmod 755 "$pkgdir/usr/bin/$pacname"
	cp -f $pacname.service "$pkgdir/etc/systemd/system/$pacname.service"
	chmod 644 "$pkgdir/etc/systemd/system/$pacname.service"
	mkdir -pm644 $pkgdir$_var_directory
	mkdir -pm644 $pkgdir$_cfg_directory
}
