pkgname="privacy-protection-messenger"
pkgver=2.0
pkgrel=3
pkgdesc="Secure messenger backend"
author="imperzer0"
url="https://github.com/$author/$pkgname"
arch=("x86_64")
license=('GPL3')
depends=("openssl" "iptables-nft" "themispp>=0.14.1" "mariadb" "lua")
makedepends=("cmake>=3.0" "inet-comm>=3.9-0" "openssl" "themispp" "mariadb" "mariadb-connector-cpp-git" "lua")

_srcprefix="local:/"
_libfiles=("CMakeLists.txt" "main.cpp" "color.hpp" "messenger.hpp" "constants.hpp" "$pkgname.service" "config.lua")

for _libfile in ${_libfiles[@]}
{
    source=(${source[@]} "$_srcprefix/$_libfile")
}

for _libfile in ${_libfiles[@]}
{
    md5sums=(${md5sums[@]} "SKIP")
}

_package_version=$pkgname" ("$pkgver"-"$pkgrel")"
_var_directory="/var/lib/$pkgname"
_cfg_directory="/etc/$pkgname"

build()
{
	cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++\
	      -DPACKAGE_VERSION="$_package_version" -DVAR_DIRECTORY="$_var_directory" -DAPPNAME="$pkgname"\
	      -DCFG_DIR="$_cfg_directory" .
	make -j 4
}

package()
{
	install -Dm755 $pkgname "$pkgdir/usr/bin/$pkgname"
	install -Dm644 $pkgname.service "$pkgdir/etc/systemd/system/$pkgname.service"
	mkdir -pm755 $pkgdir$_var_directory
	mkdir -pm755 $pkgdir$_cfg_directory
	install -Dm644 "config.lua" "$pkgdir$_cfg_directory/config.lua"
}

notarch_package()
{
	cp -f $pkgname "$pkgdir/usr/bin/$pkgname"
	chmod 755 "$pkgdir/usr/bin/$pkgname"

	cp -f $pkgname.service "$pkgdir/etc/systemd/system/$pkgname.service"
	chmod 644 "$pkgdir/etc/systemd/system/$pkgname.service"

	mkdir -pm755 $pkgdir$_var_directory
	mkdir -pm755 $pkgdir$_cfg_directory

	cp -f "config.lua" "$pkgdir$_cfg_directory/config.lua"
	chmod 644 "$pkgdir$_cfg_directory/config.lua"
}
