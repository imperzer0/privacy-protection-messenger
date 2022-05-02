pkgname="privacy-protection-messenger"
pkgver=1.2
pkgrel=3
pkgdesc="Secure messenger backend"
author="imperzer0"
url="https://github.com/$author/$pkgname"
arch=("x86_64")
license=('GPL3')
depends=("openssl" "iptables-nft" "themispp>=0.14.1" "mariadb")
makedepends=("cmake>=3.0" "inet-comm>=3.8-1" "openssl" "themispp" "mariadb" "mariadb-connector-cpp-git")

_srcprefix="local:/"
_libfiles=("CMakeLists.txt" "main.cpp" "color.hpp" "messenger.hpp" "constants.hpp" "$pkgname.service")

for _libfile in ${_libfiles[@]}
{
    source=(${source[@]} "$_srcprefix/$_libfile")
}

md5sums=('a7abc0672242dedcd5e4f563456e7dbc'
         'a2dba69f4367abe24cd54ba931c693bd'
         '058646ab78672c97a2f18dffc1b56ebf'
         '5870cc285cd690761cd23c994737fa54'
         'd17f4a822e966a71ea10bac39429811d'
         'cc8e63452b809611b046e7f27934c12e')

_package_version=$pkgname" ("$pkgver"-"$pkgrel")"
_var_directory="/var/lib/$pkgname"
_cfg_directory="/etc/$pkgname"

build()
{
	cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++\
	      -DPACKAGE_VERSION="$_package_version" -DVAR_DIRECTORY="$_var_directory" -DAPPNAME="$pkgname"\
	      -DCFG_DIR="$_cfg_directory" .
	make
}

package()
{
	install -Dm755 $pkgname "$pkgdir/usr/bin/$pkgname"
	install -Dm644 $pkgname.service "$pkgdir/etc/systemd/system/$pkgname.service"
	mkdir -pm644 $pkgdir$_var_directory
	mkdir -pm644 $pkgdir$_cfg_directory
}

notarch_package()
{
	cp -f $pkgname "$pkgdir/usr/bin/$pkgname"
	chmod 755 "$pkgdir/usr/bin/$pkgname"
	cp -f $pkgname.service "$pkgdir/etc/systemd/system/$pkgname.service"
	chmod 644 "$pkgdir/etc/systemd/system/$pkgname.service"
	mkdir -pm644 $pkgdir$_var_directory
	mkdir -pm644 $pkgdir$_cfg_directory
}
