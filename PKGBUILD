pkgname="privacy-protection-messenger"
pacname="privacy-protection-messenger"
pkgver=1.2
pkgrel=3
pkgdesc="Secure messenger backend"
author="imperzer0"
url="https://github.com/$author/$pacname"
arch=("x86_64")
license=('GPL3')
depends=("openssl" "iptables-nft" "themispp>=0.14.1" "mariadb")
makedepends=("cmake>=3.0" "inet-comm>=3.8-1" "openssl" "themispp" "mariadb" "mariadb-connector-cpp-git")

_srcprefix="local:/"
_libfiles=("CMakeLists.txt" "main.cpp" "color.hpp" "messenger.hpp" "constants.hpp" "$pacname.service")

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
