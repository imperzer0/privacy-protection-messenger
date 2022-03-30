pkgname="privacy-protection-messenger"
epoch=1
pkgver=0
pkgrel=3
pkgdesc="secure SSL messenger"
arch=("x86_64")
url="https://github.com/imperzer0/privacy-protection-messenger"
license=('GPL')
depends=("openssl" "iptables-nft")
makedepends=("cmake>=3.0" "inet-comm>=3.6-0" "openssl")

_libfiles=("CMakeLists.txt" "main.cpp" "color.hpp" "network.hpp" "$pkgname.service")

for _libfile in ${_libfiles[@]}
{
    source=(${source[@]} "local://$_libfile")
}

for _libfile in ${_libfiles[@]}
{
    md5sums=(${md5sums[@]} "SKIP")
}

_package_version=$pkgname" ("$epoch":"$pkgver"-"$pkgrel")"
_var_directory="/var/lib/$pkgname"

build()
{
	cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DPACKAGE_VERSION=$_package_version -DVAR_DIRECTORY=$_var_directory .
	make
}

package()
{
	install -Dm755 $pkgname "$pkgdir/usr/bin/$pkgname"
	install -Dm644 $pkgname.service "$pkgdir/etc/systemd/system/$pkgname.service"
	mkdir -pm644 $pkgdir$_var_directory
}
