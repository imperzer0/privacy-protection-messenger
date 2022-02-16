pkgname="privacy-protection-messenger"
epoch=1
pkgver=0
pkgrel=0
pkgdesc="secure SSL messenger"
arch=("x86_64")
url="https://github.com/imperzer0/privacy-protection-messenger"
license=('GPL')
depends=("openssl" "iptables-nft")
makedepends=("cmake>=3.0" "messenger-comm>=1:0-0" "openssl")

libfiles=("CMakeLists.txt" "main.cpp" "$pkgname.conf" "$pkgname.service")

for libfile in ${libfiles[@]}
{
    source=(${source[@]} "local://$libfile")
}

for libfile in ${libfiles[@]}
{
    md5sums=(${md5sums[@]} "SKIP")
}

build()
{
	cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DPACKAGE_VERSION=$pkgname" ("$epoch":"$pkgver"-"$pkgrel")" .
	make
}

package()
{
	install -Dm755 $pkgname "$pkgdir/usr/bin/$pkgname"
	install -Dm644 $pkgname.service "$pkgdir/etc/systemd/system/$pkgname.service"
	install -Dm644 $pkgname.conf "$pkgdir/etc/$pkgname/config.conf"
}
