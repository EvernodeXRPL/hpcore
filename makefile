all:
	mkdir -p build
	g++ src/*.cpp -lsodium -std=c++17 -o build/hpcore
	echo 'build successful, binary in '`pwd`'/build/hpcore'
