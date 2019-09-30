all:
	mkdir -p build
	g++ src/*.cpp -lsodium -lboost_system -lboost_filesystem -pthread -std=c++17 -o build/hpcore
	echo 'build successful, binary in '`pwd`'/build/hpcore'
