all:
	mkdir -p build
	g++ src/*.cpp src/*.cc -lsodium -lboost_system -lboost_filesystem -pthread -lprotobuf  -std=c++17 -o build/hpcore 
	echo 'build successful, binary in '`pwd`'/build/hpcore'
