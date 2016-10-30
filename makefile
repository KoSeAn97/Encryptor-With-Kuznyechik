cxx = g++
cxxflags = -std=gnu++11

srcs = main.cpp Kuznyechik.cpp mycrypto.cpp argvparser.cpp
hdrs = Kuznyechik.hpp mycrypto.hpp argvparser.h
objs = $(srcs:.cpp=.o)

program: $(objs)
	$(cxx) $^ -o $@ -lpthread
main.o: main.cpp Kuznyechik.hpp mycrypto.hpp argvparser.h
	$(cxx) $(cxxflags) $< -c -o $@
Kuznyechik.o: Kuznyechik.cpp Kuznyechik.hpp mycrypto.hpp
	$(cxx) $(cxxflags) $< -c -o $@
mycrypto.o: mycrypto.cpp mycrypto.hpp
	$(cxx) $(cxxflags) $< -c -o $@
argvparser.o: argvparser.cpp argvparser.h
	$(cxx) $(cxxflags) $< -c -o $@

.PHONY: clean all
all: program
clean:
	$(RM) $(objs) program
