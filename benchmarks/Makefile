.PHONY: writev_cow, writev_no_copy, writev_copy, writev_cow_time, writev_no_copy_time, writev_copy_time

writev_cow:
	mkdir -p bin
	gcc writev/writev_cow_benchmark.c -O2 -o writev_cow -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./writev_cow bin
writev_no_copy:
	mkdir -p bin
	gcc writev/writev_no_copy_benchmark.c -O2 -o writev_no_copy -Wno-int-conversion
	mv ./writev_no_copy bin
writev_copy:
	mkdir -p bin
	gcc writev/writev_copy_benchmark.c -O2 -o writev_copy -Wno-int-conversion
	mv ./writev_copy bin

writev_cow_time:
	mkdir -p bin
	gcc writev/writev_cow_benchmark_timer.c -O2 -o writev_cow_time -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./writev_cow_time bin

writev_no_copy_time:
	mkdir -p bin
	gcc writev/writev_no_copy_benchmark_timer.c -O2 -o writev_no_copy_time -Wno-int-conversion
	mv ./writev_no_copy_time bin

writev_copy_time:
	mkdir -p bin
	gcc writev/writev_copy_benchmark_timer.c -O2 -o writev_copy_time -Wno-int-conversion
	mv ./writev_copy_time bin

writev_stats:
	make writev_cow
	make writev_no_copy
	make writev_copy

writev_times:
	make writev_cow_time
	make writev_no_copy_time
	make writev_copy_time

hunspell_cow:
	mkdir -p bin
	g++ hunspell/hunspell_cow.cc -O2 -o hunspell_cow -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./hunspell_cow bin

hunspell_no_copy:
	mkdir -p bin
	g++ hunspell/hunspell_no_copy.cc -O2 -o hunspell_no_copy -std=c++14 -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./hunspell_no_copy bin

hunspell_copy:
	mkdir -p bin
	g++ hunspell/hunspell_copy.cc -O2 -o hunspell_copy -std=c++14 -Wno-int-conversion -Wno-incompatible-pointer-types
	mv hunspell_copy bin

hunspell_cow_time:
	mkdir -p bin
	g++ hunspell/hunspell_cow_benchmark_timer.cc -O2 -std=c++14 -o hunspell_cow_time -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./hunspell_cow_time bin

hunspell_copy_time:
	mkdir -p bin
	g++ hunspell/hunspell_copy_benchmark_timer.cc -O2 -std=c++14 -o hunspell_copy_time -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./hunspell_copy_time bin

hunspell_no_copy_time:
	mkdir -p bin
	g++ hunspell/hunspell_no_copy_benchmark_timer.cc -O2 -std=c++14 -o hunspell_no_copy_time -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./hunspell_no_copy_time bin

sendmsg_cow:
	mkdir -p bin
	gcc sendmsg/sendmsg_cow_benchmark.c -O2 -o sendmsg_cow -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./sendmsg_cow bin
sendmsg_no_copy:
	mkdir -p bin
	gcc sendmsg/sendmsg_no_copy_benchmark.c -O2 -o sendmsg_no_copy -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./sendmsg_no_copy bin
sendmsg_copy:
	mkdir -p bin
	gcc sendmsg/sendmsg_copy_benchmark.c -O2 -o sendmsg_copy -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./sendmsg_copy bin

sendmsg_cow_time:
	mkdir -p bin
	gcc sendmsg/sendmsg_cow_benchmark_timer.c -O2 -o sendmsg_cow_time -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./sendmsg_cow_time bin

sendmsg_no_copy_time:
	mkdir -p bin
	gcc sendmsg/sendmsg_no_copy_benchmark_timer.c -O2 -o sendmsg_no_copy_time -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./sendmsg_no_copy_time bin

sendmsg_copy_time:
	mkdir -p bin
	gcc sendmsg/sendmsg_copy_benchmark_timer.c -O2 -o sendmsg_copy_time -Wno-int-conversion -Wno-incompatible-pointer-types
	mv ./sendmsg_copy_time bin

sendmsg_stats:
	make sendmsg_cow
	make sendmsg_no_copy
	make sendmsg_copy

sendmsg_times:
	make sendmsg_cow_time
	make sendmsg_no_copy_time
	make sendmsg_copy_time

clean:
	rm -rf bin