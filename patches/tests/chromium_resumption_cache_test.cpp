#include "mtproto/details/mtproto_chromium_resumption_cache.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

using Cache = MTP::details::ChromiumResumptionCache<int>;
using Minutes = std::chrono::minutes;

int main() {
	const auto start = Cache::TimePoint();
	const auto lifetime = [] { return Minutes(40); };

	Cache cache(2, 2);
	assert(!cache.take(1, start));
	assert(cache.confirm(1, lifetime, start) == Minutes(40));
	assert(cache.slotCount(1, start) == 2);
	assert(cache.take(1, start));
	assert(cache.take(1, start));
	assert(!cache.take(1, start));

	assert(cache.confirm(1, [] { return Minutes(0); }, start) == Minutes(1));
	assert(cache.slotCount(1, start + Minutes(1)) == 0);

	(void)cache.confirm(1, [] { return Minutes(10); }, start);
	(void)cache.confirm(2, [] { return Minutes(20); }, start);
	(void)cache.confirm(3, [] { return Minutes(30); }, start);
	assert(cache.slotCount(1, start) == 0);
	assert(cache.slotCount(2, start) == 2);
	assert(cache.slotCount(3, start) == 2);

	Cache concurrent(128, 2);
	(void)concurrent.confirm(7, lifetime, start);
	auto resumed = std::atomic<int>(0);
	auto workers = std::vector<std::thread>();
	for (auto i = 0; i != 8; ++i) {
		workers.emplace_back([&] {
			if (concurrent.take(7, start)) {
				++resumed;
			}
		});
	}
	for (auto &worker : workers) {
		worker.join();
	}
	assert(resumed.load() == 2);

	std::cout << "Chromium synthetic resumption-cache tests passed.\n";
}
