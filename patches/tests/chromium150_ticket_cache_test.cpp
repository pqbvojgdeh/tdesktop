#include "mtproto/details/mtproto_chromium_session_cache.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

namespace {

using Cache = MTP::details::ChromiumSessionCache<int>;
using Minutes = std::chrono::minutes;

[[noreturn]] void Fail(const char *message) {
	std::cerr << message << std::endl;
	std::exit(1);
}

void Expect(bool condition, const char *message) {
	if (!condition) {
		Fail(message);
	}
}

} // namespace

int main() {
	const auto start = Cache::TimePoint();
	const auto lifetime = [] { return Minutes(40); };

	{
		auto cache = Cache(128, 2);
		Expect(!cache.take(1, start), "A new endpoint must start fresh.");
		Expect(cache.confirm(1, lifetime, start) == Minutes(40),
			"Confirmation must report the issued lifetime.");
		Expect(cache.ticketCount(1, start) == 2,
			"A successful handshake must issue two tickets.");
		Expect(cache.take(1, start), "The first ticket must resume.");
		Expect(cache.take(1, start), "The second ticket must resume.");
		Expect(!cache.take(1, start),
			"Each issued ticket must be consumed only once.");
	}

	{
		auto cache = Cache(128, 2);
		(void)cache.confirm(1, lifetime, start);
		Expect(cache.take(1, start), "A failed attempt still takes one ticket.");
		Expect(cache.ticketCount(1, start) == 1,
			"A failed attempt must not replenish the cache.");
		(void)cache.confirm(1, lifetime, start + Minutes(1));
		Expect(cache.ticketCount(1, start + Minutes(1)) == 2,
			"A successful handshake must replenish the cache.");
	}

	{
		auto cache = Cache(128, 2);
		(void)cache.confirm(1, lifetime, start);
		Expect(cache.ticketCount(1, start + Minutes(39)) == 2,
			"Tickets must remain valid before expiry.");
		Expect(cache.ticketCount(1, start + Minutes(40)) == 0,
			"Tickets must expire at their individual deadline.");
		Expect(!cache.take(1, start + Minutes(40)),
			"An expired endpoint must return to fresh.");
	}

	{
		auto cache = Cache(128, 2);
		auto generated = 0;
		const auto longest = cache.confirm(1, [&] {
			return (++generated == 1) ? Minutes(10) : Minutes(20);
		}, start);
		Expect(longest == Minutes(20),
			"The displayed window must use the longest issued ticket.");
		const auto taken = cache.takeWithRemaining(1, start);
		Expect(taken.taken,
			"A confirmed endpoint must provide a resumable ticket.");
		Expect(taken.maximumRemaining == Minutes(10),
			"Taking a ticket must report the actual remaining window.");
		Expect(cache.ticketCount(1, start + Minutes(9)) == 1,
			"The remaining ticket must survive before its deadline.");
		Expect(cache.ticketCount(1, start + Minutes(10)) == 0,
			"The remaining ticket must expire at its own deadline.");
	}

	{
		auto cache = Cache(2, 2);
		(void)cache.confirm(1, [] { return Minutes(10); }, start);
		(void)cache.confirm(2, [] { return Minutes(20); }, start);
		(void)cache.confirm(3, [] { return Minutes(30); }, start);
		Expect(cache.ticketCount(1, start) == 0,
			"The earliest-expiring endpoint must be evicted at capacity.");
		Expect(cache.ticketCount(2, start) == 2,
			"A newer endpoint must survive capacity pruning.");
		Expect(cache.ticketCount(3, start) == 2,
			"The newly confirmed endpoint must be retained.");
	}

	{
		auto cache = Cache(128, 2);
		(void)cache.confirm(1, lifetime, start);
		auto resumed = std::atomic<int>(0);
		auto workers = std::vector<std::thread>();
		for (auto i = 0; i != 8; ++i) {
			workers.emplace_back([&] {
				if (cache.take(1, start)) {
					++resumed;
				}
			});
		}
		for (auto &worker : workers) {
			worker.join();
		}
		Expect(resumed.load() == 2,
			"Parallel attempts must not reuse a single-use ticket.");
	}

	std::cout << "Chromium 150 ticket-cache tests passed." << std::endl;
	return 0;
}
