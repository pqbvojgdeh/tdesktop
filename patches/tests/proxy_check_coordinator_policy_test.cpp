#include "mtproto/details/mtproto_proxy_check_coordinator_policy.h"
#include "test_check.h"

#include <iostream>

int main() {
	using MTP::details::ProxyCheckCoordinatorState;

	auto state = ProxyCheckCoordinatorState();
	TEST_CHECK(state.valid());
	TEST_CHECK(state.active() == 0);
	TEST_CHECK(state.canStart(2));
	TEST_CHECK(state.start(2));
	TEST_CHECK(state.start(2));
	TEST_CHECK(!state.start(2));
	TEST_CHECK(state.active() == 2);

	TEST_CHECK(state.finish(false));
	TEST_CHECK(state.active() == 2);
	TEST_CHECK(state.finish(true));
	TEST_CHECK(state.active() == 1);
	TEST_CHECK(state.finish(true));
	TEST_CHECK(state.active() == 0);
	TEST_CHECK(!state.finish(true));
	TEST_CHECK(state.active() == 0);
	TEST_CHECK(state.valid());

	std::cout << "Production proxy-check coordinator policy tests passed.\n";
}
