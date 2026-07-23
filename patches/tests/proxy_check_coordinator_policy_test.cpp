#include "mtproto/details/mtproto_proxy_check_coordinator_policy.h"

#include <cassert>
#include <iostream>

int main() {
	using MTP::details::ProxyCheckCoordinatorState;

	auto state = ProxyCheckCoordinatorState();
	assert(state.valid());
	assert(state.active() == 0);
	assert(state.canStart(2));
	assert(state.start(2));
	assert(state.start(2));
	assert(!state.start(2));
	assert(state.active() == 2);

	assert(state.finish(false));
	assert(state.active() == 2);
	assert(state.finish(true));
	assert(state.active() == 1);
	assert(state.finish(true));
	assert(state.active() == 0);
	assert(!state.finish(true));
	assert(state.active() == 0);
	assert(state.valid());

	std::cout << "Production proxy-check coordinator policy tests passed.\n";
}
