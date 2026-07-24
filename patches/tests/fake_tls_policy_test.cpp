#include "mtproto/details/mtproto_fake_tls_policy.h"
#include "test_check.h"

#include <array>
#include <cstdint>
#include <iostream>

int main() {
	using MTP::details::IsFakeTlsSecret;
	using MTP::details::kFakeTlsMinimumSecretSize;

	static_assert(kFakeTlsMinimumSecretSize == 21);

	auto empty = std::array<std::uint8_t, 0>();
	auto shortSecret = std::array<std::uint8_t, 20>();
	auto minimumSecret = std::array<std::uint8_t, 21>();
	auto longerSecret = std::array<std::uint8_t, 128>();

	shortSecret[0] = 0xEE;
	minimumSecret[0] = 0xEE;
	longerSecret[0] = 0xEE;

	TEST_CHECK(!IsFakeTlsSecret(empty));
	TEST_CHECK(!IsFakeTlsSecret(shortSecret));
	TEST_CHECK(IsFakeTlsSecret(minimumSecret));
	TEST_CHECK(IsFakeTlsSecret(longerSecret));

	minimumSecret[0] = 0xDD;
	TEST_CHECK(!IsFakeTlsSecret(minimumSecret));

	std::cout << "Production FakeTLS classification policy tests passed.\n";
}
