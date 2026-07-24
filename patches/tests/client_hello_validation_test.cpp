#include "mtproto/details/mtproto_client_hello_validation.h"
#include "test_check.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {
using Bytes = std::vector<std::byte>;
void b(Bytes &v, std::uint8_t x) { v.push_back(std::byte(x)); }
void u16(Bytes &v, std::size_t x) {
	TEST_CHECK(x <= std::size_t{ 0xFFFF });
	b(v, static_cast<std::uint8_t>((x >> 8) & 0xFF));
	b(v, static_cast<std::uint8_t>(x & 0xFF));
}
void u24(Bytes &v, std::size_t x) {
	TEST_CHECK(x <= std::size_t{ 0xFFFFFF });
	b(v, static_cast<std::uint8_t>((x >> 16) & 0xFF));
	b(v, static_cast<std::uint8_t>((x >> 8) & 0xFF));
	b(v, static_cast<std::uint8_t>(x & 0xFF));
}
void extension(Bytes &v, std::uint16_t type, const Bytes &data) {
	u16(v, type); u16(v, data.size()); v.insert(v.end(), data.begin(), data.end());
}
Bytes keyShare(bool p256) {
	Bytes shares;
	u16(shares, p256 ? 0x0017 : 0x001D);
	u16(shares, p256 ? 65 : 32);
	if (p256) b(shares, 0x04);
	shares.resize(shares.size() + (p256 ? 64 : 32), std::byte(0x42));
	Bytes data; u16(data, shares.size()); data.insert(data.end(), shares.begin(), shares.end());
	return data;
}
Bytes makeHello(bool resumed, bool p256 = false) {
	Bytes extensions;
	extension(extensions, 0x0033, keyShare(p256));
	if (resumed) {
		extension(extensions, 0x002D, Bytes{std::byte(1), std::byte(1)});
		Bytes psk;
		u16(psk, 7);                 // identities vector length
		u16(psk, 1); b(psk, 0x42);  // one identity
		psk.insert(psk.end(), 4, std::byte(0));
		u16(psk, 2); b(psk, 1); b(psk, 0xAA); // one binder
		extension(extensions, 0x0029, psk);   // PSK must be last
	}

	Bytes body;
	u16(body, 0x0303);
	body.resize(body.size() + 32, std::byte(0x11));
	b(body, 0);                    // session id
	u16(body, 2); u16(body, 0x1301);
	b(body, 1); b(body, 0);        // compression
	u16(body, extensions.size());
	body.insert(body.end(), extensions.begin(), extensions.end());

	Bytes handshake; b(handshake, 1); u24(handshake, body.size());
	handshake.insert(handshake.end(), body.begin(), body.end());
	Bytes record; b(record, 0x16); b(record, 0x03); b(record, 0x01);
	u16(record, handshake.size()); record.insert(record.end(), handshake.begin(), handshake.end());
	return record;
}
} // namespace

int main() {
	using MTP::details::ValidateClientHello;
	const auto fresh = makeHello(false);
	const auto freshResult = ValidateClientHello(fresh, 0);
	TEST_CHECK(freshResult.valid && !freshResult.resumed && freshResult.hasKeyShare);

	const auto resumed = makeHello(true);
	const auto resumedResult = ValidateClientHello(resumed, 1);
	TEST_CHECK(resumedResult.valid && resumedResult.resumed);
	TEST_CHECK(!ValidateClientHello(resumed, 0).valid);

	const auto p256 = ValidateClientHello(makeHello(false, true), 0);
	TEST_CHECK(p256.valid && p256.hasP256KeyShare);

	auto malformed = fresh;
	malformed[4] = std::byte(0);
	TEST_CHECK(!ValidateClientHello(malformed, 0).valid);
	TEST_CHECK(!ValidateClientHello(std::span<const std::byte>(), -1).valid);

	std::cout << "ClientHello validation tests passed.\n";
}
