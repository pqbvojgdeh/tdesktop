#include "mtproto/details/mtproto_client_hello_validation.h"

#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <span>
#include <vector>

namespace {

using Bytes = std::vector<std::byte>;

[[noreturn]] void Fail(const char *message) {
	std::cerr << message << std::endl;
	std::exit(1);
}

void Expect(bool condition, const char *message) {
	if (!condition) {
		Fail(message);
	}
}

void Byte(Bytes &to, std::size_t value) {
	to.push_back(std::byte(value & 0xFF));
}

void U16(Bytes &to, std::size_t value) {
	Byte(to, value >> 8);
	Byte(to, value);
}

void U24(Bytes &to, std::size_t value) {
	Byte(to, value >> 16);
	Byte(to, value >> 8);
	Byte(to, value);
}

void Zeros(Bytes &to, std::size_t count) {
	to.insert(to.end(), count, std::byte(0));
}

void Extension(Bytes &to, unsigned type, const Bytes &content) {
	U16(to, type);
	U16(to, content.size());
	to.insert(to.end(), content.begin(), content.end());
}

[[nodiscard]] Bytes MakeKeyShares(bool validP256) {
	auto entries = Bytes();
	U16(entries, 0x001D);
	U16(entries, 32);
	Zeros(entries, 32);
	U16(entries, 0x0017);
	U16(entries, 65);
	Byte(entries, validP256 ? 0x04 : 0x03);
	Zeros(entries, 64);
	auto result = Bytes();
	U16(result, entries.size());
	result.insert(result.end(), entries.begin(), entries.end());
	return result;
}

[[nodiscard]] Bytes MakePsk() {
	auto result = Bytes();
	U16(result, 7);
	U16(result, 1);
	Byte(result, 0x42);
	Zeros(result, 4);
	U16(result, 33);
	Byte(result, 32);
	Zeros(result, 32);
	return result;
}

[[nodiscard]] Bytes MakeHello(
		bool resumed,
		bool validP256 = true,
		bool extensionAfterPsk = false) {
	auto extensions = Bytes();
	Extension(extensions, 0x0033, MakeKeyShares(validP256));
	if (resumed) {
		Extension(extensions, 0x0029, MakePsk());
	}
	if (extensionAfterPsk) {
		Extension(extensions, 0x0017, {});
	}

	auto body = Bytes();
	Byte(body, 0x03);
	Byte(body, 0x03);
	Zeros(body, 32);
	Byte(body, 0);
	U16(body, 2);
	U16(body, 0x1301);
	Byte(body, 1);
	Byte(body, 0);
	U16(body, extensions.size());
	body.insert(body.end(), extensions.begin(), extensions.end());

	auto result = Bytes();
	Byte(result, 0x16);
	Byte(result, 0x03);
	Byte(result, 0x01);
	U16(result, body.size() + 4);
	Byte(result, 0x01);
	U24(result, body.size());
	result.insert(result.end(), body.begin(), body.end());
	return result;
}

[[nodiscard]] MTP::details::ClientHelloValidation Validate(
		const Bytes &hello,
		int resumed) {
	return MTP::details::ValidateClientHello(
		std::span<const std::byte>(hello),
		resumed);
}

} // namespace

int main() {
	const auto fresh = MakeHello(false);
	const auto freshResult = Validate(fresh, 0);
	Expect(freshResult.valid, "A structurally valid fresh ClientHello must pass.");
	Expect(!freshResult.resumed, "A fresh ClientHello must not contain PSK.");
	Expect(freshResult.hasP256KeyShare,
		"The P-256 key share must be recognized.");

	const auto resumed = MakeHello(true);
	const auto resumedResult = Validate(resumed, 1);
	Expect(resumedResult.valid,
		"A structurally valid resumed ClientHello must pass.");
	Expect(resumedResult.resumed,
		"A resumed ClientHello must contain a final PSK extension.");
	Expect(!Validate(fresh, 1).valid,
		"Fresh output must not pass as resumed output.");

	auto badLength = fresh;
	badLength[4] ^= std::byte(1);
	Expect(!Validate(badLength, 0).valid,
		"A mismatched TLS record length must fail.");
	Expect(!Validate(MakeHello(false, false), 0).valid,
		"A P-256 share without uncompressed-point encoding must fail.");
	Expect(!Validate(MakeHello(true, true, true), 1).valid,
		"The pre-shared-key extension must be last.");

	std::cout << "ClientHello validation tests passed." << std::endl;
	return 0;
}
