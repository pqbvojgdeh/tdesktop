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

[[nodiscard]] Bytes MakeKeyShares(bool validP256Encoding) {
	auto entries = Bytes();
	U16(entries, 0x001D);
	U16(entries, 32);
	Zeros(entries, 32);
	U16(entries, 0x0017);
	U16(entries, 65);
	Byte(entries, validP256Encoding ? 0x04 : 0x03);
	Zeros(entries, 64);
	auto result = Bytes();
	U16(result, entries.size());
	result.insert(result.end(), entries.begin(), entries.end());
	return result;
}

[[nodiscard]] Bytes MakePsk(bool extraBinder) {
	auto result = Bytes();
	U16(result, 7);
	U16(result, 1);
	Byte(result, 0x42);
	Zeros(result, 4);
	auto binders = Bytes();
	Byte(binders, 32);
	Zeros(binders, 32);
	if (extraBinder) {
		Byte(binders, 32);
		Zeros(binders, 32);
	}
	U16(result, binders.size());
	result.insert(result.end(), binders.begin(), binders.end());
	return result;
}

struct HelloOptions {
	bool resumed = false;
	bool validP256Encoding = true;
	bool extensionAfterPsk = false;
	bool emptyKeyShares = false;
	bool omitPskModes = false;
	bool extraBinder = false;
	bool duplicateKeyShare = false;
};

[[nodiscard]] Bytes MakeHello(HelloOptions options = {}) {
	auto extensions = Bytes();
	auto keyShares = options.emptyKeyShares
		? Bytes{ std::byte(0), std::byte(0) }
		: MakeKeyShares(options.validP256Encoding);
	Extension(extensions, 0x0033, keyShares);
	if (options.duplicateKeyShare) {
		Extension(extensions, 0x0033, keyShares);
	}
	if (options.resumed) {
		if (!options.omitPskModes) {
			Extension(
				extensions,
				0x002D,
				Bytes{ std::byte(1), std::byte(1) });
		}
		Extension(extensions, 0x0029, MakePsk(options.extraBinder));
	}
	if (options.extensionAfterPsk) {
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
	const auto fresh = MakeHello();
	const auto freshResult = Validate(fresh, 0);
	Expect(freshResult.valid, "A structurally valid fresh ClientHello must pass.");
	Expect(!freshResult.resumed, "A fresh ClientHello must not contain PSK.");
	Expect(freshResult.hasP256KeyShare,
		"The P-256 key share must be recognized.");

	const auto resumed = MakeHello({ .resumed = true });
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
	Expect(!Validate(MakeHello({ .validP256Encoding = false }), 0).valid,
		"A P-256 share without uncompressed-point encoding must fail.");
	Expect(!Validate(MakeHello({ .emptyKeyShares = true }), 0).valid,
		"An empty key-share list must fail.");
	Expect(!Validate(MakeHello({
		.resumed = true,
		.extensionAfterPsk = true,
	}), 1).valid,
		"The pre-shared-key extension must be last.");
	Expect(!Validate(MakeHello({
		.resumed = true,
		.omitPskModes = true,
	}), 1).valid,
		"A resumed ClientHello must advertise PSK DHE mode.");
	Expect(!Validate(MakeHello({
		.resumed = true,
		.extraBinder = true,
	}), 1).valid,
		"The identity and binder counts must match.");
	Expect(!Validate(MakeHello({ .duplicateKeyShare = true }), 0).valid,
		"A duplicate key-share extension must fail.");

	std::cout << "ClientHello validation tests passed." << std::endl;
	return 0;
}
