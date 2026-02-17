#include "vault.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

#include <sodium.h>

namespace pwman {
namespace {
constexpr std::size_t kMagicSize = 8;
constexpr std::size_t kHeaderSize = kMagicSize + sizeof(std::uint32_t) + sizeof(std::uint64_t) +
                                    sizeof(std::uint64_t) + sizeof(std::int32_t) +
                                    crypto_pwhash_SALTBYTES +
                                    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

void write_u32(std::vector<unsigned char>& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xff));
    }
}

void write_u64(std::vector<unsigned char>& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xff));
    }
}

void write_i32(std::vector<unsigned char>& out, std::int32_t value) {
    write_u32(out, static_cast<std::uint32_t>(value));
}

std::uint32_t read_u32(const std::vector<unsigned char>& in, std::size_t& offset) {
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(in.at(offset++)) << (i * 8);
    }
    return value;
}

std::uint64_t read_u64(const std::vector<unsigned char>& in, std::size_t& offset) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(in.at(offset++)) << (i * 8);
    }
    return value;
}

std::int32_t read_i32(const std::vector<unsigned char>& in, std::size_t& offset) {
    return static_cast<std::int32_t>(read_u32(in, offset));
}

void ensure_sodium() {
    static bool initialized = false;
    if (!initialized) {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialization failed");
        }
        initialized = true;
    }
}

std::vector<unsigned char> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("unable to open vault file: " + path);
    }
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(in), {});
}

void write_file(const std::string& path, const std::vector<unsigned char>& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("unable to write vault file: " + path);
    }
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

int find_entry(const nlohmann::json& payload, const std::string& name) {
    const auto& entries = payload.at("entries");
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (entries.at(i).at("name").get<std::string>() == name) {
            return static_cast<int>(i);
        }
    }
    return -1;
}
} // namespace

Vault::Vault(std::string file_path) : file_path_(std::move(file_path)) { ensure_sodium(); }

void Vault::init(const std::string& master_password) {
    VaultHeader header;
    header.salt.resize(crypto_pwhash_SALTBYTES);
    header.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(header.salt.data(), header.salt.size());
    randombytes_buf(header.nonce.data(), header.nonce.size());

    nlohmann::json payload = {{"entries", nlohmann::json::array()}};
    encrypt_and_write(header, payload, master_password);
}

Vault::DecodedVault Vault::read_and_decrypt(const std::string& master_password) {
    auto raw = read_file(file_path_);
    if (raw.size() < kHeaderSize + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw std::runtime_error("vault file too small or corrupted");
    }

    std::vector<unsigned char> header_bytes(raw.begin(), raw.begin() + static_cast<long>(kHeaderSize));
    std::vector<unsigned char> cipher_bytes(raw.begin() + static_cast<long>(kHeaderSize), raw.end());
    auto header = deserialize_header(header_bytes);

    std::vector<unsigned char> key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    if (crypto_pwhash(key.data(),
                      key.size(),
                      master_password.c_str(),
                      master_password.size(),
                      header.salt.data(),
                      header.opslimit,
                      header.memlimit,
                      header.alg) != 0) {
        throw std::runtime_error("failed to derive key");
    }

    std::vector<unsigned char> plaintext(cipher_bytes.size());
    unsigned long long plaintext_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext.data(),
                                                   &plaintext_len,
                                                   nullptr,
                                                   cipher_bytes.data(),
                                                   cipher_bytes.size(),
                                                   header_bytes.data(),
                                                   header_bytes.size(),
                                                   header.nonce.data(),
                                                   key.data()) != 0) {
        sodium_memzero(key.data(), key.size());
        throw std::runtime_error("authentication failed (wrong password or tampered vault)");
    }

    sodium_memzero(key.data(), key.size());

    plaintext.resize(static_cast<std::size_t>(plaintext_len));
    nlohmann::json payload = nlohmann::json::parse(plaintext.begin(), plaintext.end());

    return DecodedVault{header, payload};
}

void Vault::encrypt_and_write(VaultHeader& header,
                              const nlohmann::json& payload,
                              const std::string& master_password) {
    std::vector<unsigned char> key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    if (crypto_pwhash(key.data(),
                      key.size(),
                      master_password.c_str(),
                      master_password.size(),
                      header.salt.data(),
                      header.opslimit,
                      header.memlimit,
                      header.alg) != 0) {
        throw std::runtime_error("failed to derive key");
    }

    randombytes_buf(header.nonce.data(), header.nonce.size());

    const std::string payload_text = payload.dump(2);
    std::vector<unsigned char> plaintext(payload_text.begin(), payload_text.end());
    std::vector<unsigned char> header_bytes = serialize_header(header);

    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(),
                                               &ciphertext_len,
                                               plaintext.data(),
                                               plaintext.size(),
                                               header_bytes.data(),
                                               header_bytes.size(),
                                               nullptr,
                                               header.nonce.data(),
                                               key.data());

    sodium_memzero(key.data(), key.size());

    ciphertext.resize(static_cast<std::size_t>(ciphertext_len));

    std::vector<unsigned char> out;
    out.reserve(header_bytes.size() + ciphertext.size());
    out.insert(out.end(), header_bytes.begin(), header_bytes.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    write_file(file_path_, out);
}

std::vector<unsigned char> Vault::serialize_header(const VaultHeader& header) {
    std::vector<unsigned char> out;
    out.reserve(kHeaderSize);

    std::string magic = header.magic;
    magic.resize(kMagicSize, '\0');
    out.insert(out.end(), magic.begin(), magic.end());

    write_u32(out, header.version);
    write_u64(out, header.opslimit);
    write_u64(out, header.memlimit);
    write_i32(out, header.alg);

    if (header.salt.size() != crypto_pwhash_SALTBYTES ||
        header.nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        throw std::runtime_error("invalid header salt/nonce size");
    }

    out.insert(out.end(), header.salt.begin(), header.salt.end());
    out.insert(out.end(), header.nonce.begin(), header.nonce.end());
    return out;
}

VaultHeader Vault::deserialize_header(const std::vector<unsigned char>& bytes) {
    if (bytes.size() != kHeaderSize) {
        throw std::runtime_error("invalid header size");
    }

    VaultHeader header;
    std::size_t offset = 0;

    header.magic.assign(bytes.begin(), bytes.begin() + static_cast<long>(kMagicSize));
    header.magic.erase(std::find(header.magic.begin(), header.magic.end(), '\0'), header.magic.end());
    offset += kMagicSize;

    if (header.magic != "PWMAN01") {
        throw std::runtime_error("invalid vault magic");
    }

    header.version = read_u32(bytes, offset);
    if (header.version != 1) {
        throw std::runtime_error("unsupported vault version");
    }

    header.opslimit = read_u64(bytes, offset);
    header.memlimit = read_u64(bytes, offset);
    header.alg = read_i32(bytes, offset);

    header.salt.assign(bytes.begin() + static_cast<long>(offset),
                       bytes.begin() + static_cast<long>(offset + crypto_pwhash_SALTBYTES));
    offset += crypto_pwhash_SALTBYTES;
    header.nonce.assign(bytes.begin() + static_cast<long>(offset),
                        bytes.begin() + static_cast<long>(offset + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES));

    return header;
}

void Vault::add(const std::string& name,
                const std::string& username,
                const std::string& password,
                const std::string& notes,
                const std::string& master_password) {
    auto dv = read_and_decrypt(master_password);
    if (find_entry(dv.payload, name) >= 0) {
        throw std::runtime_error("entry already exists: " + name);
    }

    dv.payload["entries"].push_back({{"name", name},
                                      {"username", username},
                                      {"password", password},
                                      {"notes", notes},
                                      {"updated_at", now_iso8601()}});
    encrypt_and_write(dv.header, dv.payload, master_password);
}

nlohmann::json Vault::get(const std::string& name, const std::string& master_password) {
    auto dv = read_and_decrypt(master_password);
    int idx = find_entry(dv.payload, name);
    if (idx < 0) {
        throw std::runtime_error("entry not found: " + name);
    }
    return dv.payload["entries"][idx];
}

nlohmann::json Vault::list(const std::string& master_password) {
    auto dv = read_and_decrypt(master_password);
    return dv.payload["entries"];
}

void Vault::update(const std::string& name,
                   const std::optional<std::string>& username,
                   const std::optional<std::string>& password,
                   const std::optional<std::string>& notes,
                   const std::string& master_password) {
    auto dv = read_and_decrypt(master_password);
    int idx = find_entry(dv.payload, name);
    if (idx < 0) {
        throw std::runtime_error("entry not found: " + name);
    }

    auto& item = dv.payload["entries"][idx];
    if (username) item["username"] = *username;
    if (password) item["password"] = *password;
    if (notes) item["notes"] = *notes;
    item["updated_at"] = now_iso8601();

    encrypt_and_write(dv.header, dv.payload, master_password);
}

void Vault::remove(const std::string& name, const std::string& master_password) {
    auto dv = read_and_decrypt(master_password);
    auto& entries = dv.payload["entries"];
    int idx = find_entry(dv.payload, name);
    if (idx < 0) {
        throw std::runtime_error("entry not found: " + name);
    }
    entries.erase(entries.begin() + idx);
    encrypt_and_write(dv.header, dv.payload, master_password);
}

std::string now_iso8601() {
    const auto now = std::chrono::system_clock::now();
    const auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string generate_password(std::size_t length) {
    static const std::string charset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.?";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::size_t> dist(0, charset.size() - 1);

    std::string out;
    out.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        out.push_back(charset[dist(gen)]);
    }
    return out;
}

} // namespace pwman

