#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace pwman {

struct VaultHeader {
    std::string magic = "PWMAN01";
    std::uint32_t version = 1;
    std::uint64_t opslimit = 3;
    std::uint64_t memlimit = 268435456; // 256 MiB
    std::int32_t alg = 2; // crypto_pwhash_ALG_ARGON2ID13
    std::vector<unsigned char> salt;
    std::vector<unsigned char> nonce;
};

class Vault {
  public:
    explicit Vault(std::string file_path);

    void init(const std::string& master_password);
    void add(const std::string& name,
             const std::string& username,
             const std::string& password,
             const std::string& notes,
             const std::string& master_password);
    nlohmann::json get(const std::string& name, const std::string& master_password);
    nlohmann::json list(const std::string& master_password);
    void update(const std::string& name,
                const std::optional<std::string>& username,
                const std::optional<std::string>& password,
                const std::optional<std::string>& notes,
                const std::string& master_password);
    void remove(const std::string& name, const std::string& master_password);

  private:
    std::string file_path_;

    struct DecodedVault {
        VaultHeader header;
        nlohmann::json payload;
    };

    DecodedVault read_and_decrypt(const std::string& master_password);
    void encrypt_and_write(VaultHeader& header,
                           const nlohmann::json& payload,
                           const std::string& master_password);
    static std::vector<unsigned char> serialize_header(const VaultHeader& header);
    static VaultHeader deserialize_header(const std::vector<unsigned char>& bytes);
};

std::string now_iso8601();
std::string generate_password(std::size_t length);

} // namespace pwman

