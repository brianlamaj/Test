#include "vault.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

int main() {
    try {
        const std::string vault_file = "test.vault";
        const std::string pw = "correct horse battery staple";

        if (std::filesystem::exists(vault_file)) {
            std::filesystem::remove(vault_file);
        }

        pwman::Vault vault(vault_file);
        vault.init(pw);
        vault.add("github", "alice", "s3cr3t", "note", pw);

        auto entry = vault.get("github", pw);
        if (entry.at("username") != "alice" || entry.at("password") != "s3cr3t") {
            std::cerr << "round-trip failed\n";
            return 1;
        }

        // Tamper with ciphertext and verify authentication failure.
        {
            std::ifstream in(vault_file, std::ios::binary);
            std::vector<char> bytes((std::istreambuf_iterator<char>(in)), {});
            bytes.back() ^= 0x01;
            std::ofstream out(vault_file, std::ios::binary | std::ios::trunc);
            out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        }

        bool tamper_detected = false;
        try {
            (void)vault.list(pw);
        } catch (const std::exception&) {
            tamper_detected = true;
        }

        if (!tamper_detected) {
            std::cerr << "tamper detection failed\n";
            return 1;
        }

        std::filesystem::remove(vault_file);
        std::cout << "crypto tests passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "test error: " << ex.what() << '\n';
        return 1;
    }
}

