#include "vault.hpp"

#include <iostream>
#include <optional>
#include <stdexcept>

namespace {
void print_usage() {
    std::cout << "pwman <vault-file> <command> [args]\n"
              << "Commands:\n"
              << "  init <master_password>\n"
              << "  add <master_password> <name> <username> <password> [notes]\n"
              << "  get <master_password> <name>\n"
              << "  list <master_password>\n"
              << "  update <master_password> <name> [--username v] [--password v] [--notes v]\n"
              << "  remove <master_password> <name>\n"
              << "  gen [length]\n";
}

std::optional<std::string> read_opt(int argc, char** argv, const std::string& flag) {
    for (int i = 0; i < argc - 1; ++i) {
        if (flag == argv[i]) {
            return argv[i + 1];
        }
    }
    return std::nullopt;
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 3) {
            print_usage();
            return 1;
        }

        const std::string vault_file = argv[1];
        const std::string cmd = argv[2];

        if (cmd == "gen") {
            std::size_t len = 20;
            if (argc >= 4) {
                len = static_cast<std::size_t>(std::stoul(argv[3]));
            }
            std::cout << pwman::generate_password(len) << '\n';
            return 0;
        }

        pwman::Vault vault(vault_file);

        if (cmd == "init") {
            if (argc < 4) throw std::runtime_error("init requires <master_password>");
            vault.init(argv[3]);
            std::cout << "vault initialized\n";
        } else if (cmd == "add") {
            if (argc < 8) throw std::runtime_error("add requires <master_password> <name> <username> <password> [notes]");
            const std::string notes = argc >= 9 ? argv[8] : "";
            vault.add(argv[4], argv[5], argv[6], notes, argv[3]);
            std::cout << "entry added\n";
        } else if (cmd == "get") {
            if (argc < 5) throw std::runtime_error("get requires <master_password> <name>");
            auto entry = vault.get(argv[4], argv[3]);
            std::cout << entry.dump(2) << '\n';
        } else if (cmd == "list") {
            if (argc < 4) throw std::runtime_error("list requires <master_password>");
            auto entries = vault.list(argv[3]);
            for (const auto& e : entries) {
                std::cout << e.at("name") << " (" << e.at("username") << ")\n";
            }
        } else if (cmd == "update") {
            if (argc < 5) throw std::runtime_error("update requires <master_password> <name>");
            auto username = read_opt(argc - 5, argv + 5, "--username");
            auto password = read_opt(argc - 5, argv + 5, "--password");
            auto notes = read_opt(argc - 5, argv + 5, "--notes");
            if (!username && !password && !notes) {
                throw std::runtime_error("update requires at least one field to update");
            }
            vault.update(argv[4], username, password, notes, argv[3]);
            std::cout << "entry updated\n";
        } else if (cmd == "remove") {
            if (argc < 5) throw std::runtime_error("remove requires <master_password> <name>");
            vault.remove(argv[4], argv[3]);
            std::cout << "entry removed\n";
        } else {
            throw std::runtime_error("unknown command: " + cmd);
        }

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << '\n';
        return 1;
    }
}

