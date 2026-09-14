#pragma once
#include <vanetza_idf/credentials.hpp>
#include <string>

/** CredentialStore on ESP-IDF non-volatile storage (the nvs_flash component).
 *
 * One bundle (credentials.hpp) as one NVS blob under a namespace and key of the
 * application's choosing. The application initialises NVS itself
 * (nvs_flash_init or nvs_flash_secure_init) before using the store; whether the
 * private keys rest encrypted is the application's NVS/flash encryption
 * configuration (ESP-IDF "NVS Encryption"), not this class's doing. Built with
 * CONFIG_VANETZA_IDF_NVS_CREDENTIALS (default on with the security entity).
 */
namespace vanetza_idf::security {

class NvsCredentialStore final : public CredentialStore {
public:
    /// namespace_name up to 15 characters, key up to 15 characters (NVS limits)
    explicit NvsCredentialStore(std::string namespace_name = "vanetza_idf", std::string key = "credentials") :
        namespace_(std::move(namespace_name)), key_(std::move(key)) {}
    Result save(const Credentials&) override;
    Result load(Credentials&) override;
    Result erase() override;
private:
    std::string namespace_;
    std::string key_;
};

} // namespace vanetza_idf::security
