#include <vanetza_idf/nvs_credential_store.hpp>
#include <nvs.h>

namespace vanetza_idf::security {

namespace {
// nvs_open/nvs_close around one operation; NVS handles are cheap and the store is stateless
class Handle {
public:
    Handle(const std::string& ns, nvs_open_mode_t mode) { error_ = nvs_open(ns.c_str(), mode, &handle_); }
    ~Handle() { if (error_ == ESP_OK) nvs_close(handle_); }
    esp_err_t error() const { return error_; }
    nvs_handle_t get() const { return handle_; }
private:
    nvs_handle_t handle_ = 0;
    esp_err_t error_ = ESP_FAIL;
};
} // namespace

Result NvsCredentialStore::save(const Credentials& credentials) {
    const ByteBuffer bundle = encode(credentials);
    Handle nvs(namespace_, NVS_READWRITE);
    if (nvs.error() != ESP_OK) return Result::rejected;
    if (nvs_set_blob(nvs.get(), key_.c_str(), bundle.data(), bundle.size()) != ESP_OK) return Result::resource_limit;
    return nvs_commit(nvs.get()) == ESP_OK ? Result::accepted : Result::rejected;
}

Result NvsCredentialStore::load(Credentials& credentials) {
    Handle nvs(namespace_, NVS_READONLY);
    if (nvs.error() != ESP_OK) return Result::rejected; // no such namespace yet: nothing stored
    std::size_t size = 0;
    const esp_err_t probe = nvs_get_blob(nvs.get(), key_.c_str(), nullptr, &size);
    if (probe == ESP_ERR_NVS_NOT_FOUND) return Result::rejected;
    if (probe != ESP_OK || size == 0) return Result::rejected;
    ByteBuffer bundle(size);
    if (nvs_get_blob(nvs.get(), key_.c_str(), bundle.data(), &size) != ESP_OK) return Result::rejected;
    bundle.resize(size);
    return decode(bundle, credentials) ? Result::accepted : Result::invalid_argument;
}

Result NvsCredentialStore::erase() {
    Handle nvs(namespace_, NVS_READWRITE);
    if (nvs.error() != ESP_OK) return Result::rejected;
    const esp_err_t error = nvs_erase_key(nvs.get(), key_.c_str());
    if (error == ESP_ERR_NVS_NOT_FOUND) return Result::rejected;
    if (error != ESP_OK) return Result::rejected;
    return nvs_commit(nvs.get()) == ESP_OK ? Result::accepted : Result::rejected;
}

} // namespace vanetza_idf::security
