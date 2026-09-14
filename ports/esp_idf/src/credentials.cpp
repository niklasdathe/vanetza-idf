#include <vanetza_idf/credentials.hpp>
#include <cstdio>
#include <fstream>
#include <iterator>

namespace vanetza_idf::security {
using vanetza::security::KeyType;

namespace {
constexpr std::uint8_t magic[4] = {'V', 'C', 'R', '1'};
enum Record : std::uint8_t { root = 1, authority = 2, ticket = 3, ticket_key = 4 };

std::uint8_t curve_code(KeyType type) {
    switch (type) {
        case KeyType::NistP256: return 1;
        case KeyType::BrainpoolP256r1: return 2;
        case KeyType::BrainpoolP384r1: return 3;
        default: return 0;
    }
}
KeyType curve_type(std::uint8_t code) {
    switch (code) {
        case 1: return KeyType::NistP256;
        case 2: return KeyType::BrainpoolP256r1;
        case 3: return KeyType::BrainpoolP384r1;
        default: return KeyType::Unspecified;
    }
}
void put(ByteBuffer& out, std::uint8_t type, const ByteBuffer& payload) {
    out.push_back(type);
    out.push_back(static_cast<std::uint8_t>(payload.size() >> 8));
    out.push_back(static_cast<std::uint8_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
}
} // namespace

ByteBuffer encode(const Credentials& credentials) {
    ByteBuffer out(std::begin(magic), std::end(magic));
    for (const auto& coer : credentials.roots) put(out, Record::root, coer);
    for (const auto& coer : credentials.authorities) put(out, Record::authority, coer);
    for (const auto& t : credentials.tickets) {
        put(out, Record::ticket, t.certificate);
        ByteBuffer key {curve_code(t.key.type)};
        key.insert(key.end(), t.key.key.begin(), t.key.key.end());
        put(out, Record::ticket_key, key);
    }
    return out;
}

bool decode(const ByteBuffer& bundle, Credentials& out) {
    if (bundle.size() < sizeof(magic) || !std::equal(std::begin(magic), std::end(magic), bundle.begin())) return false;
    Credentials parsed;
    bool key_pending = false; // a ticket certificate awaits its key record
    std::size_t at = sizeof(magic);
    while (at < bundle.size()) {
        if (bundle.size() - at < 3) return false;
        const std::uint8_t type = bundle[at];
        const std::size_t length = (static_cast<std::size_t>(bundle[at + 1]) << 8) | bundle[at + 2];
        at += 3;
        if (bundle.size() - at < length || length == 0) return false;
        ByteBuffer payload(bundle.begin() + at, bundle.begin() + at + length);
        at += length;
        if (key_pending && type != Record::ticket_key) return false;
        switch (type) {
            case Record::root: parsed.roots.push_back(std::move(payload)); break;
            case Record::authority: parsed.authorities.push_back(std::move(payload)); break;
            case Record::ticket:
                parsed.tickets.push_back(Credentials::Ticket {std::move(payload), PrivateKey {}});
                key_pending = true;
                break;
            case Record::ticket_key: {
                if (!key_pending) return false;
                const KeyType curve = curve_type(payload[0]);
                if (curve == KeyType::Unspecified || payload.size() - 1 != vanetza::security::key_length(curve)) return false;
                auto& key = parsed.tickets.back().key;
                key.type = curve;
                key.key.assign(payload.begin() + 1, payload.end());
                key_pending = false;
                break;
            }
            default:
                return false;
        }
    }
    if (key_pending) return false;
    out = std::move(parsed);
    return true;
}

ApplyReport apply(const Credentials& credentials, TrustConfiguration& trust, CertificatePool& pool) {
    ApplyReport report;
    for (const auto& coer : credentials.roots) {
        if ((report.result = trust.add_root(coer)) != Result::accepted) return report;
        ++report.roots;
    }
    for (const auto& coer : credentials.authorities) {
        if ((report.result = trust.add_authority(coer)) != Result::accepted) return report;
        ++report.authorities;
    }
    for (const auto& t : credentials.tickets) {
        if ((report.result = pool.add(t.certificate, t.key)) != Result::accepted) return report;
        ++report.tickets;
    }
    return report;
}

Result FileCredentialStore::save(const Credentials& credentials) {
    const ByteBuffer bundle = encode(credentials);
    std::ofstream out(path_, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bundle.data()), bundle.size());
    return out ? Result::accepted : Result::rejected;
}

Result FileCredentialStore::load(Credentials& credentials) {
    std::ifstream in(path_, std::ios::binary);
    if (!in) return Result::rejected;
    const ByteBuffer bundle(std::istreambuf_iterator<char>(in), {});
    return decode(bundle, credentials) ? Result::accepted : Result::invalid_argument;
}

Result FileCredentialStore::erase() {
    return std::remove(path_.c_str()) == 0 ? Result::accepted : Result::rejected;
}

} // namespace vanetza_idf::security
