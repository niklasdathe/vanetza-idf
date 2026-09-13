#pragma once
// Backend used by the security entity tests: OpenSSL on the host (the oracle),
// the PSA backend on a device or when only that one is built.
#if VIDF_BACKEND_OPENSSL
#include <vanetza/security/backend_openssl.hpp>
namespace vidf_test { using TestBackend = vanetza::security::BackendOpenSsl; }
#else
#include <vanetza_idf/backend_mbedtls.hpp>
namespace vidf_test { using TestBackend = vanetza_idf::BackendMbedTls; }
#endif
