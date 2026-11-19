// schannel_groups.h -- reusable Schannel TLS key-establishment group control.
//
// Self-contained: no logging, no sockets, no console I/O. Depends only on the Windows SDK
// (secur32, crypt32, ncrypt, advapi32). Requires C++23 (std::expected).
//
// Typical server use:
//
//   auto os = schgroups::GetOsDefaultGroups();                           // std::expected<OsGroupList, wstring>
//   if (!os) return fail(os.error());
//   auto policy = schgroups::GroupPolicy::Build(os->groups, schgroups::Mode::EnableOnly,
//                                               {L"SecP384r1_MLKEM1024"});
//   if (!policy.valid()) return fail(...);
//   auto cred = schgroups::AcquireServerCredential(cert, policy, schgroups::kTls13OnlyServer);
//   if (!cred) return fail(cred.error());                                // SECURITY_STATUS
//   ... AcceptSecurityContext(cred->get(), ...) handshake loop ...
//   if (schgroups::ViolatesPolicy(&ctx, policy)) {                       // fail-closed enforcement
//       if (auto alert = schgroups::BuildFatalAlert(cred->get(), &ctx)) send(sock, *alert ...);
//       // close the connection
//   }
//
// Security notes:
//   * Per-credential disables use TLS_PARAMETERS.pDisabledCrypto (TlsParametersCngAlgUsageKeyExchange).
//     NIST curves map to the documented ECDH_P256/384/521 ids. curve25519 and the ML-KEM groups are
//     passed by group name, and in testing (Windows 11 24H2) Schannel honored X25519_MLKEM768 but
//     ignored SecP384r1_MLKEM1024 and MLKEM1024. Always pair the credential with ViolatesPolicy().
//   * ViolatesPolicy() runs AFTER the handshake. The connection is refused, but the client's first
//     flight of application data may already have been sent under the disallowed group. Only a group
//     Schannel itself refuses (or an OS-wide Disable-TlsEccCurve) prevents that.
//   * ViolatesPolicy() is an allowlist and fails closed: in Disable or EnableOnly mode, a
//     connection whose group is unknown, unreported (e.g. TLS 1.2 RSA/DHE key exchange) or not in the
//     enabled set is a violation.
//   * With an ECDSA server cert, handshakes offering only ML-KEM groups failed with
//     SEC_E_ALGORITHM_MISMATCH in testing; an RSA cert works.
//
// Thread safety: GroupPolicy and Credential are immutable after construction; concurrent reads are safe.

#pragma once

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#ifndef SCHANNEL_USE_BLACKLISTS
#define SCHANNEL_USE_BLACKLISTS  // must be defined before the first include of schannel.h
#endif
#include <windows.h>
#include <winternl.h>  // UNICODE_STRING
#include <wincrypt.h>
#include <schannel.h>
#include <security.h>

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace schgroups {

// ---- group catalog ---------------------------------------------------------------------------
struct KnownGroup {
    const wchar_t* winName;  // Windows spelling (Get-TlsEccCurve)
    uint16_t       id;       // IANA TLS NamedGroup code point
    const char*    iana;     // IANA / OpenSSL name
    const wchar_t* cngAlg;   // documented CNG alg id for CRYPTO_SETTINGS, or nullptr
};

[[nodiscard]] std::span<const KnownGroup> KnownGroups() noexcept;
[[nodiscard]] const KnownGroup* FindGroup(std::wstring_view nameOrAlias);  // Windows/IANA/OpenSSL name; case, '_', '-' ignored
[[nodiscard]] const KnownGroup* FindGroup(uint32_t tlsGroupId) noexcept;
[[nodiscard]] bool              SameGroup(std::wstring_view a, std::wstring_view b);
[[nodiscard]] std::wstring      NormalizeName(std::wstring_view s);        // lower-case, '_' and '-' removed

// ---- OS default list -------------------------------------------------------------------------
struct OsGroupList {
    std::vector<std::wstring> groups;  // in OS preference order
    std::wstring              source;  // L"Group Policy", L"Get-TlsEccCurve" or L"SslEnumEccCurves"
};

// Order of precedence: GPO 'ECC Curve Order' -> Get-TlsEccCurve (PowerShell) -> SslEnumEccCurves.
[[nodiscard]] std::expected<OsGroupList, std::wstring> GetOsDefaultGroups();

// ---- policy ----------------------------------------------------------------------------------
enum class Mode {
    Defaults,    // use the base list unchanged
    Disable,     // base list minus the named groups
    EnableOnly,  // only the named groups (everything else in the base list is disabled)
};

class GroupPolicy {
public:
    GroupPolicy() = default;

    // Both restriction modes require a base list and names. Disable rejects any unmatched name.
    // EnableOnly skips unmatched names with a warning and rejects an empty intersection.
    [[nodiscard]] static GroupPolicy Build(const std::vector<std::wstring>& baseGroups, Mode mode,
                                           const std::vector<std::wstring>& names,
                                           std::vector<std::wstring>* warnings = nullptr);

    [[nodiscard]] bool valid() const noexcept { return valid_; }
    [[nodiscard]] bool Restricts() const noexcept { return mode_ != Mode::Defaults; }
    [[nodiscard]] const std::vector<std::wstring>& Base() const noexcept { return base_; }
    [[nodiscard]] const std::vector<std::wstring>& Disabled() const noexcept { return disabled_; }  // OS spellings
    [[nodiscard]] const std::vector<std::wstring>& DisabledAlgIds() const noexcept { return algIds_; }
    [[nodiscard]] std::vector<std::wstring>        Enabled() const;
    [[nodiscard]] bool IsDisabled(std::wstring_view group) const;

    // Only Defaults allows everything. An explicit restriction requires a known, enabled base
    // group even when nothing had to be disabled in the credential. An invalid policy denies all.
    [[nodiscard]] bool Allows(std::optional<uint32_t> tlsGroupId) const;

private:
    std::vector<std::wstring> base_, disabled_, algIds_;
    Mode                      mode_ = Mode::Defaults;
    bool                      valid_ = true;
};

// ---- credentials -----------------------------------------------------------------------------
constexpr DWORD kTls13OnlyServer = SP_PROT_SSL2_SERVER | SP_PROT_SSL3_SERVER | SP_PROT_TLS1_0_SERVER |
                                   SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_2_SERVER;
constexpr DWORD kTls12PlusServer = SP_PROT_SSL2_SERVER | SP_PROT_SSL3_SERVER | SP_PROT_TLS1_0_SERVER |
                                   SP_PROT_TLS1_1_SERVER;

// Owns an SCH_CREDENTIALS + TLS_PARAMETERS + CRYPTO_SETTINGS block carrying a policy, for callers
// that call AcquireCredentialsHandle themselves (client side, extra flags, ...). It copies what it
// needs from the policy and the cert array, so it has no lifetime ties to either. Not copyable or
// movable (the structures point into the object).
class SchCredentialData {
public:
    // Throws std::invalid_argument rather than constructing a credential block for an invalid policy.
    SchCredentialData(std::span<const PCCERT_CONTEXT> certs, const GroupPolicy& policy, DWORD disabledProtocols,
                      DWORD schFlags = SCH_USE_STRONG_CRYPTO);
    SchCredentialData(const SchCredentialData&) = delete;
    SchCredentialData& operator=(const SchCredentialData&) = delete;

    [[nodiscard]] SCH_CREDENTIALS* get() noexcept { return &sc_; }
    [[nodiscard]] TLS_PARAMETERS&  tls() noexcept { return tp_; }

private:
    std::vector<std::wstring>    algIds_;
    std::vector<CRYPTO_SETTINGS> settings_;
    std::vector<PCCERT_CONTEXT>  certs_;
    TLS_PARAMETERS               tp_{};
    SCH_CREDENTIALS              sc_{};
};

// Move-only owner of an SSPI credential handle (FreeCredentialsHandle on destruction).
class Credential {
public:
    Credential() noexcept = default;
    explicit Credential(const CredHandle& h) noexcept : h_(h) {}
    Credential(Credential&& o) noexcept : h_(std::exchange(o.h_, kInvalid)) {}
    Credential& operator=(Credential&& o) noexcept {
        if (this != &o) { reset(); h_ = std::exchange(o.h_, kInvalid); }
        return *this;
    }
    ~Credential() { reset(); }

    void reset() noexcept;
    [[nodiscard]] explicit operator bool() const noexcept { return h_.dwLower != kInvalid.dwLower && h_.dwUpper != kInvalid.dwUpper; }
    // SSPI takes a non-const pointer but does not modify the handle.
    [[nodiscard]] PCredHandle get() const noexcept { return const_cast<PCredHandle>(&h_); }

private:
    static constexpr CredHandle kInvalid{static_cast<ULONG_PTR>(-1), static_cast<ULONG_PTR>(-1)};
    CredHandle h_ = kInvalid;
};

// AcquireCredentialsHandleW(SECPKG_CRED_INBOUND) with the policy applied. disabledProtocols goes into
// TLS_PARAMETERS.grbitDisabledProtocols. Fails with SEC_E_NO_CREDENTIALS for a null cert and
// SEC_E_ALGORITHM_MISMATCH for an invalid policy.
[[nodiscard]] std::expected<Credential, SECURITY_STATUS> AcquireServerCredential(
    PCCERT_CONTEXT cert, const GroupPolicy& policy, DWORD disabledProtocols, DWORD schFlags = SCH_USE_STRONG_CRYPTO);

// ---- post-handshake --------------------------------------------------------------------------
// Negotiated TLS NamedGroup code point (SECPKG_ATTR_CIPHER_INFO.dwKeyType); nullopt if the query
// fails or no group is reported.
[[nodiscard]] std::optional<uint32_t> NegotiatedGroup(PCtxtHandle ctx) noexcept;

// True unless policy.Allows() the group this context negotiated. Fails closed; see the notes above.
[[nodiscard]] bool ViolatesPolicy(PCtxtHandle ctx, const GroupPolicy& policy);

// Builds an (encrypted) fatal TLS alert record for an established server context. The caller sends
// the bytes, then deletes the context.
[[nodiscard]] std::expected<std::vector<uint8_t>, SECURITY_STATUS> BuildFatalAlert(
    PCredHandle cred, PCtxtHandle ctx, DWORD alert = TLS1_ALERT_HANDSHAKE_FAILURE);

}  // namespace schgroups
