// schannel_groups.cpp -- see schannel_groups.h

#include "schannel_groups.h"

#include <ncrypt.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <iterator>
#include <optional>
#include <ranges>
#include <stdexcept>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef BCRYPT_ECDH_P256_ALGORITHM
#define BCRYPT_ECDH_P256_ALGORITHM L"ECDH_P256"
#define BCRYPT_ECDH_P384_ALGORITHM L"ECDH_P384"
#define BCRYPT_ECDH_P521_ALGORITHM L"ECDH_P521"
#endif
#ifndef SECPKGCONTEXT_CIPHERINFO_V1
#define SECPKGCONTEXT_CIPHERINFO_V1 1
#endif

namespace schgroups {
namespace {

constexpr KnownGroup kGroups[] = {
    {L"curve25519",          0x001D, "x25519",             nullptr},
    {L"NistP256",            0x0017, "secp256r1",          BCRYPT_ECDH_P256_ALGORITHM},
    {L"NistP384",            0x0018, "secp384r1",          BCRYPT_ECDH_P384_ALGORITHM},
    {L"NistP521",            0x0019, "secp521r1",          BCRYPT_ECDH_P521_ALGORITHM},
    {L"X25519_MLKEM768",     0x11EC, "X25519MLKEM768",     nullptr},
    {L"SecP256r1_MLKEM768",  0x11EB, "SecP256r1MLKEM768",  nullptr},
    {L"SecP384r1_MLKEM1024", 0x11ED, "SecP384r1MLKEM1024", nullptr},
    {L"MLKEM512",            0x0200, "MLKEM512",           nullptr},
    {L"MLKEM768",            0x0201, "MLKEM768",           nullptr},
    {L"MLKEM1024",           0x0202, "MLKEM1024",          nullptr},
};

std::wstring WideAscii(const char* s) {
    std::wstring w;
    for (; *s; ++s) w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*s)));
    return w;
}

std::wstring WideUtf8(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::vector<std::wstring> SplitWs(std::wstring_view s) {
    std::vector<std::wstring> out;
    std::wstring cur;
    for (wchar_t c : s) {
        if (std::iswspace(c) || c == L',') {
            if (!cur.empty()) out.push_back(std::move(cur)), cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

constexpr size_t kMaxAlgIdChars = 255;

UNICODE_STRING Us(const std::wstring& s) {
    UNICODE_STRING u{};
    u.Buffer = const_cast<PWSTR>(s.c_str());
    u.Length = static_cast<USHORT>(s.size() * sizeof(wchar_t));
    u.MaximumLength = static_cast<USHORT>(u.Length + sizeof(wchar_t));
    return u;
}

// ---- OS sources ------------------------------------------------------------------------------
constexpr wchar_t kPolicyKey[] = L"SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002";

std::optional<std::vector<std::wstring>> ReadPolicyCurves() {
    DWORD cb = 0;
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kPolicyKey, L"EccCurves", RRF_RT_REG_MULTI_SZ, nullptr, nullptr, &cb) != ERROR_SUCCESS)
        return std::nullopt;
    std::vector<wchar_t> buf(cb / sizeof(wchar_t) + 2, L'\0');
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kPolicyKey, L"EccCurves", RRF_RT_REG_MULTI_SZ, nullptr, buf.data(), &cb) != ERROR_SUCCESS)
        return std::nullopt;
    std::vector<std::wstring> out;
    for (const wchar_t* q = buf.data(); *q; q += wcslen(q) + 1) out.emplace_back(q);
    if (out.empty()) return std::nullopt;
    return out;
}

// Layout-identical to NCRYPT_SSL_ECC_CURVE (sslprovider.h); functions resolved from ncrypt.dll.
struct SslEccCurve {
    WCHAR szCurveName[255];
    CHAR  szOID[255];
    DWORD dwPublicKeyLength;
    DWORD dwCurveType;
    DWORD dwFlags;
};

std::optional<std::vector<std::wstring>> EnumProviderCurves(std::wstring& err) {
    using OpenFn  = LONG(WINAPI*)(NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
    using EnumFn  = LONG(WINAPI*)(NCRYPT_PROV_HANDLE, DWORD*, SslEccCurve**, DWORD);
    using FreeBuf = LONG(WINAPI*)(PVOID);
    using FreeObj = LONG(WINAPI*)(NCRYPT_HANDLE, DWORD);

    HMODULE h = LoadLibraryExW(L"ncrypt.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!h) { err = L"cannot load ncrypt.dll"; return std::nullopt; }
    auto open    = reinterpret_cast<OpenFn>(reinterpret_cast<void*>(GetProcAddress(h, "SslOpenProvider")));
    auto enumc   = reinterpret_cast<EnumFn>(reinterpret_cast<void*>(GetProcAddress(h, "SslEnumEccCurves")));
    auto freeBuf = reinterpret_cast<FreeBuf>(reinterpret_cast<void*>(GetProcAddress(h, "SslFreeBuffer")));
    auto freeObj = reinterpret_cast<FreeObj>(reinterpret_cast<void*>(GetProcAddress(h, "SslFreeObject")));
    if (!open || !enumc || !freeBuf || !freeObj) { err = L"ncrypt.dll lacks SslEnumEccCurves"; return std::nullopt; }

    NCRYPT_PROV_HANDLE prov = 0;
    if (open(&prov, L"Microsoft SSL Protocol Provider", 0) != 0) { err = L"SslOpenProvider failed"; return std::nullopt; }
    DWORD n = 0;
    SslEccCurve* p = nullptr;
    LONG st = enumc(prov, &n, &p, 0);
    std::vector<std::wstring> out;
    if (st == 0 && p)
        for (DWORD i = 0; i < n; ++i) out.emplace_back(p[i].szCurveName, wcsnlen(p[i].szCurveName, 255));
    if (p) freeBuf(p);
    freeObj(prov, 0);
    if (st != 0) { err = L"SslEnumEccCurves failed"; return std::nullopt; }
    return out;
}

std::wstring Base64(const unsigned char* d, size_t len) {
    static constexpr char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::wstring o;
    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        uint32_t v = (d[i] << 16) | (d[i + 1] << 8) | d[i + 2];
        o += t[(v >> 18) & 63]; o += t[(v >> 12) & 63]; o += t[(v >> 6) & 63]; o += t[v & 63];
    }
    if (i + 1 == len) {
        uint32_t v = d[i] << 16;
        o += t[(v >> 18) & 63]; o += t[(v >> 12) & 63]; o += L"==";
    } else if (i + 2 == len) {
        uint32_t v = (d[i] << 16) | (d[i + 1] << 8);
        o += t[(v >> 18) & 63]; o += t[(v >> 12) & 63]; o += t[(v >> 6) & 63]; o += L'=';
    }
    return o;
}

// Runs Get-TlsEccCurve in a child powershell.exe (stdout captured; only the pipe is inherited).
std::optional<std::vector<std::wstring>> GetTlsEccCurve(std::wstring& err) {
    wchar_t sysDir[MAX_PATH]{};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    const std::wstring exe = std::wstring(sysDir) + L"\\WindowsPowerShell\\v1.0\\powershell.exe";
    const std::wstring script =
        L"[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='Stop';"
        L"try { foreach ($c in @(Get-TlsEccCurve)) { foreach ($n in @($c)) { \"G:$n\" } } } "
        L"catch { \"E:$($_.Exception.Message)\"; exit 1 }";
    std::wstring cmd = L"\"" + exe + L"\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " +
                       Base64(reinterpret_cast<const unsigned char*>(script.data()), script.size() * sizeof(wchar_t));

    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) { err = L"CreatePipe failed"; return std::nullopt; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    std::vector<BYTE> attrBuf(attrSize);
    auto attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
    InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize);
    HANDLE inherit[] = {wr};
    UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit, sizeof(inherit), nullptr, nullptr);

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdOutput = wr;
    si.StartupInfo.hStdError = wr;
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                             nullptr, nullptr, &si.StartupInfo, &pi);
    DeleteProcThreadAttributeList(attrs);
    CloseHandle(wr);
    if (!ok) { CloseHandle(rd); err = L"cannot start powershell.exe"; return std::nullopt; }

    std::string out;
    char buf[4096];
    DWORD n = 0;
    while (ReadFile(rd, buf, sizeof(buf), &n, nullptr) && n) out.append(buf, n);
    CloseHandle(rd);
    if (WaitForSingleObject(pi.hProcess, 120'000) == WAIT_TIMEOUT) TerminateProcess(pi.hProcess, 1);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::vector<std::wstring> names;
    size_t pos = 0;
    while (pos < out.size()) {
        size_t e = out.find('\n', pos);
        std::string l = out.substr(pos, e == std::string::npos ? std::string::npos : e - pos);
        while (!l.empty() && (l.back() == '\r' || l.back() == ' ')) l.pop_back();
        if (l.size() >= 3 && static_cast<unsigned char>(l[0]) == 0xEF) l.erase(0, 3);  // UTF-8 BOM
        if (l.rfind("G:", 0) == 0)
            for (auto& g : SplitWs(WideUtf8(l.substr(2)))) names.push_back(std::move(g));
        else if (l.rfind("E:", 0) == 0)
            err = WideUtf8(l.substr(2));
        if (e == std::string::npos) break;
        pos = e + 1;
    }
    if (exitCode != 0 || names.empty()) {
        if (err.empty()) err = L"Get-TlsEccCurve returned nothing";
        return std::nullopt;
    }
    return names;
}

}  // namespace

// ---- catalog ---------------------------------------------------------------------------------
std::span<const KnownGroup> KnownGroups() noexcept { return kGroups; }

std::wstring NormalizeName(std::wstring_view s) {
    std::wstring r;
    r.reserve(s.size());
    for (wchar_t c : s)
        if (c != L'_' && c != L'-') r.push_back(static_cast<wchar_t>(std::towlower(c)));
    return r;
}

const KnownGroup* FindGroup(std::wstring_view nameOrAlias) {
    const auto n = NormalizeName(nameOrAlias);
    const auto it = std::ranges::find_if(kGroups, [&](const KnownGroup& g) {
        return NormalizeName(g.winName) == n || NormalizeName(WideAscii(g.iana)) == n;
    });
    return it == std::ranges::end(kGroups) ? nullptr : &*it;
}

const KnownGroup* FindGroup(uint32_t tlsGroupId) noexcept {
    const auto it = std::ranges::find(kGroups, tlsGroupId, &KnownGroup::id);
    return it == std::ranges::end(kGroups) ? nullptr : &*it;
}

bool SameGroup(std::wstring_view a, std::wstring_view b) {
    if (NormalizeName(a) == NormalizeName(b)) return true;
    const auto* ga = FindGroup(a);
    return ga && ga == FindGroup(b);
}

// ---- OS default list -------------------------------------------------------------------------
std::expected<OsGroupList, std::wstring> GetOsDefaultGroups() {
    if (auto pol = ReadPolicyCurves()) return OsGroupList{std::move(*pol), L"Group Policy"};
    std::wstring psErr, provErr;
    if (auto ps = GetTlsEccCurve(psErr)) return OsGroupList{std::move(*ps), L"Get-TlsEccCurve"};
    if (auto prov = EnumProviderCurves(provErr); prov && !prov->empty())
        return OsGroupList{std::move(*prov), L"SslEnumEccCurves"};
    return std::unexpected(L"Get-TlsEccCurve: " + psErr + L"; SslEnumEccCurves: " +
                           (provErr.empty() ? std::wstring(L"returned nothing") : provErr));
}

// ---- policy ----------------------------------------------------------------------------------
GroupPolicy GroupPolicy::Build(const std::vector<std::wstring>& baseGroups, Mode mode, const std::vector<std::wstring>& names,
                               std::vector<std::wstring>* warnings) {
    GroupPolicy p;
    p.mode_ = mode;
    p.base_ = baseGroups;
    const auto inBase = [&](std::wstring_view g) {
        return std::ranges::any_of(baseGroups, [&](const std::wstring& b) { return SameGroup(b, g); });
    };
    const auto named = [&](std::wstring_view b) {
        return std::ranges::any_of(names, [&](const std::wstring& n) { return SameGroup(b, n); });
    };
    const auto warn = [&](std::wstring w) { if (warnings) warnings->push_back(std::move(w)); };

    if (mode != Mode::Defaults && (baseGroups.empty() || names.empty())) {
        warn(baseGroups.empty() ? L"the base group list is empty; the requested restriction cannot be applied"
                                : L"the requested restriction requires a nonempty group list");
        p.valid_ = false;
        return p;
    }

    if (mode == Mode::Disable) {
        for (const auto& n : names) {
            if (!inBase(n)) {
                warn(L"'" + n + L"' is not in the base group list; cannot apply the disable policy");
                p.valid_ = false;
                continue;
            }
            for (const auto& b : baseGroups)
                if (SameGroup(b, n) && !std::ranges::contains(p.disabled_, b)) p.disabled_.push_back(b);
        }
    } else if (mode == Mode::EnableOnly) {
        for (const auto& n : names)
            if (!inBase(n)) warn(L"'" + n + L"' is not in the base group list; it cannot be enabled per-credential");
        for (const auto& b : baseGroups)
            if (!named(b)) p.disabled_.push_back(b);
        if (p.disabled_.size() == baseGroups.size()) {
            warn(L"none of the enabled groups are in the base group list; nothing would remain enabled");
            p.valid_ = false;
        }
    }

    if (p.disabled_.size() > SCH_CRED_MAX_SUPPORTED_CRYPTO_SETTINGS) {
        warn(L"too many disabled groups for one credential");
        p.valid_ = false;
    }
    for (const auto& d : p.disabled_) {
        const auto* g = FindGroup(d);
        p.algIds_.push_back(g && g->cngAlg ? std::wstring(g->cngAlg) : d);  // documented id, else group name
        if (p.algIds_.back().size() > kMaxAlgIdChars) {                     // UNICODE_STRING lengths are 16-bit
            warn(L"a group name is too long to pass to Schannel");
            p.valid_ = false;
        }
    }
    return p;
}

std::vector<std::wstring> GroupPolicy::Enabled() const {
    std::vector<std::wstring> out;
    std::ranges::copy_if(base_, std::back_inserter(out), [&](const std::wstring& b) { return !IsDisabled(b); });
    return out;
}

bool GroupPolicy::IsDisabled(std::wstring_view group) const {
    return std::ranges::any_of(disabled_, [&](const std::wstring& d) { return SameGroup(d, group); });
}

bool GroupPolicy::Allows(std::optional<uint32_t> tlsGroupId) const {
    if (!valid()) return false;
    if (!Restricts()) return true;
    if (!tlsGroupId) return false;   // group not reported: cannot prove it is allowed
    const auto* g = FindGroup(*tlsGroupId);
    if (!g) return false;            // unknown code point
    const bool inBase = std::ranges::any_of(base_, [&](const std::wstring& b) { return SameGroup(b, g->winName); });
    return inBase && !IsDisabled(g->winName);
}

// ---- credentials -----------------------------------------------------------------------------
SchCredentialData::SchCredentialData(std::span<const PCCERT_CONTEXT> certs, const GroupPolicy& policy,
                                     DWORD disabledProtocols, DWORD schFlags)
    : algIds_(policy.DisabledAlgIds()), certs_(certs.begin(), certs.end()) {
    if (!policy.valid()) throw std::invalid_argument("invalid Schannel group policy");
    settings_.reserve(algIds_.size());
    for (const auto& id : algIds_) {
        CRYPTO_SETTINGS cs{};
        cs.eAlgorithmUsage = TlsParametersCngAlgUsageKeyExchange;
        cs.strCngAlgId = Us(id);
        settings_.push_back(cs);
    }
    tp_.grbitDisabledProtocols = disabledProtocols;
    tp_.cDisabledCrypto = static_cast<DWORD>(settings_.size());
    tp_.pDisabledCrypto = settings_.empty() ? nullptr : settings_.data();

    sc_.dwVersion = SCH_CREDENTIALS_VERSION;
    sc_.cCreds = static_cast<DWORD>(certs_.size());
    sc_.paCred = certs_.empty() ? nullptr : certs_.data();
    sc_.dwFlags = schFlags;
    sc_.cTlsParameters = 1;
    sc_.pTlsParameters = &tp_;
}

void Credential::reset() noexcept {
    if (*this) FreeCredentialsHandle(&h_);
    h_ = kInvalid;
}

std::expected<Credential, SECURITY_STATUS> AcquireServerCredential(PCCERT_CONTEXT cert, const GroupPolicy& policy,
                                                                   DWORD disabledProtocols, DWORD schFlags) {
    if (!cert) return std::unexpected(SEC_E_NO_CREDENTIALS);
    if (!policy.valid()) return std::unexpected(SEC_E_ALGORITHM_MISMATCH);
    SchCredentialData data(std::span(&cert, 1), policy, disabledProtocols, schFlags);
    CredHandle h{};
    TimeStamp ts{};
    const SECURITY_STATUS ss = AcquireCredentialsHandleW(nullptr, const_cast<LPWSTR>(UNISP_NAME_W), SECPKG_CRED_INBOUND, nullptr,
                                                         data.get(), nullptr, nullptr, &h, &ts);
    if (ss != SEC_E_OK) return std::unexpected(ss);
    return Credential{h};
}

// ---- post-handshake --------------------------------------------------------------------------
std::optional<uint32_t> NegotiatedGroup(PCtxtHandle ctx) noexcept {
    SecPkgContext_CipherInfo ci{};
    ci.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
    if (QueryContextAttributesW(ctx, SECPKG_ATTR_CIPHER_INFO, &ci) != SEC_E_OK || ci.dwKeyType == 0) return std::nullopt;
    return ci.dwKeyType;
}

bool ViolatesPolicy(PCtxtHandle ctx, const GroupPolicy& policy) { return !policy.Allows(NegotiatedGroup(ctx)); }

std::expected<std::vector<uint8_t>, SECURITY_STATUS> BuildFatalAlert(PCredHandle cred, PCtxtHandle ctx, DWORD alert) {
    SCHANNEL_ALERT_TOKEN t{SCHANNEL_ALERT, TLS1_ALERT_FATAL, alert};
    SecBuffer b{sizeof(t), SECBUFFER_TOKEN, &t};
    SecBufferDesc d{SECBUFFER_VERSION, 1, &b};
    if (const SECURITY_STATUS ss = ApplyControlToken(ctx, &d); ss != SEC_E_OK) return std::unexpected(ss);

    SecBuffer o{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc od{SECBUFFER_VERSION, 1, &o};
    ULONG attrs = 0;
    TimeStamp ts{};
    constexpr ULONG req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
                          ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
    const SECURITY_STATUS ss = AcceptSecurityContext(cred, ctx, nullptr, req, 0, ctx, &od, &attrs, &ts);
    std::vector<uint8_t> out;
    if (o.pvBuffer) {
        const auto* p = static_cast<const uint8_t*>(o.pvBuffer);
        out.assign(p, p + o.cbBuffer);
        FreeContextBuffer(o.pvBuffer);
    }
    if (FAILED(ss)) return std::unexpected(ss);
    return out;
}

}  // namespace schgroups
