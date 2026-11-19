// schgroups.cpp
// Schannel TLS 1.3 test server. All group logic lives in schannel_groups.h/.cpp; this file is the
// sockets / SSPI handshake / CLI shell around it. The server:
//   * validates every port's group policy and Schannel credential before listening,
//   * shows the OS default key-establishment groups and, per port, which are enabled,
//   * refuses connections whose negotiated group the port's policy does not allow,
//   * logs the negotiated protocol / suite / group for every connection and echoes it over HTTP.
//
// Build: VS 2026 (v145 / MSVC 14.5x), Windows SDK 10.0.28000+, /std:c++latest (C++23). See CMakeLists.txt.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS   // SCH_CREDENTIALS, TLS_PARAMETERS, CRYPTO_SETTINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winternl.h>             // UNICODE_STRING (required by SCHANNEL_USE_BLACKLISTS)
#include <wincrypt.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include "schannel_groups.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <exception>
#include <expected>
#include <format>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <semaphore>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef SECPKGCONTEXT_CIPHERINFO_V1
#define SECPKGCONTEXT_CIPHERINFO_V1 1
#endif

namespace {

// ---------------------------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------------------------
std::mutex g_logMx;

template <class... A>
void Log(std::format_string<A...> f, A&&... a) {
    std::string s = std::format(f, std::forward<A>(a)...);
    s.push_back('\n');
    std::lock_guard g(g_logMx);
    std::fwrite(s.data(), 1, s.size(), stdout);
    std::fflush(stdout);
}

std::string U8(std::wstring_view w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::string Err(long code) {
    char* msg = nullptr;
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, static_cast<DWORD>(code), 0, reinterpret_cast<LPSTR>(&msg), 0, nullptr);
    std::string text = msg ? msg : "";
    if (msg) LocalFree(msg);
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) text.pop_back();
    return text.empty() ? std::format("0x{:08X}", static_cast<uint32_t>(code))
                        : std::format("0x{:08X} ({})", static_cast<uint32_t>(code), text);
}

// Lower-case and strip '_' / '-' so "x25519_mlkem768" == "X25519MLKEM768".
std::wstring Norm(std::wstring_view s) {
    std::wstring r;
    for (wchar_t c : s)
        if (c != L'_' && c != L'-') r.push_back(static_cast<wchar_t>(std::towlower(c)));
    return r;
}

bool AppendGroupList(std::vector<std::wstring>& out, std::wstring_view s) {
    if (s.starts_with(L"--")) {
        Log("error: expected a group list before {}", U8(s));
        return false;
    }
    const auto before = out.size();
    std::wstring cur;
    for (wchar_t c : s) {
        if (c == L',' || std::iswspace(c)) {
            if (!cur.empty()) out.push_back(std::move(cur)), cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    if (out.size() != before) return true;
    Log("error: --enable and --disable require a nonempty group list");
    return false;
}

namespace sg = schgroups;

std::string GroupLabel(std::optional<uint32_t> id) {
    if (!id) return "n/a (no (EC)DHE/KEM group reported)";
    if (const auto* g = sg::FindGroup(*id)) return std::format("{} / {} (0x{:04X})", U8(g->winName), g->iana, *id);
    return std::format("unknown (0x{:04X})", *id);
}

// Compact group name for log lines: Windows name, or the hex code point if unknown.
std::string GroupShort(std::optional<uint32_t> id) {
    if (!id) return "group n/a";
    if (const auto* g = sg::FindGroup(*id)) return U8(g->winName);
    return std::format("group 0x{:04X}", *id);
}

// Symbolic name for common SSPI errors, else the full system message.
std::string ErrShort(long code) {
    switch (static_cast<uint32_t>(code)) {
        case 0x80090331: return "SEC_E_ALGORITHM_MISMATCH";
        case 0x80090304: return "SEC_E_INTERNAL_ERROR";
        case 0x80090326: return "SEC_E_ILLEGAL_MESSAGE";
        case 0x80090327: return "SEC_E_CERT_UNKNOWN";
        case 0x8009030E: return "SEC_E_NO_CREDENTIALS";
        case 0x80090302: return "SEC_E_UNSUPPORTED_FUNCTION";
        case 0x80090308: return "SEC_E_INVALID_TOKEN";
        case 0x80090318: return "SEC_E_INCOMPLETE_MESSAGE";
        default: return Err(code);
    }
}

std::string ProtoName(DWORD p) {
    if (p & SP_PROT_TLS1_3) return "TLS 1.3";
    if (p & SP_PROT_TLS1_2) return "TLS 1.2";
    if (p & SP_PROT_TLS1_1) return "TLS 1.1";
    if (p & SP_PROT_TLS1_0) return "TLS 1.0";
    return p ? std::format("protocol 0x{:08X}", p) : std::string("protocol ?");
}

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------
struct PortCfg {
    uint16_t                  port = 0;
    std::vector<std::wstring> disable;  // remove these from the OS default list
    std::vector<std::wstring> enable;   // keep only these from the OS default list
};

struct Options {
    std::vector<PortCfg>      ports;     // empty -> 8443
    PortCfg                   defaults;  // --disable/--enable given before any --port
    std::wstring              thumbprint;
    bool                      machineStore = false;
    std::wstring              cn = L"localhost";
    std::wstring              keyAlg = L"rsa";   // self-signed cert key: rsa | p256 | p384
    std::wstring              bind = L"loopback"; // loopback | any | IP literal
    bool                      allowTls12 = false;
    bool                      enforce = true;    // refuse connections whose group the port's policy does not allow
};

// ---------------------------------------------------------------------------------------------
// Self-signed server cert (ephemeral persisted CNG key, deleted on exit)
// ---------------------------------------------------------------------------------------------
std::wstring g_tempKeyName;

void DeleteTempKey() {
    if (g_tempKeyName.empty()) return;
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS) {
        if (NCryptOpenKey(prov, &key, g_tempKeyName.c_str(), 0, 0) == ERROR_SUCCESS) NCryptDeleteKey(key, 0);
        NCryptFreeObject(prov);
    }
    g_tempKeyName.clear();
}

PCCERT_CONTEXT CreateSelfSigned(const std::wstring& cn, const std::wstring& keyAlg, std::string& err) {
    const bool rsa = keyAlg == L"rsa", p384 = keyAlg == L"p384";
    if (!rsa && !p384 && keyAlg != L"p256") { err = "--key must be rsa, p256 or p384"; return nullptr; }
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (auto st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0); st != ERROR_SUCCESS) { err = Err(st); return nullptr; }
    std::wstring keyName = L"schgroups-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    const wchar_t* alg = rsa ? NCRYPT_RSA_ALGORITHM : p384 ? NCRYPT_ECDSA_P384_ALGORITHM : NCRYPT_ECDSA_P256_ALGORITHM;
    if (auto st = NCryptCreatePersistedKey(prov, &key, alg, keyName.c_str(), 0, 0); st != ERROR_SUCCESS) {
        err = Err(st); NCryptFreeObject(prov); return nullptr;
    }
    if (rsa) {
        DWORD bits = 3072;
        NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&bits), sizeof(bits), 0);
    }
    if (auto st = NCryptFinalizeKey(key, 0); st != ERROR_SUCCESS) {
        err = Err(st); NCryptFreeObject(key); NCryptFreeObject(prov); return nullptr;
    }
    g_tempKeyName = keyName;

    std::wstring x500 = L"CN=" + cn;
    DWORD cbName = 0;
    CertStrToNameW(X509_ASN_ENCODING, x500.c_str(), CERT_X500_NAME_STR, nullptr, nullptr, &cbName, nullptr);
    std::vector<BYTE> name(cbName);
    CertStrToNameW(X509_ASN_ENCODING, x500.c_str(), CERT_X500_NAME_STR, nullptr, name.data(), &cbName, nullptr);
    CERT_NAME_BLOB subject{cbName, name.data()};

    std::wstring dns = cn;
    CERT_ALT_NAME_ENTRY alt{};
    alt.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
    alt.pwszDNSName = dns.data();
    CERT_ALT_NAME_INFO altInfo{1, &alt};
    BYTE* sanEnc = nullptr; DWORD sanCb = 0;
    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &altInfo, CRYPT_ENCODE_ALLOC_FLAG, nullptr, &sanEnc, &sanCb);

    LPSTR ekuOids[] = {const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH)};
    CERT_ENHKEY_USAGE eku{1, ekuOids};
    BYTE* ekuEnc = nullptr; DWORD ekuCb = 0;
    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &eku, CRYPT_ENCODE_ALLOC_FLAG, nullptr, &ekuEnc, &ekuCb);

    CERT_EXTENSION ext[2] = {
        {const_cast<LPSTR>(szOID_SUBJECT_ALT_NAME2), FALSE, {sanCb, sanEnc}},
        {const_cast<LPSTR>(szOID_ENHANCED_KEY_USAGE), FALSE, {ekuCb, ekuEnc}},
    };
    CERT_EXTENSIONS exts{2, ext};

    CRYPT_KEY_PROV_INFO kpi{};
    kpi.pwszContainerName = keyName.data();
    kpi.pwszProvName = const_cast<LPWSTR>(MS_KEY_STORAGE_PROVIDER);

    CRYPT_ALGORITHM_IDENTIFIER sig{const_cast<LPSTR>(rsa ? szOID_RSA_SHA256RSA : p384 ? szOID_ECDSA_SHA384 : szOID_ECDSA_SHA256), {}};

    SYSTEMTIME now{}, end{};
    GetSystemTime(&now);
    FILETIME ft{};
    SystemTimeToFileTime(&now, &ft);
    ULARGE_INTEGER u{{ft.dwLowDateTime, ft.dwHighDateTime}};
    u.QuadPart += 30ULL * 24 * 3600 * 10'000'000ULL;
    ft = {u.LowPart, u.HighPart};
    FileTimeToSystemTime(&ft, &end);

    PCCERT_CONTEXT cert = CertCreateSelfSignCertificate(key, &subject, 0, &kpi, &sig, nullptr, &end, &exts);
    if (!cert) err = Err(static_cast<long>(GetLastError()));
    if (sanEnc) LocalFree(sanEnc);
    if (ekuEnc) LocalFree(ekuEnc);
    NCryptFreeObject(key);
    NCryptFreeObject(prov);
    return cert;
}

PCCERT_CONTEXT LoadCertByThumbprint(const std::wstring& thumb, bool machine, std::string& err) {
    std::vector<BYTE> hash;
    std::wstring hex;
    for (wchar_t c : thumb) if (std::iswxdigit(c)) hex.push_back(c);
    if (hex.size() != 40) { err = "thumbprint must be 40 hex chars (SHA-1)"; return nullptr; }
    for (size_t i = 0; i < hex.size(); i += 2) hash.push_back(static_cast<BYTE>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    CRYPT_HASH_BLOB blob{static_cast<DWORD>(hash.size()), hash.data()};

    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                     (machine ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER) |
                                         CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                                     L"MY");
    if (!store) { err = Err(static_cast<long>(GetLastError())); return nullptr; }
    PCCERT_CONTEXT c = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &blob, nullptr);
    if (!c) err = std::format("not found in {}\\My", machine ? "LocalMachine" : "CurrentUser");
    CertCloseStore(store, 0);
    return c;
}

// ---------------------------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------------------------
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

constexpr auto           kHandshakeBudget  = 10s;  // the whole handshake, not each read
constexpr auto           kConnectionBudget = 30s;  // the whole connection
constexpr auto           kLingerBudget     = 2s;   // wait for the peer's FIN after our last byte
constexpr auto           kDrainBudget      = 3s;   // wait for open connections at shutdown
constexpr size_t         kInitialBuffer    = 16 * 1024;
constexpr size_t         kMaxBuffer        = 64 * 1024;  // > one TLS record; a client needs no more here
constexpr std::ptrdiff_t kMaxConnections   = 256;

// One permit per live connection thread. Namespace scope so detached threads never touch the stack.
std::counting_semaphore<kMaxConnections> g_slots{kMaxConnections};

struct SlotGuard {
    SlotGuard() = default;
    SlotGuard(const SlotGuard&) = delete;
    SlotGuard& operator=(const SlotGuard&) = delete;
    ~SlotGuard() { g_slots.release(); }
};

class Socket {
public:
    Socket() noexcept = default;
    explicit Socket(SOCKET s) noexcept : s_(s) {}
    Socket(Socket&& o) noexcept : s_(std::exchange(o.s_, INVALID_SOCKET)) {}
    Socket& operator=(Socket&& o) noexcept {
        if (this != &o) { reset(); s_ = std::exchange(o.s_, INVALID_SOCKET); }
        return *this;
    }
    ~Socket() { reset(); }

    void reset() noexcept { if (s_ != INVALID_SOCKET) closesocket(std::exchange(s_, INVALID_SOCKET)); }
    [[nodiscard]] SOCKET get() const noexcept { return s_; }
    [[nodiscard]] explicit operator bool() const noexcept { return s_ != INVALID_SOCKET; }

private:
    SOCKET s_ = INVALID_SOCKET;
};

class SecurityContext {
public:
    SecurityContext() noexcept = default;
    SecurityContext(const SecurityContext&) = delete;
    SecurityContext& operator=(const SecurityContext&) = delete;
    ~SecurityContext() { if (valid()) DeleteSecurityContext(&h_); }

    // Also true for a handle Schannel returned from a call that failed, so that one is freed too.
    [[nodiscard]] bool valid() const noexcept { return h_.dwLower != kNone && h_.dwUpper != kNone; }
    [[nodiscard]] PCtxtHandle get() noexcept { return &h_; }

private:
    static constexpr ULONG_PTR kNone = static_cast<ULONG_PTR>(-1);
    CtxtHandle h_{kNone, kNone};
};

struct ContextBufferFree {
    void operator()(void* p) const noexcept { FreeContextBuffer(p); }
};
using ContextBuffer = std::unique_ptr<void, ContextBufferFree>;

// Everything a connection needs from its port. Immutable once built and shared with connection
// threads through shared_ptr, so it outlives the listener that created it.
struct PortState {
    uint16_t                 port = 0;
    bool                     enforce = true;
    bool                     ok = false;
    sg::GroupPolicy          policy;
    sg::Credential           cred;
    std::string              config;    // "enable X,Y" / "disable X" / "OS defaults"
    std::vector<std::string> warnings;
};

struct Listener {
    uint16_t                         port = 0;
    std::vector<Socket>              sockets;    // one per bound address
    std::shared_ptr<const PortState> state;
    std::vector<std::jthread>        acceptors;  // declared last: stopped and joined before the sockets close
};

struct Server {
    Options               opt;
    PCCERT_CONTEXT        cert = nullptr;
    std::vector<Listener> listeners;
};

std::string DisabledSummary(const std::vector<std::wstring>& d) {
    if (d.empty()) return "(none)";
    std::string s;
    for (const auto& e : d) s += "\n  - " + U8(e);
    return s;
}

// ---------------------------------------------------------------------------------------------
// Connection I/O
// ---------------------------------------------------------------------------------------------
constexpr ULONG kAscReq = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                          ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;

struct IoError {
    enum class Kind { PeerClosed, TimedOut, Network, TooLarge, Sspi };
    Kind        kind;
    long        code = 0;  // WSA error or SECURITY_STATUS
    std::string note;      // what became of Schannel's alert
};
using IoResult = std::expected<void, IoError>;

[[nodiscard]] std::unexpected<IoError> Fail(IoError::Kind kind, long code = 0, std::string note = {}) {
    return std::unexpected(IoError{kind, code, std::move(note)});
}

std::string Describe(const IoError& e) {
    using enum IoError::Kind;
    switch (e.kind) {
        case PeerClosed: return "client closed the connection";
        case TimedOut:   return "timed out";
        case Network:    return "socket error " + Err(e.code);
        case TooLarge:   return "client message too large";
        case Sspi:       return e.note.empty() ? ErrShort(e.code) : std::format("{} ({})", ErrShort(e.code), e.note);
    }
    std::unreachable();
}

struct Conn {
    Socket                           sock;
    std::shared_ptr<const PortState> port;
    SecurityContext                  ctx;
    std::vector<char>                in = std::vector<char>(kInitialBuffer);
    size_t                           inLen = 0;
    Clock::time_point                deadline;
    bool                             sentAny = false;  // any byte sent to the peer yet
};

// Time left before the connection's deadline, as a socket timeout; nullopt once it has passed.
std::optional<DWORD> RemainingMs(const Conn& c) {
    const auto left = std::chrono::ceil<std::chrono::milliseconds>(c.deadline - Clock::now());
    if (left <= 0ms) return std::nullopt;
    return static_cast<DWORD>(left.count());
}

IoResult SendAll(Conn& c, std::span<const std::byte> data) {
    while (!data.empty()) {
        const auto ms = RemainingMs(c);
        if (!ms) return Fail(IoError::Kind::TimedOut);
        setsockopt(c.sock.get(), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&*ms), sizeof(DWORD));
        const int r = send(c.sock.get(), reinterpret_cast<const char*>(data.data()),
                           static_cast<int>(std::min<size_t>(data.size(), 1 << 20)), 0);
        if (r <= 0) {
            const int e = WSAGetLastError();
            return Fail(e == WSAETIMEDOUT ? IoError::Kind::TimedOut : IoError::Kind::Network, e);
        }
        data = data.subspan(static_cast<size_t>(r));
        c.sentAny = true;
    }
    return {};
}

// Appends whatever arrives next to c.in, within the deadline and the buffer cap.
IoResult RecvMore(Conn& c) {
    const auto ms = RemainingMs(c);
    if (!ms) return Fail(IoError::Kind::TimedOut);
    if (c.inLen == c.in.size()) {
        if (c.in.size() >= kMaxBuffer) return Fail(IoError::Kind::TooLarge);
        c.in.resize(std::min(c.in.size() * 2, kMaxBuffer));
    }
    setsockopt(c.sock.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&*ms), sizeof(DWORD));
    const int r = recv(c.sock.get(), c.in.data() + c.inLen, static_cast<int>(c.in.size() - c.inLen), 0);
    if (r > 0) {
        c.inLen += static_cast<size_t>(r);
        return {};
    }
    if (r == 0) return Fail(IoError::Kind::PeerClosed);
    const int e = WSAGetLastError();
    return Fail(e == WSAETIMEDOUT ? IoError::Kind::TimedOut : IoError::Kind::Network, e);
}

// Half-closes, then reads until the peer closes too (bounded), so the socket is not reset with
// unread data pending -- a reset can make the client discard the alert or response just sent.
void CloseGracefully(Conn& c) {
    shutdown(c.sock.get(), SD_SEND);
    c.deadline = std::min(c.deadline, Clock::now() + kLingerBudget);
    std::array<char, 2048> sink{};
    for (size_t total = 0; total < kMaxBuffer;) {
        const auto ms = RemainingMs(c);
        if (!ms) break;
        setsockopt(c.sock.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&*ms), sizeof(DWORD));
        const int r = recv(c.sock.get(), sink.data(), static_cast<int>(sink.size()), 0);
        if (r <= 0) break;
        total += static_cast<size_t>(r);
    }
}

// When a handshake fails, Schannel reports the alert it generated in the SECBUFFER_ALERT output
// buffer rather than the token buffer. Forwards it to the client and returns a note for the log.
std::string ForwardAlert(Conn& c, std::span<const std::byte> alert, bool tokenSent) {
    if (alert.empty()) return tokenSent ? "" : "no alert from Schannel";
    std::string hex;
    for (const std::byte b : alert.first(std::min<size_t>(alert.size(), 8)))
        hex += std::format("{}{:02X}", hex.empty() ? "" : " ", std::to_integer<unsigned>(b));
    if (alert.size() > 8) hex += " ..";
    if (tokenSent) return std::format("alert {} (token already sent)", hex);

    const auto at = [&](size_t i) { return std::to_integer<unsigned>(alert[i]); };
    // A complete TLS record: content type alert (0x15) or TLS 1.3 encrypted (0x17), length matching.
    if (alert.size() >= 7 && (at(0) == 0x15 || at(0) == 0x17) && 5 + ((at(3) << 8) | at(4)) == alert.size())
        return std::format("alert {} {}", hex, SendAll(c, alert) ? "sent" : "not sent");
    // A bare {level, description} pair. Valid to frame as a plaintext record only while nothing has
    // been sent, i.e. no ServerHello and so no handshake keys.
    if (alert.size() == 2 && (at(0) == TLS1_ALERT_WARNING || at(0) == TLS1_ALERT_FATAL) && !c.sentAny) {
        const std::array record{std::byte{0x15}, std::byte{0x03}, std::byte{0x03}, std::byte{0x00}, std::byte{0x02}, alert[0], alert[1]};
        return std::format("alert {} {}", hex, SendAll(c, record) ? "sent" : "not sent");
    }
    return std::format("alert {} not sent", hex);
}

// Drives AcceptSecurityContext until the handshake (or a post-handshake message) completes.
// With needRecv=false, submit the pending token immediately, even when it is empty.
// Leftover bytes stay in c.in[0..inLen).
IoResult Handshake(Conn& c, bool needRecv) {
    for (;;) {
        if (needRecv)
            if (auto r = RecvMore(c); !r) return r;
        std::array<SecBuffer, 2> inB{{{static_cast<ULONG>(c.inLen), SECBUFFER_TOKEN, c.in.data()}, {0, SECBUFFER_EMPTY, nullptr}}};
        SecBufferDesc inD{SECBUFFER_VERSION, static_cast<ULONG>(inB.size()), inB.data()};
        std::array<SecBuffer, 2> outB{{{0, SECBUFFER_TOKEN, nullptr}, {0, SECBUFFER_ALERT, nullptr}}};
        SecBufferDesc outD{SECBUFFER_VERSION, static_cast<ULONG>(outB.size()), outB.data()};
        ULONG attrs = 0;
        TimeStamp ts{};

        const SECURITY_STATUS ss = AcceptSecurityContext(c.port->cred.get(), c.ctx.valid() ? c.ctx.get() : nullptr, &inD, kAscReq, 0,
                                                         c.ctx.get(), &outD, &attrs, &ts);
        const ContextBuffer tokenOwner{outB[0].pvBuffer}, alertOwner{outB[1].pvBuffer};
        const auto bytesOf = [](const SecBuffer& b) {
            return b.pvBuffer ? std::span(static_cast<const std::byte*>(b.pvBuffer), b.cbBuffer) : std::span<const std::byte>{};
        };
        const auto token = bytesOf(outB[0]), alert = bytesOf(outB[1]);

        if (ss == SEC_E_INCOMPLETE_MESSAGE) { needRecv = true; continue; }

        if (!token.empty())
            if (auto r = SendAll(c, token); !r) return r;

        if (FAILED(ss)) return Fail(IoError::Kind::Sspi, ss, ForwardAlert(c, alert, !token.empty()));

        if (inB[1].BufferType == SECBUFFER_EXTRA && inB[1].cbBuffer && inB[1].cbBuffer <= c.inLen) {
            std::memmove(c.in.data(), c.in.data() + (c.inLen - inB[1].cbBuffer), inB[1].cbBuffer);
            c.inLen = inB[1].cbBuffer;
        } else {
            c.inLen = 0;
        }

        if (ss == SEC_E_OK) return {};
        if (ss != SEC_I_CONTINUE_NEEDED) return Fail(IoError::Kind::Sspi, ss);  // e.g. a request this server never makes
        needRecv = c.inLen == 0;
    }
}

IoResult SendTls(Conn& c, const SecPkgContext_StreamSizes& sz, std::string_view msg) {
    std::vector<char> buf(size_t{sz.cbHeader} + sz.cbMaximumMessage + sz.cbTrailer);
    while (!msg.empty()) {
        const size_t n = std::min<size_t>(msg.size(), sz.cbMaximumMessage);
        std::memcpy(buf.data() + sz.cbHeader, msg.data(), n);
        std::array<SecBuffer, 4> b{{{sz.cbHeader, SECBUFFER_STREAM_HEADER, buf.data()},
                                    {static_cast<ULONG>(n), SECBUFFER_DATA, buf.data() + sz.cbHeader},
                                    {sz.cbTrailer, SECBUFFER_STREAM_TRAILER, buf.data() + sz.cbHeader + n},
                                    {0, SECBUFFER_EMPTY, nullptr}}};
        SecBufferDesc d{SECBUFFER_VERSION, static_cast<ULONG>(b.size()), b.data()};
        if (const SECURITY_STATUS ss = EncryptMessage(c.ctx.get(), 0, &d, 0); ss != SEC_E_OK)
            return Fail(IoError::Kind::Sspi, ss);
        const size_t wire = size_t{b[0].cbBuffer} + b[1].cbBuffer + b[2].cbBuffer;
        if (auto r = SendAll(c, std::as_bytes(std::span(buf.data(), wire))); !r) return r;
        msg.remove_prefix(n);
    }
    return {};
}

// Sends close_notify.
void TlsShutdown(Conn& c) {
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer b{sizeof(type), SECBUFFER_TOKEN, &type};
    SecBufferDesc d{SECBUFFER_VERSION, 1, &b};
    if (ApplyControlToken(c.ctx.get(), &d) != SEC_E_OK) return;
    SecBuffer o{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc od{SECBUFFER_VERSION, 1, &o};
    ULONG attrs = 0;
    TimeStamp ts{};
    AcceptSecurityContext(c.port->cred.get(), c.ctx.get(), nullptr, kAscReq, 0, c.ctx.get(), &od, &attrs, &ts);
    const ContextBuffer owner{o.pvBuffer};
    if (o.pvBuffer && o.cbBuffer) (void)SendAll(c, std::span(static_cast<const std::byte*>(o.pvBuffer), o.cbBuffer));
}

std::string PeerName(const sockaddr_storage& a) {
    char host[INET6_ADDRSTRLEN]{};
    uint16_t port = 0;
    if (a.ss_family == AF_INET6) {
        auto* p = reinterpret_cast<const sockaddr_in6*>(&a);
        inet_ntop(AF_INET6, &p->sin6_addr, host, sizeof(host));
        port = ntohs(p->sin6_port);
    } else {
        auto* p = reinterpret_cast<const sockaddr_in*>(&a);
        inet_ntop(AF_INET, &p->sin_addr, host, sizeof(host));
        port = ntohs(p->sin_port);
    }
    std::string h = host;
    if (h.starts_with("::ffff:")) h.erase(0, 7);  // IPv4-mapped
    return std::format("{}:{}", h, port);
}

// What the established context negotiated. Queried again after any post-handshake exchange.
struct Negotiated {
    DWORD                   protocol = 0;
    std::string             suite = "?";
    DWORD                   suiteId = 0;
    std::string             exchange;
    std::optional<uint32_t> group;

    [[nodiscard]] bool tls13() const noexcept { return (protocol & SP_PROT_TLS1_3) != 0; }
};

Negotiated QueryNegotiated(PCtxtHandle ctx) {
    Negotiated n;
    if (SecPkgContext_ConnectionInfo ci{}; QueryContextAttributesW(ctx, SECPKG_ATTR_CONNECTION_INFO, &ci) == SEC_E_OK)
        n.protocol = ci.dwProtocol;
    SecPkgContext_CipherInfo cinfo{};
    cinfo.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
    if (QueryContextAttributesW(ctx, SECPKG_ATTR_CIPHER_INFO, &cinfo) == SEC_E_OK) {
        n.suite = U8(cinfo.szCipherSuite);
        n.suiteId = cinfo.dwCipherSuite;
        n.exchange = U8(cinfo.szExchange);
        if (cinfo.dwKeyType != 0) n.group = cinfo.dwKeyType;
    }
    return n;
}

// Drops a connection whose negotiated group the port's policy does not allow.
void Refuse(Conn& c, std::string_view peer, const Negotiated& n, std::string_view why) {
    Log("{}  refused {} ({})", peer, GroupShort(n.group), why);
    if (const auto alert = sg::BuildFatalAlert(c.port->cred.get(), c.ctx.get()); alert && !alert->empty())
        (void)SendAll(c, std::as_bytes(std::span(*alert)));
    CloseGracefully(c);
}

void HandleConn(std::shared_ptr<const PortState> port, Socket sock, std::string peer) {
    Conn c;
    c.sock = std::move(sock);
    c.port = std::move(port);
    const PortState& ps = *c.port;
    peer += std::format(" -> :{}", ps.port);
    const auto started = Clock::now();
    c.deadline = started + kHandshakeBudget;

    if (auto hs = Handshake(c, true); !hs) {
        Log("{}  handshake failed: {}", peer, Describe(hs.error()));
        if (hs.error().kind == IoError::Kind::Sspi) CloseGracefully(c);  // let the alert arrive before the close
        return;
    }
    c.deadline = started + kConnectionBudget;

    Negotiated info = QueryNegotiated(c.ctx.get());
    Log("{}  {}  {}  {}", peer, ProtoName(info.protocol), info.suite, GroupShort(info.group));
    const auto allowed = [&] { return !ps.enforce || ps.policy.Allows(info.group); };
    if (!allowed()) return Refuse(c, peer, info, "not an enabled group on this port");

    SecPkgContext_StreamSizes sz{};
    if (QueryContextAttributesW(c.ctx.get(), SECPKG_ATTR_STREAM_SIZES, &sz) != SEC_E_OK) return;

    // Read until we have a line (HTTP request line or a typed s_client line).
    std::string plain;
    while (!plain.contains('\n') && plain.size() < kMaxBuffer) {
        if (c.inLen == 0)
            if (auto r = RecvMore(c); !r) {
                if (r.error().kind != IoError::Kind::PeerClosed) Log("{}  {}", peer, Describe(r.error()));
                return;
            }
        std::array<SecBuffer, 4> b{{{static_cast<ULONG>(c.inLen), SECBUFFER_DATA, c.in.data()},
                                    {0, SECBUFFER_EMPTY, nullptr}, {0, SECBUFFER_EMPTY, nullptr}, {0, SECBUFFER_EMPTY, nullptr}}};
        SecBufferDesc d{SECBUFFER_VERSION, static_cast<ULONG>(b.size()), b.data()};
        const SECURITY_STATUS ss = DecryptMessage(c.ctx.get(), &d, 0, nullptr);
        if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            if (auto r = RecvMore(c); !r) {
                if (r.error().kind != IoError::Kind::PeerClosed) Log("{}  {}", peer, Describe(r.error()));
                return;
            }
            continue;
        }
        if (ss == SEC_I_CONTEXT_EXPIRED) return;  // close_notify
        if (ss != SEC_E_OK && ss != SEC_I_RENEGOTIATE) {
            Log("{}  DecryptMessage: {}", peer, ErrShort(ss));
            return;
        }
        const auto findBuffer = [&](ULONG type) { return std::ranges::find(b, type, &SecBuffer::BufferType); };
        auto pending = findBuffer(SECBUFFER_EXTRA);
        if (ss == SEC_I_RENEGOTIATE) {
            if (!info.tls13()) return Refuse(c, peer, info, "renegotiation is not allowed");
            // Schannel usually returns the handshake input as EXTRA. Without EXTRA, use the
            // modified token/data buffer, or an empty token if the context buffered everything.
            if (pending == b.end()) {
                pending = findBuffer(SECBUFFER_TOKEN);
                if (pending == b.end()) pending = findBuffer(SECBUFFER_DATA);
            }
        } else if (const auto data = findBuffer(SECBUFFER_DATA); data != b.end() && data->cbBuffer) {
            plain.append(static_cast<const char*>(data->pvBuffer), data->cbBuffer);
        }
        if (pending != b.end() && pending->cbBuffer) {
            if (pending->cbBuffer > c.inLen) return;
            const void* src = pending->pvBuffer;
            if (!src && pending->BufferType == SECBUFFER_EXTRA) src = c.in.data() + (c.inLen - pending->cbBuffer);
            if (!src) return;
            std::memmove(c.in.data(), src, pending->cbBuffer);
            c.inLen = pending->cbBuffer;
        } else {
            c.inLen = 0;
        }

        if (ss == SEC_I_RENEGOTIATE) {
            if (auto r = Handshake(c, false); !r) {
                Log("{}  post-handshake: {}", peer, Describe(r.error()));
                return;
            }
            info = QueryNegotiated(c.ctx.get());
            if (!allowed()) return Refuse(c, peer, info, "not an enabled group on this port");
        }
    }

    const std::string body = std::format(
        "Schannel group test server\n"
        "client -> server port:   {}\n"
        "protocol:                {}\n"
        "cipher suite:            {} (0x{:04X})\n"
        "key exchange group:      {}\n"
        "exchange:                {}\n"
        "disabled groups:         {}\n",
        peer, ProtoName(info.protocol), info.suite, info.suiteId, GroupLabel(info.group),
        info.exchange.empty() ? "(not reported)" : info.exchange, DisabledSummary(ps.policy.Disabled()));
    const std::string resp = plain.starts_with("GET ") || plain.starts_with("HEAD ")
                                 ? std::format("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n"
                                               "Connection: close\r\n\r\n{}",
                                               body.size(), body)
                                 : body;
    if (SendTls(c, sz, resp)) {
        TlsShutdown(c);
        CloseGracefully(c);
    }
}

// ---------------------------------------------------------------------------------------------
// Listening
// ---------------------------------------------------------------------------------------------
struct Endpoint {
    sockaddr_storage addr{};
    int              len = 0;
    bool             dualStack = false;
};

Endpoint V4Endpoint(const in_addr& a) {
    Endpoint e;
    auto* p = reinterpret_cast<sockaddr_in*>(&e.addr);
    p->sin_family = AF_INET;
    p->sin_addr = a;
    e.len = sizeof(sockaddr_in);
    return e;
}

Endpoint V6Endpoint(const in6_addr& a, bool dualStack) {
    Endpoint e;
    auto* p = reinterpret_cast<sockaddr_in6*>(&e.addr);
    p->sin6_family = AF_INET6;
    p->sin6_addr = a;
    e.len = sizeof(sockaddr_in6);
    e.dualStack = dualStack;
    return e;
}

// "loopback" (default) -> 127.0.0.1 and ::1; "any" -> every interface; otherwise an IP literal.
std::expected<std::vector<Endpoint>, std::string> ResolveBind(const std::wstring& bind) {
    const auto key = Norm(bind);
    if (key == L"loopback" || key == L"localhost") {
        in_addr lo{};
        lo.s_addr = htonl(INADDR_LOOPBACK);
        return std::vector{V4Endpoint(lo), V6Endpoint(in6addr_loopback, false)};
    }
    if (key == L"any" || key == L"*") return std::vector{V6Endpoint(in6addr_any, true)};
    if (in_addr a4{}; InetPtonW(AF_INET, bind.c_str(), &a4) == 1) return std::vector{V4Endpoint(a4)};
    if (in6_addr a6{}; InetPtonW(AF_INET6, bind.c_str(), &a6) == 1) return std::vector{V6Endpoint(a6, false)};
    return std::unexpected(std::format("--bind '{}': use loopback, any, or an IPv4/IPv6 address", U8(bind)));
}

// Returns a non-blocking listening socket, or the Winsock error.
std::expected<Socket, int> Listen(Endpoint e, uint16_t port) {
    const auto fail = [] { return std::unexpected(WSAGetLastError()); };
    const bool v6 = e.addr.ss_family == AF_INET6;
    Socket s{WSASocketW(e.addr.ss_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT)};
    if (!s) return fail();
    if (v6) {
        reinterpret_cast<sockaddr_in6*>(&e.addr)->sin6_port = htons(port);
        const DWORD v6only = e.dualStack ? 0 : 1;
        if (setsockopt(s.get(), IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6only), sizeof(v6only)) != 0) return fail();
    } else {
        reinterpret_cast<sockaddr_in*>(&e.addr)->sin_port = htons(port);
    }
    const BOOL exclusive = TRUE;
    if (setsockopt(s.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) != 0) return fail();
    u_long nonBlocking = 1;  // so the accept loop can poll and notice a stop request
    if (bind(s.get(), reinterpret_cast<const sockaddr*>(&e.addr), e.len) != 0 || listen(s.get(), SOMAXCONN) != 0 ||
        ioctlsocket(s.get(), FIONBIO, &nonBlocking) != 0)
        return fail();
    return s;
}

void AcceptLoop(std::stop_token stop, SOCKET listener, std::shared_ptr<const PortState> port) {
    Clock::time_point lastLimitLog{};
    while (!stop.stop_requested()) {
        WSAPOLLFD pfd{listener, POLLRDNORM, 0};
        const int ready = WSAPoll(&pfd, 1, 250);
        if (ready == 0) continue;
        if (ready < 0 || (pfd.revents & (POLLERR | POLLNVAL))) {
            Log(":{} listener failed: {}", port->port, Err(WSAGetLastError()));
            return;
        }

        sockaddr_storage a{};
        int len = sizeof(a);
        Socket s{accept(listener, reinterpret_cast<sockaddr*>(&a), &len)};
        if (!s) continue;  // the pending connection went away
        u_long blocking = 0;  // accepted sockets inherit the listener's non-blocking mode
        ioctlsocket(s.get(), FIONBIO, &blocking);

        if (!g_slots.try_acquire()) {  // at the cap: drop (the Socket destructor closes it)
            if (const auto now = Clock::now(); now - lastLimitLog > 1s) {
                Log(":{} connection limit ({}) reached; dropping new connections", port->port, kMaxConnections);
                lastLimitLog = now;
            }
            continue;
        }
        try {
            std::thread([port, s = std::move(s), peer = PeerName(a)]() mutable {
                const SlotGuard slot;
                try {
                    HandleConn(std::move(port), std::move(s), std::move(peer));
                } catch (const std::exception& e) {
                    Log("connection error: {}", e.what());
                }
            }).detach();
        } catch (const std::exception& e) {  // the thread never started, so its SlotGuard never existed
            g_slots.release();
            Log(":{} cannot start a connection thread: {}", port->port, e.what());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------
void Usage() {
    Log(R"(schgroups -- Schannel TLS 1.3 server with key-establishment group control

usage: schgroups [--port <n> [--disable <g>,.. | --enable <g>,..]]... [options]
  --port <n>              add a listener (repeatable; default 8443)
  --disable <g>[,<g>...]  start from the OS default group list and remove these groups
  --enable <g>[,<g>...]   start from the OS default group list and keep ONLY these groups
                          --disable/--enable apply to the preceding --port and are mutually exclusive per port.
                          Given before any --port, they apply to every port that sets neither.
  --port <n>:disable=<g>,..   shorthand for --port <n> --disable <g>,..
  --port <n>:enable=<g>,..    shorthand for --port <n> --enable <g>,..
  --bind <addr>           loopback (default: 127.0.0.1 and ::1), any (all interfaces), or an IP address
  --cert <sha1>           server cert from CurrentUser\My (add --machine for LocalMachine\My);
                          default: ephemeral self-signed cert (see --key)
  --cn <name>             CN/SAN for the self-signed cert (default localhost)
  --key rsa|p256|p384     key type for the self-signed cert (default rsa = RSA-3072).
                          Observed: with an ECDSA cert, handshakes offering only ML-KEM groups fail with
                          SEC_E_ALGORITHM_MISMATCH while classical groups work; RSA works for both.
  --tls12                 also allow TLS 1.2 (default TLS 1.3 only)

groups: curve25519 NistP256 NistP384 NistP521 X25519_MLKEM768 SecP256r1_MLKEM768 SecP384r1_MLKEM1024
        MLKEM512 MLKEM768 MLKEM1024
        (case/underscore-insensitive; OpenSSL/IANA names like X25519MLKEM768, secp256r1 also accepted)

examples:
  schgroups --port 9443 --disable curve25519
  schgroups --port 8443 --enable SecP384r1_MLKEM1024 --port 9443 --disable X25519_MLKEM768,curve25519 --port 10443
  schgroups --bind any --port 8443:enable=SecP384r1_MLKEM1024 --port 9443:disable=curve25519)");
}

std::string JoinU8(const std::vector<std::wstring>& v) {
    std::string r;
    for (const auto& x : v) r += (r.empty() ? "" : ",") + U8(x);
    return r;
}

// Applies --disable / --enable for one port against the OS default list and builds its credential.
// Output is deferred to PrintSummary(); state.ok says whether the port is usable.
PortState ConfigurePort(const Server& srv, const PortCfg& cfg, const sg::OsGroupList& def) {
    PortState st;
    st.port = cfg.port;
    st.enforce = srv.opt.enforce;
    st.config = "OS defaults";
    sg::Mode mode = sg::Mode::Defaults;
    const std::vector<std::wstring>* names = &cfg.disable;
    if (!cfg.disable.empty()) {
        mode = sg::Mode::Disable;
        st.config = "disable " + JoinU8(cfg.disable);
    } else if (!cfg.enable.empty()) {
        mode = sg::Mode::EnableOnly;
        names = &cfg.enable;
        st.config = "enable  " + JoinU8(cfg.enable);
    }

    std::vector<std::wstring> warnings;
    st.policy = sg::GroupPolicy::Build(def.groups, mode, *names, &warnings);
    std::ranges::transform(warnings, std::back_inserter(st.warnings), [](const std::wstring& w) { return U8(w); });
    if (!st.policy.valid()) return st;

    const DWORD protocols = srv.opt.allowTls12 ? sg::kTls12PlusServer : sg::kTls13OnlyServer;
    auto cred = sg::AcquireServerCredential(srv.cert, st.policy, protocols);
    if (!cred) {
        st.warnings.push_back("AcquireCredentialsHandle: " + ErrShort(cred.error()));
        return st;
    }
    st.cred = std::move(*cred);
    st.ok = true;
    return st;
}

// Port configs, then one matrix: OS default groups (rows) x ports (columns).
void PrintSummary(std::span<const Listener> listeners, const sg::OsGroupList& def) {
    for (const auto& l : listeners) {
        Log(":{:<6} {}", l.port, l.state->config);
        for (const auto& w : l.state->warnings) Log("        ! {}", w);
    }
    std::string head = std::format("\n {:>2}  {:<20} {:<7}", "#", "group", "code");
    for (const auto& l : listeners) head += std::format(" {:>6}", l.port);
    Log("{}", head);
    for (const auto& [i, name] : std::views::enumerate(def.groups)) {
        const auto* g = sg::FindGroup(name);
        std::string row = std::format(" {:>2}  {:<20} {:<7}", i, U8(name), g ? std::format("0x{:04X}", g->id) : "?");
        for (const auto& l : listeners) row += std::format(" {:>6}", l.state->policy.IsDisabled(name) ? "-" : "on");
        Log("{}", row);
    }
    std::string foot = std::format("     {:<28}", "enabled");
    for (const auto& l : listeners) foot += std::format(" {:>6}", l.state->policy.Enabled().size());
    Log("{}", foot);
}

BOOL WINAPI CtrlHandler(DWORD) {
    DeleteTempKey();
    return FALSE;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    Server srv;
    auto& o = srv.opt;

    for (int i = 1; i < argc; ++i) {
        std::wstring_view a = argv[i];
        auto next = [&]() -> std::wstring {
            if (i + 1 >= argc) { Usage(); std::exit(2); }
            return argv[++i];
        };
        auto current = [&]() -> PortCfg& { return o.ports.empty() ? o.defaults : o.ports.back(); };
        if (a == L"--port") {
            std::wstring v = next();
            auto colon = v.find(L':');
            unsigned long n = std::wcstoul(v.substr(0, colon).c_str(), nullptr, 10);
            if (n == 0 || n > 65535) { Log("bad port: {}", U8(v)); return 2; }
            PortCfg pc;
            pc.port = static_cast<uint16_t>(n);
            if (std::ranges::contains(o.ports, pc.port, &PortCfg::port)) {
                Log("duplicate port {}", pc.port);
                return 2;
            }
            if (colon != std::wstring::npos) {
                std::wstring spec = v.substr(colon + 1);
                auto eq = spec.find(L'=');
                std::wstring verb = Norm(spec.substr(0, eq));
                if (eq == std::wstring::npos || (verb != L"disable" && verb != L"enable")) {
                    Log("bad port spec '{}': use <port>:disable=<g>,.. or <port>:enable=<g>,..", U8(v));
                    return 2;
                }
                if (!AppendGroupList(verb == L"disable" ? pc.disable : pc.enable, std::wstring_view(spec).substr(eq + 1))) return 2;
            }
            o.ports.push_back(std::move(pc));
        }
        else if (a == L"--disable" || a == L"--enable") {
            if (!AppendGroupList(a == L"--disable" ? current().disable : current().enable, next())) return 2;
        }
        else if (a == L"--bind") o.bind = next();
        else if (a == L"--cert") o.thumbprint = next();
        else if (a == L"--machine") o.machineStore = true;
        else if (a == L"--cn") o.cn = next();
        else if (a == L"--key") o.keyAlg = Norm(next());
        else if (a == L"--tls12") o.allowTls12 = true;
        else if (a == L"--enforce") o.enforce = true;      // the default; accepted for old command lines
        else if (a == L"--no-enforce") o.enforce = false;  // show what Schannel alone accepts
        else if (a == L"--help" || a == L"-h" || a == L"/?") { Usage(); return 0; }
        else { Log("error: unknown option '{}'  (run with --help for usage)", U8(a)); return 2; }
    }
    if (o.ports.empty()) o.ports.push_back({8443, {}, {}});
    if (!o.defaults.disable.empty() && !o.defaults.enable.empty()) {
        Log("error: --disable and --enable are mutually exclusive");
        return 2;
    }
    for (auto& pc : o.ports) {
        if (!pc.disable.empty() && !pc.enable.empty()) {
            Log("error: port {}: --disable and --enable are mutually exclusive", pc.port);
            return 2;
        }
        if (pc.disable.empty() && pc.enable.empty()) { pc.disable = o.defaults.disable; pc.enable = o.defaults.enable; }
    }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { Log("WSAStartup failed"); return 1; }
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    auto bail = [&](int rc) {
        srv.listeners.clear();
        if (srv.cert) CertFreeCertificateContext(srv.cert);
        DeleteTempKey();
        WSACleanup();
        return rc;
    };

    const auto endpoints = ResolveBind(o.bind);
    if (!endpoints) { Log("error: {}", endpoints.error()); return bail(2); }

    std::string err;
    srv.cert = o.thumbprint.empty() ? CreateSelfSigned(o.cn, o.keyAlg, err) : LoadCertByThumbprint(o.thumbprint, o.machineStore, err);
    if (!srv.cert) { Log("certificate: {}", err); return bail(1); }
    const std::string certDesc = o.thumbprint.empty()
        ? "self-signed " + std::string(o.keyAlg == L"rsa" ? "RSA-3072" : o.keyAlg == L"p384" ? "ECDSA P-384" : "ECDSA P-256") + " CN=" + U8(o.cn)
        : "cert " + U8(o.thumbprint);

    const auto os = sg::GetOsDefaultGroups();
    const sg::OsGroupList def = os.value_or(sg::OsGroupList{});
    Log("{} | {} | bind {} | groups from {}", certDesc, o.allowTls12 ? "TLS 1.2/1.3" : "TLS 1.3 only", U8(o.bind),
        os ? U8(os->source) : "nowhere: " + U8(os.error()));
    const bool anyChange = std::ranges::any_of(o.ports, [](const PortCfg& p) { return !p.disable.empty() || !p.enable.empty(); });
    if (def.groups.empty() && anyChange) { Log("error: no OS default list to work from"); return bail(1); }

    for (const auto& pc : o.ports) {
        auto& l = srv.listeners.emplace_back();
        l.port = pc.port;
        l.state = std::make_shared<const PortState>(ConfigurePort(srv, pc, def));
    }
    PrintSummary(srv.listeners, def);
    if (!std::ranges::all_of(srv.listeners, [](const Listener& l) { return l.state->ok; })) {
        Log("error: a port could not be configured (see ! above)");
        return bail(1);
    }

    for (auto& l : srv.listeners) {
        for (const auto& ep : *endpoints) {
            auto s = Listen(ep, l.port);
            if (s) { l.sockets.push_back(std::move(*s)); continue; }
            // With the two loopback addresses, a machine without IPv4 or IPv6 may bind only one.
            const bool familyMissing = s.error() == WSAEAFNOSUPPORT || s.error() == WSAEADDRNOTAVAIL;
            if (!(familyMissing && endpoints->size() > 1)) { Log("listen on {}: {}", l.port, Err(s.error())); return bail(1); }
        }
        if (l.sockets.empty()) { Log("listen on {}: no usable address", l.port); return bail(1); }
    }

    for (auto& l : srv.listeners)
        for (const auto& s : l.sockets) l.acceptors.emplace_back(AcceptLoop, s.get(), l.state);
    std::string portsList;
    for (const auto& l : srv.listeners) portsList += (portsList.empty() ? "" : ", ") + std::to_string(l.port);
    Log("ready on {} -- q + Enter to quit\n", portsList);

    std::string line;
    while (std::getline(std::cin, line))
        if (line == "q" || line == "quit") break;
    if (!std::cin) {  // no console input: run until killed
        std::binary_semaphore forever{0};
        forever.acquire();
    }

    // Stop accepting (each accept loop notices within its poll interval), then give open
    // connections a moment. Connection threads own what they use, so leaving some behind is safe.
    for (auto& l : srv.listeners)
        for (auto& t : l.acceptors) t.request_stop();
    for (auto& l : srv.listeners) l.acceptors.clear();  // joins
    const auto until = Clock::now() + kDrainBudget;
    std::ptrdiff_t idle = 0;
    while (idle < kMaxConnections && g_slots.try_acquire_until(until)) ++idle;
    if (idle < kMaxConnections) Log("{} connection(s) still open at exit", kMaxConnections - idle);
    return bail(0);
}
