#include "schannel_groups.h"

#include <cstdio>
#include <stdexcept>

int main() {
    using namespace schgroups;
    const std::vector<std::wstring> pq{L"X25519_MLKEM768"};
    const auto only = GroupPolicy::Build(pq, Mode::EnableOnly, {L"X25519MLKEM768"});
    if (!only.valid() || !only.Allows(0x11EC) || only.Allows(0x001D) || only.Allows(0xFFFF) || only.Allows(std::nullopt)) {
        std::puts("An explicit allowlist equal to the base must still check the negotiated group");
        return 1;
    }

    const auto defaults = GroupPolicy::Build(pq, Mode::Defaults, {});
    if (!defaults.Allows(std::nullopt) || !defaults.Allows(0x001D)) return 1;

    const std::vector<std::wstring> both{L"curve25519", pq.front()};
    const auto restricted = GroupPolicy::Build(both, Mode::Disable, {L"x25519"});
    if (!restricted.valid() || !restricted.Allows(0x11EC) || restricted.Allows(0x001D)) return 1;
    for (const auto& invalid : {GroupPolicy::Build(both, Mode::Disable, {L"x25519", L"typo"}),
                                GroupPolicy::Build(pq, Mode::EnableOnly, {}), GroupPolicy::Build(pq, Mode::Disable, {})}) {
        if (invalid.valid() || invalid.Allows(0x11EC) || invalid.Allows(std::nullopt)) {
            std::puts("An invalid restriction must deny even a known base group");
            return 1;
        }
        try {
            SchCredentialData data({}, invalid, kTls13OnlyServer);
            std::puts("An invalid policy produced a native credential block");
            return 1;
        } catch (const std::invalid_argument&) {}
    }
}
