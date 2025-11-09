// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <map>

#include "crab/ebpf_domain.hpp"
#include "program.hpp"

namespace prevail {

class InterleavedFwdFixpointIterator;

struct InvariantMapPair {
    EbpfDomain pre;
    EbpfDomain post;
};
using InvariantTable = std::map<Label, std::map<Label, InvariantMapPair>>;

void run_forward_analyzer_function(InterleavedFwdFixpointIterator& analyser);
std::vector<std::pair<Label, std::string>> run_forward_analyzer(const Program& prog, EbpfDomain entry_inv);

} // namespace prevail
