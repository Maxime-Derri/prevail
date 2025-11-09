// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/fwd_analyzer.hpp"
#include "program.hpp"
#include "spec_type_descriptors.hpp"
#include "string_constraints.hpp"

namespace prevail {
//class Report final {
//    std::map<Label, std::vector<std::string>> warnings;
//    std::map<Label, std::vector<std::string>> reachability;
//    friend class Invariants;
//
//  public:
//    friend void print_reachability(std::ostream& os, const Report& report);
//    friend void print_warnings(std::ostream& os, const Report& report);
//    friend void print_all_messages(std::ostream& os, const Report& report);
//
//    std::set<std::string> all_messages() const {
//        std::set<std::string> result = warning_set();
//        for (const auto& note : reachability_set()) {
//            result.insert(note);
//        }
//        return result;
//    }
//
//    std::set<std::string> reachability_set() const {
//        std::set<std::string> result;
//        for (const auto& [label, reach_warning] : reachability) {
//            for (const auto& msg : reach_warning) {
//                result.insert(to_string(label) + ": " + msg);
//            }
//        }
//        return result;
//    }
//
//    std::set<std::string> warning_set() const {
//        std::set<std::string> result;
//        for (const auto& [label, warning_vec] : warnings) {
//            for (const auto& msg : warning_vec) {
//                result.insert(to_string(label) + ": " + msg);
//            }
//        }
//        return result;
//    }
//
//    bool verified() const { return warnings.empty(); }
//};

//class Invariants final {
//    InvariantTable invariants;
//
//    std::map<Label, InvariantMapPair> *shortcut_invariants;
//
//  public:
//    explicit Invariants(InvariantTable&& invariants) : invariants(std::move(invariants)) {}
//    Invariants(Invariants&& invariants) = default;
//    Invariants(const Invariants& invariants) = default;
//
//    void set_shortcut_invariants(const Label& function);
//    void reset_shortcut_invariants();
//
//    bool is_valid_after(const Label& function, const Label& label, const StringInvariant& state) const;
//    bool is_valid_after(const Label& label, const StringInvariant& state) const;
//
//    StringInvariant Invariants::invariant_at(const Label& function, const Label& label) const;
//    StringInvariant invariant_at(const Label& label) const;
//
//    Interval exit_value() const;
//
//    int max_loop_count() const;
//    bool verified(const Program& prog) const;
//    //Report check_assertions(const Program& prog) const;
//
//    void check_assertions_at(const Program& prog, const Label& function, const Label& label, const std::string& frame_prefix, std::vector<std::pair<Label, std::string>>& report);
//    friend void check_assertions_of_inv(const Program& prog, const Label& function, const Label& label, const std::string& frame_prefix, const prevail::InvariantMapPair& inv, std::vector<std::pair<Label, std::string>>& report);
//
//    friend void print_invariants(std::ostream& os, const Program& prog, bool simplify, const InvariantMapPair& invariants);
//};

//Invariants analyze(const Program& prog);
//Invariants analyze(const Program& prog, const StringInvariant& entry_invariant);
//inline bool verify(const Program& prog) { return analyze(prog).verified(prog); }

std::vector<std::pair<Label, std::string>> analyze(const Program& prog);
std::vector<std::pair<Label, std::string>> analyze(const Program& prog, const StringInvariant& entry_invariant);
inline bool verify(const Program& prog) { return analyze(prog).empty(); }

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
                    ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);

void check_assertions_of_inv(const Instruction& instruction, const Label& function, const Label& label, const std::string& frame_prefix, const EbpfDomain& pre, const EbpfDomain& post, std::vector<std::pair<Label, std::string>>& report);

void print_report(std::ostream& os, std::vector<std::pair<Label, std::string>>& report);

void ebpf_verifier_clear_thread_local_state();
} // namespace prevail
