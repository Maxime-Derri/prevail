// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/**
 *  This module is about selecting the numerical and memory domains, initiating
 *  the verification process and returning the results.
 **/

#include <map>
#include <ranges>
#include <string>

#include "asm_files.hpp"
#include "asm_syntax.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"
#include "crab/var_registry.hpp"
#include "crab_utils/lazy_allocator.hpp"
#include "crab_verifier.hpp"
#include "string_constraints.hpp"

using std::string;

namespace prevail {
thread_local LazyAllocator<ProgramInfo> thread_local_program_info;
thread_local ebpf_verifier_options_t thread_local_options;
void ebpf_verifier_clear_before_analysis();

//void Invariants::set_shortcut_invariants(const Label& function) {
//    if (shortcut_invariants != nullptr) {
//        CRAB_ERROR("Shortcut is already in use");
//    }
//    const auto inv = invariants.find(function);
//    if (inv == invariants.end()) {
//        CRAB_ERROR("Function does not exist, cannot set shortcut");
//    }
//    shortcut_invariants = &(inv->second);
//}

//void Invariants::reset_shortcut_invariants() {
//    shortcut_invariants = nullptr;
//}

//bool Invariants::is_valid_after(const Label& function, const Label& label, const StringInvariant& state) const {
//    const EbpfDomain abstract_state =
//        EbpfDomain::from_constraints(state.value(), thread_local_options.setup_constraints);
//    return abstract_state <= invariants.at(function).at(label).post;
//}

//bool Invariants::is_valid_after(const Label& label, const StringInvariant& state) const {
//    if (shortcut_invariants == nullptr) {
//        CRAB_ERROR("Shortcut is null");
//    }
//    const EbpfDomain abstract_state =
//        EbpfDomain::from_constraints(state.value(), thread_local_options.setup_constraints);
//    return abstract_state <= shortcut_invariants->at(label).post;
//}

//StringInvariant Invariants::invariant_at(const Label& function, const Label& label) const { return invariants.at(function).at(label).post.to_set(); }

//StringInvariant Invariants::invariant_at(const Label& label) const {
//    if (shortcut_invariants == nullptr) {
//        CRAB_ERROR("Shortcut is null");
//    }
//    return shortcut_invariants->at(label).post.to_set(); }

//Interval Invariants::exit_value() const { return invariants.at(Label::exit).post.get_r0(); }

//int Invariants::max_loop_count() const {
//    ExtendedNumber max_loop_count{0};
//    // Gather the upper bound of loop counts from post-invariants.
//    for (const auto& [function, invs] : invariants) {
//        for (const auto& [label, inv] : invs) {
//            max_loop_count = std::max(max_loop_count, inv.post.get_loop_count_upper_bound());
//        }
//    }
//
//    const auto m = max_loop_count.number();
//    if (m && m->fits<int32_t>()) {
//        return m->cast_to<int32_t>();
//    }
//    return std::numeric_limits<int>::max();
//}

//Invariants analyze(const Program& prog, EbpfDomain&& entry_invariant) {
//    return Invariants{run_forward_analyzer(prog, std::move(entry_invariant))};
//}
//
//Invariants analyze(const Program& prog) {
//    ebpf_verifier_clear_before_analysis();
//    return analyze(prog, EbpfDomain::setup_entry(thread_local_options.setup_constraints));
//}
//
//Invariants analyze(const Program& prog, const StringInvariant& entry_invariant) {
//    ebpf_verifier_clear_before_analysis();
//    return analyze(prog, EbpfDomain::from_constraints(entry_invariant.value(), thread_local_options.setup_constraints));
//}

std::vector<std::pair<Label, std::string>> analyze(const Program& prog, EbpfDomain&& entry_invariant) {
    return run_forward_analyzer(prog, std::move(entry_invariant));
}

std::vector<std::pair<Label, std::string>> analyze(const Program& prog) {
    ebpf_verifier_clear_before_analysis();
    return analyze(prog, EbpfDomain::setup_entry(thread_local_options.setup_constraints));
}

std::vector<std::pair<Label, std::string>> analyze(const Program& prog, const StringInvariant& entry_invariant) {
    ebpf_verifier_clear_before_analysis();
    return analyze(prog, EbpfDomain::from_constraints(entry_invariant.value(), thread_local_options.setup_constraints));
}

//bool Invariants::verified(const Program& prog) const {
//    for (const auto& [function, invs] : invariants) {
//        const auto& instructions = prog.instructions(function);
//        for (const auto& [label, inv] : invs) {
//            if (inv.pre.is_bottom()) {
//                continue;
//            }
//            for (const Assertion& assertion : get_assertions(instructions.at(label), *thread_local_program_info, inv.pre.get_frame_prefix().has_value() ? inv.pre.get_frame_prefix().value() : "")) {
//                if (!ebpf_domain_check(inv.pre, assertion).empty()) {
//                    return false;
//                }
//            }
//        }
//    }
//    return true;
//}

//Report Invariants::check_assertions(const Program& prog) const {
//    Report report;
//
//    for (const auto& [function, invs] : invariants) {
//        const auto& instructions = prog.instructions(function);
//        for (const auto& [label, inv] : invs) {
//            if (inv.pre.is_bottom()) {
//                continue;
//            }
//            const auto& ins = instructions.at(label);
//            for (const Assertion& assertion : get_assertions(ins, *thread_local_program_info, inv.pre.get_frame_prefix().has_value() ? inv.pre.get_frame_prefix().value() : "")) {
//                const auto warnings = ebpf_domain_check(inv.pre, assertion);
//                for (const auto& msg : warnings) {
//                    report.warnings[label].emplace_back(msg);
//                }
//            }
//            if (const auto passume = std::get_if<Assume>(&ins)) {
//                if (inv.post.is_bottom()) {
//                    const auto s = to_string(*passume);
//                    report.reachability[label].emplace_back("Code becomes unreachable (" + s + ")");
//                }
//            }
//        }
//    }
//    return report;
//}

void check_assertions_of_inv(const Instruction& instruction, const Label& function, const Label& label, const std::string& frame_prefix, const EbpfDomain& pre, const EbpfDomain& post, std::vector<std::pair<Label, std::string>>& report) {
    if (pre.is_bottom()) {
        return;
    }
    for (const Assertion& assertion : get_assertions(instruction, *thread_local_program_info, frame_prefix)) {
        const auto warnings = ebpf_domain_check(pre, assertion);
        for (const auto& msg : warnings) {
            report.emplace_back(std::pair{label, frame_prefix + to_string(label) + ":" + msg});
        }
    }

    // Indicates if a path will not be executed at the execution of the program
    //if (const auto passume = std::get_if<Assume>(&instruction)) {
    //    if (post.is_bottom()) {
    //        const auto s = to_string(*passume);
    //        report.emplace_back(std::pair{label, frame_prefix + to_string(label) + ":" + "Code becomes unreachable (" + s + ")"});
    //    }
    //}
}

//void Invariants::check_assertions_at(const Program& prog, const Label& function, const Label& label, const std::string& frame_prefix, std::vector<std::pair<Label, std::string>>& report) {
//    if (shortcut_invariants == nullptr) {
//        const auto invs = invariants.find(function);
//        if (invs == invariants.end()) {
//            CRAB_ERROR("InvariantTable not found");
//        }
//        const auto inv = invs->second.find(label);
//        if (inv == invs->second.end()) {
//            CRAB_ERROR("InvariantMapPair not found");
//        }
//        check_assertions_of_inv(prog, function, label, frame_prefix, inv->second, report);
//    }
//    else {
//        const auto inv = shortcut_invariants->find(label);
//        if (inv == shortcut_invariants->end()) {
//            CRAB_ERROR("InvariantMapPair not found");
//        }
//        check_assertions_of_inv(prog, function, label, frame_prefix, inv->second, report);
//    }
//}

void ebpf_verifier_clear_before_analysis() {
    clear_thread_local_state();
    variable_registry.clear();
}

void ebpf_verifier_clear_thread_local_state() {
    CrabStats::clear_thread_local_state();
    thread_local_program_info.clear();
    clear_thread_local_state();
    SplitDBM::clear_thread_local_state();
}
} // namespace prevail
