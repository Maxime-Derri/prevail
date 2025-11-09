// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <map>
#include <vector>
#include <optional>

#include "asm_syntax.hpp"
#include "cfg/cfg.hpp"
#include "cfg/wto.hpp"
#include "cfg/label.hpp"
#include "config.hpp"
#include "crab_utils/debug.hpp"

namespace prevail {
class Program {
    friend struct CfgBuilder;

    const Label entry_point; // Index of the main function (the prog)

    mutable std::map<Label, std::map<Label, Instruction>> m_instructions;

    // These maps can be accessed through the target of CallLocal instructions.
    mutable std::map<Label, Cfg> m_cfg; // Maps the label of the first instruction of a function (not Label::entry) to its CFG.
    mutable std::map<Label, Wto> m_wto; // Maps the label of the first intruction of a CFG (not Label::entry) to its WTO.

    // These pointers are shortcuts to the values of the maps currently in use
    mutable std::map<Label, Instruction> *m_shortcut_instructions = nullptr;
    mutable Cfg *m_shortcut_cfg = nullptr;
    mutable Wto *m_shortcut_wto = nullptr;

    // TODO: add ProgramInfo field

  public:
    explicit Program(const Label entry_point = Label(0)) : entry_point{std::move(entry_point)} {};

    const std::map<Label, Cfg>& cfg() const { return m_cfg; }
    const Cfg& cfg(const Label& function) const { return m_cfg.at(function); }

    const std::map<Label, Wto>& wto() const { return m_wto; }
    const Wto& wto(const Label& function) const { return m_wto.at(function); }

    const std::map<Label, std::map<Label, Instruction>>& instructions() const { return m_instructions; }
    const std::map<Label, Instruction>& instructions(const Label& function) const { return m_instructions.at(function); }


    const Label& get_entry_point() const {
        return entry_point;
    }

    void set_shortcut_instructions(const Label& function) const {
        if (m_shortcut_instructions != nullptr) {
            CRAB_ERROR("Shortcut is already in use");
        }
        const auto instructions = m_instructions.find(function);
        if (instructions == m_instructions.end()){
            CRAB_ERROR("Function does not exist, cannot set shortcut");
        }
        m_shortcut_instructions = &(instructions->second);
    }

    void set_shortcut_cfg(const Label& function) const {
        if (m_shortcut_cfg != nullptr) {
            CRAB_ERROR("Shortcut is already in use");
        }
        const auto cfg = m_cfg.find(function);
        if (cfg == m_cfg.end()) {
            CRAB_ERROR("Function does not exist, cannot set shortcut");
        }
        m_shortcut_cfg = &(cfg->second);
    }

    void set_shortcut_wto(const Label& function) const {
        if (m_shortcut_wto != nullptr) {
            CRAB_ERROR("Shortcut is already in use");
        }
        const auto wto = m_wto.find(function);
        if (wto == m_wto.end()) {
            CRAB_ERROR("Function does not exist, cannot set shortcut");
        }
        m_shortcut_wto = &(wto->second);
    }

    void reset_shortcut_instructions() const {
        m_shortcut_instructions = nullptr;
    }

    void reset_shortcut_cfg() const {
        m_shortcut_cfg = nullptr;
    }

    void reset_shortcut_wto() const {
        m_shortcut_wto = nullptr;
    }

    //! return a view of the labels, including entry and exit
    [[nodiscard]]
    auto labels(const Label& function) const {
        return m_cfg.at(function).labels();
    }

    //! return a view of the labels, including entry and exit
    [[nodiscard]]
    auto labels() const {
        if (m_shortcut_cfg == nullptr) {
            CRAB_ERROR("Shortcut is null");
        }
        return m_shortcut_cfg->labels();
    }

    const Instruction& instruction_at(const Label& function, const Label& label) const {
        const auto& instructions = m_instructions.at(function);
        if (!instructions.contains(label)) {
            CRAB_ERROR("Label ", to_string(label), " not found in the CFG: ");
        }
        return instructions.at(label);
    }

    const Instruction& instruction_at(const Label& label) const {
        if (m_shortcut_instructions == nullptr) {
            CRAB_ERROR("Shortcut is null");
        }
        if (!m_shortcut_instructions->contains(label)) {
            CRAB_ERROR("Label ", to_string(label), " not found in the CFG: ");
        }
        return m_shortcut_instructions->at(label);
    }

    Instruction& instruction_at(const Label& function, const Label& label) {
        auto& instructions = m_instructions.at(function);
        if (!instructions.contains(label)) {
            CRAB_ERROR("Label ", to_string(label), " not found in the CFG: ");
        }
        return instructions.at(label);
    }

    Instruction& instruction_at(const Label& label) {
        if (m_shortcut_instructions == nullptr) {
            CRAB_ERROR("Shortcut is null");
        }
        if (!m_shortcut_instructions->contains(label)) {
            CRAB_ERROR("Label ", to_string(label), " not found in the CFG: ");
        }
        return m_shortcut_instructions->at(label);
    }

    static Program from_sequence(const InstructionSeq& inst_seq, const std::vector<std::pair<size_t, size_t>>& function_locations,
                                    const ProgramInfo& info, const ebpf_verifier_options_t& options);
};

class InvalidControlFlow final : public std::runtime_error {
  public:
    explicit InvalidControlFlow(const std::string& what) : std::runtime_error(what) {}
};

std::vector<Assertion> get_assertions(const Instruction& ins, const ProgramInfo& info, const std::string& frame_prefix);

std::optional<std::vector<std::pair<size_t, size_t>>> get_function_locations(const InstructionSeq& inst_seq);

std::vector<std::string> stats_headers();
std::map<std::string, int> collect_stats(const Program& prog);

using printfunc = std::function<void(std::ostream&, const Label& label)>;
void print_program(const Program& prog, std::ostream& os, bool simplify, const printfunc& prefunc,
                   const printfunc& postfunc);
void print_program(const Program& prog, std::ostream& os, bool simplify);
void print_dot(const Program& prog, const std::string& outfile);
void print_dot_unroll(const Program& prog, const std::string& outfile);
} // namespace prevail
