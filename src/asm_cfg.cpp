// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <cassert>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "asm_syntax.hpp"
#include "cfg/cfg.hpp"
#include "cfg/wto.hpp"
#include "config.hpp"
#include "program.hpp"

using std::optional;
using std::set;
using std::string;
using std::to_string;
using std::vector;

namespace prevail {

struct CfgBuilder final {
    Program prog;

    CfgBuilder(const Label& entry_point = Label(0)) : prog(Program(entry_point)) {}

    void add_function(const Label& function) {
        prog.m_instructions.insert_or_assign(function, std::map<Label, Instruction>{{Label::entry, Undefined{}}, {Label::exit, Undefined{}}});
        prog.m_cfg.insert_or_assign(function, Cfg());
    }

    // TODO: ins should be inserted elsewhere
    void insert_after(const Label& prev_label, const Label& new_label, const Instruction& ins) {
        if (prog.m_shortcut_cfg == nullptr)
            CRAB_ERROR("Shortcut is null");
        if (prev_label == new_label) {
            CRAB_ERROR("Cannot insert after the same label ", to_string(new_label));
        }

        std::set<Label> prev_children;
        std::swap(prev_children, prog.m_shortcut_cfg->get_node(prev_label).children);

        for (const Label& next_label : prev_children) {
            prog.m_shortcut_cfg->get_node(next_label).parents.erase(prev_label);
        }

        insert(new_label, ins);
        for (const Label& next_label : prev_children) {
            add_child(prev_label, new_label);
            add_child(new_label, next_label);
        }
    }

    // TODO: ins should be inserted elsewhere
    void insert(const Label& _label, const Instruction& ins) {
        if (prog.m_shortcut_cfg == nullptr || prog.m_shortcut_instructions == nullptr)
            CRAB_ERROR("Shortcut is null");
        if (const auto it = prog.m_shortcut_cfg->neighbours.find(_label); it != prog.m_shortcut_cfg->neighbours.end()) {
            CRAB_ERROR("Label ", to_string(_label), " already exists");
        }
        prog.m_shortcut_cfg->neighbours.emplace(_label, Cfg::Adjacent{});
        prog.m_shortcut_instructions->emplace(_label, ins);
    }

    // TODO: ins should be inserted elsewhere
    Label insert_jump(const Label& from, const Label& to, const Instruction& ins) {
        if (prog.m_shortcut_cfg == nullptr)
            CRAB_ERROR("Shortcut is null");
        const Label jump_label = Label::make_jump(from, to);
        if (prog.m_shortcut_cfg->contains(jump_label)) {
            CRAB_ERROR("Jump label ", to_string(jump_label), " already exists");
        }
        insert(jump_label, ins);
        add_child(from, jump_label);
        add_child(jump_label, to);
        return jump_label;
    }

    void add_child(const Label& a, const Label& b) {
        if (prog.m_shortcut_cfg == nullptr)
            CRAB_ERROR("Shortcut is null");
        assert(b != Label::entry);
        assert(a != Label::exit);

        prog.m_shortcut_cfg->neighbours.at(a).children.insert(b);
        prog.m_shortcut_cfg->neighbours.at(b).parents.insert(a);
    }

    void remove_child(const Label& a, const Label& b) {
        if (prog.m_shortcut_cfg == nullptr)
            CRAB_ERROR("Shortcut is null");
        prog.m_shortcut_cfg->get_node(a).children.erase(b);
        prog.m_shortcut_cfg->get_node(b).parents.erase(a);
    }
};

/// Get the inverse of a given comparison operation.
static Condition::Op reverse(const Condition::Op op) {
    switch (op) {
    case Condition::Op::EQ: return Condition::Op::NE;
    case Condition::Op::NE: return Condition::Op::EQ;

    case Condition::Op::GE: return Condition::Op::LT;
    case Condition::Op::LT: return Condition::Op::GE;

    case Condition::Op::SGE: return Condition::Op::SLT;
    case Condition::Op::SLT: return Condition::Op::SGE;

    case Condition::Op::LE: return Condition::Op::GT;
    case Condition::Op::GT: return Condition::Op::LE;

    case Condition::Op::SLE: return Condition::Op::SGT;
    case Condition::Op::SGT: return Condition::Op::SLE;

    case Condition::Op::SET: return Condition::Op::NSET;
    case Condition::Op::NSET: return Condition::Op::SET;
    }
    assert(false);
    return {};
}

/// Get the inverse of a given comparison condition.
static Condition reverse(const Condition& cond) {
    return {.op = reverse(cond.op), .left = cond.left, .right = cond.right, .is64 = cond.is64};
}

static bool has_fall(const Instruction& ins) {
    if (std::holds_alternative<Exit>(ins)) {
        return false;
    }

    if (const auto pins = std::get_if<Jmp>(&ins)) {
        if (!pins->cond) {
            return false;
        }
    }

    return true;
}

// Convert an instruction sequence to a control-flow graph (CFG).
// A CFG is generated for each function.
static CfgBuilder instruction_seq_to_cfg(const InstructionSeq& insts, const std::vector<std::pair<size_t, size_t>>& function_locations, const bool must_have_exit) {
    // Set the entry point of the program.
    // According to read_elf(), insts[0] is the first instruction of the selected function.
    CfgBuilder builder{std::get<0>(insts[0])};
    size_t processed_instructions = 0;
    size_t next_begin = 0;
    size_t sz = 0;

    for (const auto& [begin, end]: function_locations) {
        if ((end <= begin) || (processed_instructions > 0 && next_begin != begin))
            throw InvalidControlFlow("function location is incorrect");

        processed_instructions += (end - begin + 1);
        if (processed_instructions > insts.size())
            throw InvalidControlFlow("function location is out of bounds");

        next_begin = end + 1;

        // First, add the instructions of the function to the CFGs without connecting.
        const Label function = std::get<0>(insts[begin]);
        builder.add_function(function);
        builder.prog.set_shortcut_instructions(function);
        builder.prog.set_shortcut_cfg(function);
        for (size_t i = begin; i < next_begin; ++i) {
            const auto& [label, inst, _0] = insts[i];

            if (std::holds_alternative<Undefined>(inst)) {
                continue;
            }
            else {
                builder.insert(label, inst);
            }
        }
        builder.prog.reset_shortcut_instructions();
        builder.prog.reset_shortcut_cfg();
    }

    // Connect basic blocks.
    for (const auto& [begin, end]: function_locations) {
        const Label function = std::get<0>(insts[begin]);
        const auto& cfg = builder.prog.cfg(function);
        sz += end - begin + 1;
        builder.prog.set_shortcut_instructions(function);
        builder.prog.set_shortcut_cfg(function);

        builder.add_child(cfg.entry_label(), function);
        for (size_t i = begin; i <= end; ++i) {
            const auto& [label, inst, _0] = insts[i];

            if (std::holds_alternative<Undefined>(inst)) {
                continue;
            }

            Label fallthrough{cfg.exit_label()};
            if (i + 1 < sz) {
                fallthrough = std::get<0>(insts[i + 1]);
            } else {
                if (has_fall(inst) && must_have_exit) {
                    throw InvalidControlFlow{"fallthrough in last instruction"};
                }
            }
            if (const auto jmp = std::get_if<Jmp>(&inst)) {
                if (const auto cond = jmp->cond) {
                    Label target_label = jmp->target;
                    if (target_label == fallthrough) {
                        builder.add_child(label, fallthrough);
                        continue;
                    }
                    if (!cfg.contains(target_label)) {
                        throw InvalidControlFlow{"jump to undefined label " + to_string(target_label)};
                    }
                    builder.insert_jump(label, target_label, Assume{.cond = *cond, .is_implicit = true});
                    builder.insert_jump(label, fallthrough, Assume{.cond = reverse(*cond), .is_implicit = true});
                } else {
                    builder.add_child(label, jmp->target);
                }
            } else {
                if (has_fall(inst)) {
                    builder.add_child(label, fallthrough);
                }
            }
            if (const auto call_local = std::get_if<CallLocal>(&inst)) {
                if (call_local->target == function) {
                    throw InvalidControlFlow{to_string(function) + ": illegal recursion"};
                }
                if (builder.prog.cfg().find(call_local->target) == builder.prog.cfg().end()) {
                    throw InvalidControlFlow{"call to undefined subprog " + to_string(call_local->target)};
                }
            }
            if (std::holds_alternative<Exit>(inst)) {
                builder.add_child(label, cfg.exit_label());
            }
        }
        builder.prog.reset_shortcut_instructions();
        builder.prog.reset_shortcut_cfg();
    }
    return builder;
}

Program Program::from_sequence(const InstructionSeq& inst_seq, const std::vector<std::pair<size_t, size_t>>& function_locations, const ProgramInfo& info,
                               const ebpf_verifier_options_t& options) {
    if (function_locations.empty()) {
        throw InvalidControlFlow("cannot determine the locations of functions");
    }

    thread_local_program_info.set(info);
    thread_local_options = options;

    // Convert the instruction sequence to a deterministic control-flow graph.
    CfgBuilder builder = instruction_seq_to_cfg(inst_seq, function_locations, options.cfg_opts.must_have_exit);

    for (const auto& [function, cfg] : builder.prog.cfg()) {
        builder.prog.set_shortcut_instructions(function);
        builder.prog.set_shortcut_cfg(function);

        // Compute the Weak Topological Ordering (WTO) of each CFG. WTO provides a hierarchical decomposition of a CFG
        // that identifies all strongly connected components (cycles) and their entry points. These entry points serve as
        // natural locations for loop counters that help verify program termination.
        builder.prog.m_wto.insert_or_assign(function, Wto{cfg});
        if (options.cfg_opts.check_for_termination) {
            builder.prog.m_wto.at(function).for_each_cycle([&](const std::shared_ptr<WtoCycle> component) -> void {
                const Label& head = component->head();
                builder.insert_after(head, Label::make_increment_counter(head), IncrementLoopCounter{head});
                component->insert_after_head(Label::make_increment_counter(head));
            });
        }
        builder.prog.reset_shortcut_instructions();
        builder.prog.reset_shortcut_cfg();
    }

    return std::move(builder.prog);
}

std::set<BasicBlock> BasicBlock::collect_basic_blocks(const Cfg& cfg, const bool simplify) {
    std::set<BasicBlock> res;
    if (!simplify) {
        for (const Label& label : cfg.labels()) {
            if (label != cfg.entry_label() && label != cfg.exit_label()) {
                res.insert(BasicBlock{label});
            }
        }
        return res;
    }

    std::set<Label> worklist;
    for (const Label& label : cfg.labels()) {
        worklist.insert(label);
    }
    std::set<Label> seen;
    while (!worklist.empty()) {
        Label label = *worklist.begin();
        worklist.erase(label);
        if (seen.contains(label)) {
            continue;
        }
        seen.insert(label);

        if (cfg.in_degree(label) == 1 && cfg.num_siblings(label) == 1) {
            continue;
        }
        BasicBlock bb{label};
        while (cfg.out_degree(label) == 1) {
            const Label& next_label = cfg.get_child(bb.last_label());

            if (seen.contains(next_label) || next_label == cfg.exit_label() || cfg.in_degree(next_label) != 1) {
                break;
            }

            if (bb.first_label() == cfg.entry_label()) {
                // Entry instruction is Undefined. We want to start with 0
                bb.m_ts.clear();
            }
            bb.m_ts.push_back(next_label);

            worklist.erase(next_label);
            seen.insert(next_label);

            label = next_label;
        }
        res.emplace(std::move(bb));
    }
    return res;
}

/// Get the type of given Instruction.
/// Most of these type names are also statistics header labels.
static std::string instype(Instruction ins) {
    if (const auto pcall = std::get_if<Call>(&ins)) {
        if (pcall->is_map_lookup) {
            return "call_1";
        }
        if (pcall->pairs.empty()) {
            if (std::ranges::all_of(pcall->singles,
                                    [](const ArgSingle kr) { return kr.kind == ArgSingle::Kind::ANYTHING; })) {
                return "call_nomem";
            }
        }
        return "call_mem";
    } else if (std::holds_alternative<Callx>(ins)) {
        return "callx";
    } else if (const auto pimm = std::get_if<Mem>(&ins)) {
        return pimm->is_load ? "load" : "store";
    } else if (std::holds_alternative<Atomic>(ins)) {
        return "load_store";
    } else if (std::holds_alternative<Packet>(ins)) {
        return "packet_access";
    } else if (const auto pins = std::get_if<Bin>(&ins)) {
        switch (pins->op) {
        case Bin::Op::MOV:
        case Bin::Op::MOVSX8:
        case Bin::Op::MOVSX16:
        case Bin::Op::MOVSX32: return "assign";
        default: return "arith";
        }
    } else if (std::holds_alternative<Un>(ins)) {
        return "arith";
    } else if (std::holds_alternative<LoadMapFd>(ins)) {
        return "assign";
    } else if (std::holds_alternative<LoadMapAddress>(ins)) {
        return "assign";
    } else if (std::holds_alternative<Assume>(ins)) {
        return "assume";
    } else {
        return "other";
    }
}

std::vector<std::string> stats_headers() {
    return {
        "instructions", "joins",      "other",      "jumps",         "assign",  "arith",
        "load",         "store",      "load_store", "packet_access", "call_1",  "call_mem",
        "call_nomem",   "reallocate", "map_in_map", "arith64",       "arith32",
    };
}

std::map<std::string, int> collect_stats(const Program& prog) {
    std::map<std::string, int> res;
    for (const auto& h : stats_headers()) {
        res[h] = 0;
    }

    for (const auto& [function, cfg] : prog.cfg()) {
        prog.set_shortcut_instructions(function);
        for (const auto& label : cfg.labels()) {
            res["instructions"]++;
            const auto cmd = prog.instruction_at(label);
            if (const auto pins = std::get_if<LoadMapFd>(&cmd)) {
                if (pins->mapfd == -1) {
                    res["map_in_map"] = 1;
                }
            }
            if (const auto pins = std::get_if<Call>(&cmd)) {
                if (pins->reallocate_packet) {
                    res["reallocate"] = 1;
                }
            }
            if (const auto pins = std::get_if<Bin>(&cmd)) {
                res[pins->is64 ? "arith64" : "arith32"]++;
            }
            res[instype(cmd)]++;
            if (cfg.in_degree(label) > 1) {
                res["joins"]++;
            }
            if (cfg.out_degree(label) > 1) {
                res["jumps"]++;
            }
        }
        prog.reset_shortcut_instructions();
    }

    return res;
}

Cfg cfg_from_adjacency_list(const std::map<Label, std::vector<Label>>& AdjList) {
    CfgBuilder builder;
    Label function = Label(0);

    builder.add_function(Label(0));
    builder.prog.set_shortcut_instructions(function);
    builder.prog.set_shortcut_cfg(function);

    for (const auto& label : std::views::keys(AdjList)) {
        if (label == Label::entry || label == Label::exit) {
            continue;
        }
        builder.insert(label, Undefined{});
    }
    for (const auto& [label, children] : AdjList) {
        for (const auto& child : children) {
            builder.add_child(label, child);
        }
    }

    builder.prog.reset_shortcut_instructions();
    builder.prog.reset_shortcut_cfg();

    return std::move(builder.prog.cfg(function));
}

// Returns a vector of pairs, each containing the start and the end indices of a function in the instruction sequence.
std::optional<std::vector<std::pair<size_t, size_t>>> get_function_locations(const InstructionSeq& inst_seq) {
    std::vector<std::pair<size_t, size_t>> function_locations;
    std::set<size_t> functions;
    functions.emplace(0); //main function

    for (const auto&[_0, inst, _1] : inst_seq) {
        if (const auto call_local = std::get_if<CallLocal>(&inst))
            functions.insert(call_local->target.from);
    }

    std::vector<size_t> sorted_functions(functions.begin(), functions.end());
    sorted_functions.emplace_back(inst_seq.size());
    std::sort(sorted_functions.begin(), sorted_functions.end(), [](int a, int b) {return a < b;});

    size_t begin = sorted_functions[0];
    size_t end;

    for (size_t i = 1; i < sorted_functions.size(); ++i) {
        end = sorted_functions[i];
        if (end - 1 <= begin)
            return std::nullopt;
        function_locations.emplace_back(std::pair{begin, end - 1});
        begin = end;
    }

    return function_locations;
}

size_t call_stack_depth(const std::string& frame_prefix) {
    // The call stack depth is the number of '/' separated components in the prefix,
    // which is one more than the number of '/' separated components in the prefix,
    // hence two more than the number of '/' in the prefix, if any.
    if (frame_prefix.empty()) {
        return 1;
    }
    return gsl::narrow<int>(2 + std::ranges::count(frame_prefix, STACK_FRAME_DELIMITER));
}

} // namespace prevail
