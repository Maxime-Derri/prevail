// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include <utility>
#include <variant>

#include "cfg/cfg.hpp"
#include "cfg/wto.hpp"
#include "config.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab_verifier.hpp"
#include "crab/fwd_analyzer.hpp"
#include "program.hpp"

namespace prevail {

class InterleavedFwdFixpointIterator final {
    const Program& _prog;
    mutable InvariantTable _inv;

    mutable std::map<Label, InvariantMapPair> *_shortcut_invariants = nullptr;
    std::stack<Label> _frames;
    std::stack<std::string> _frame_prefixes;

    std::vector<std::pair<Label, std::string>> _report;

    /// number of narrowing iterations. If the narrowing operator is
    /// indeed a narrowing operator this parameter is not
    /// needed. However, there are abstract domains for which an actual
    /// narrowing operation is not available so we must enforce
    /// termination.
    static constexpr unsigned int _descending_iterations = 2000000;

    /// Used to skip the analysis until _entry is found
    bool _skip{true};

    bool _check_assertions = false;
    size_t _wto_cycle_level = 0; // 0 means the analysis is not in a cycle

    bool get_check_assertions() { return _check_assertions; }

    void set_check_assertions (bool b) { _check_assertions = b; }

    size_t get_wto_cycle_level() { return _wto_cycle_level; }
    void incr_wto_cycle_level() { ++_wto_cycle_level; }
    void decr_wto_cycle_level() { --_wto_cycle_level; }

    void set_shortcut_invariants(const Label& function) const {
        if (_shortcut_invariants != nullptr) {
            CRAB_ERROR("Shortcut is already in use");
        }
        const auto invariants =_inv.find(function);
        if (invariants == _inv.end()){
            _inv.insert_or_assign(function, std::map<Label, InvariantMapPair>());
            _shortcut_invariants = &(_inv.at(function));
        }
        else {
            _shortcut_invariants = &(invariants->second);
        }
    }

    void reset_shortcut_invariants() const {
        _shortcut_invariants = nullptr;
    }

    void set_pre(const Label& function, const Label& label, EbpfDomain& v) {
        switch (label.special_label)
        {
        case SpecialLabel::Exit:
            if (_frames.size() > 1) {
                v.set_frame_prefix(_frame_prefixes.top());
            }
            break;
        case SpecialLabel::CallLocal:
        case SpecialLabel::Call:
            v.set_frame_prefix(_frame_prefixes.top());
            break;
        default:
            break;
        }

        const auto invariants = _inv.find(function);
        if (invariants == _inv.end()) {
            _inv[function][label] = InvariantMapPair{v, EbpfDomain::bottom()};
            return;
        }

        const auto inv = invariants->second.find(label);

        if (inv == invariants->second.end()) {
            invariants->second[label] = InvariantMapPair{v, EbpfDomain::bottom()};
            return;
        }

        invariants->second[label].pre = v;
    }

    void set_pre(const Label& label, EbpfDomain& v) {
        if (_shortcut_invariants == nullptr) {
            CRAB_ERROR("Shortcut is null");
        }

        switch (label.special_label)
        {
        case SpecialLabel::Exit:
            if (_frames.size() > 1) {
                v.set_frame_prefix(_frame_prefixes.top());
            }
            break;
        case SpecialLabel::CallLocal:
        case SpecialLabel::Call:
            v.set_frame_prefix(_frame_prefixes.top());
            break;
        default:
            break;
        }

        const auto inv = _shortcut_invariants->find(label);

        if (inv == _shortcut_invariants->end()) {
            (*_shortcut_invariants)[label] = InvariantMapPair{v, EbpfDomain::bottom()};
            return;
        }

        (*_shortcut_invariants)[label].pre = v;
    }

    EbpfDomain& get_pre(const Label& function, const Label& node) const {
        const auto invariants = _inv.find(function);
        if (invariants == _inv.end()) {
            _inv[function][node] = InvariantMapPair{EbpfDomain::bottom(), EbpfDomain::bottom()};
            return _inv[function][node].pre;
        }

        const auto inv = invariants->second.find(node);

        if (inv == invariants->second.end()) {
            invariants->second[node] = InvariantMapPair{EbpfDomain::bottom(), EbpfDomain::bottom()};
            return invariants->second[node].pre;
        }

        return inv->second.pre;
    }

    EbpfDomain& get_pre(const Label& node) const {
        if (_shortcut_invariants == nullptr) {
            CRAB_ERROR("Shortcut is null");
        }

        const auto inv = _shortcut_invariants->find(node);

        if (inv == _shortcut_invariants->end()) {
            (*_shortcut_invariants)[node] = InvariantMapPair{EbpfDomain::bottom(), EbpfDomain::bottom()};
            return (*_shortcut_invariants)[node].pre;
        }

        return inv->second.pre;
    }

    EbpfDomain& get_post(const Label& function, const Label& node) const {
        const auto invariants = _inv.find(function);
        if (invariants == _inv.end()) {
            _inv[function][node] = InvariantMapPair{EbpfDomain::bottom(), EbpfDomain::bottom()};
            return _inv[function][node].post;
        }

        const auto inv = invariants->second.find(node);

        if (inv == invariants->second.end()){
            invariants->second[node] = InvariantMapPair{EbpfDomain::bottom(), EbpfDomain::bottom()};
            return invariants->second[node].post;
        }

        return inv->second.post;
    }

    EbpfDomain& get_post(const Label& node) const {
        if (_shortcut_invariants == nullptr) {
            CRAB_ERROR("Shortcut is null");
        }

        const auto inv = _shortcut_invariants->find(node);

        if (inv == _shortcut_invariants->end()) {
            (*_shortcut_invariants)[node] = InvariantMapPair{EbpfDomain::bottom(), EbpfDomain::bottom()};
            return (*_shortcut_invariants)[node].post;
        }

        return inv->second.post;
    }

    void set_post(const Label& function, const Label& label, const EbpfDomain& v) {
        auto invariants = _inv.find(function);
        if (invariants == _inv.end()) {
            _inv[function][label] = InvariantMapPair{EbpfDomain::bottom(), v};
            return;
        }

        const auto inv = invariants->second.find(label);

        if (inv == invariants->second.end()) {
            invariants->second[label] = InvariantMapPair{EbpfDomain::bottom(), v};
            return;
        }

        invariants->second[label].post = v;
    }

    void set_post(const Label& label, const EbpfDomain& v) {
        if (_shortcut_invariants == nullptr) {
            CRAB_ERROR("Shortcut is null");
        }

        const auto inv = _shortcut_invariants->find(label);

        if (inv == _shortcut_invariants->end()) {
            (*_shortcut_invariants)[label] = InvariantMapPair{EbpfDomain::bottom(), v};
            return;
        }

        (*_shortcut_invariants)[label].post = v;
    }

    //set special
    void transform_to_post(const Label& label, EbpfDomain pre) {

        switch (label.special_label)
        {
        case SpecialLabel::Exit:
            if (_frames.size() > 1) {
                pre.set_frame_prefix(_frame_prefixes.top());
            }
            break;
        case SpecialLabel::CallLocal:
        case SpecialLabel::Call:
            pre.set_frame_prefix(_frame_prefixes.top());
            break;
        default:
            break;
        }

        //if (thread_local_options.assume_assertions) {
        //    for (const auto& assertion : _prog.assertions_at(label)) {
        //        // avoid redundant errors
        //        ebpf_domain_assume(pre, assertion);
        //    }
        //}

        ebpf_domain_transform(pre, _prog.instruction_at(label));

        set_post(label, pre);
        //_inv.at(label).post = std::move(pre);
    }

    EbpfDomain join_all_prevs(const Label& node) const {
        if(_shortcut_invariants == nullptr) {
            CRAB_ERROR("Shortcut is null");
        }
        const Cfg& cfg = _prog.cfg(_frames.top());
        if (node == cfg.entry_label()) {
            return get_pre(node);
        }
        EbpfDomain res = EbpfDomain::bottom();
        for (const Label& prev : cfg.parents_of(node)) {
            res |= get_post(prev);
        }
        return res;
    }

    void print_invariants(const InvariantMapPair& invariant, const Label label, const Instruction& ins) {
        std::cout << "\nPre-invariant : " << invariant.pre << std::endl;

        std::cout << _frame_prefixes.top() << to_string(label) << ":" << std::endl;
        std::cout << to_string(ins) << std::endl;

        std::cout << "\nPost-invariant : " << invariant.post << std::endl;
    }

    explicit InterleavedFwdFixpointIterator(const Program& prog) : _prog(prog)  {}

  public:
    void operator()(const Label& node);

    void operator()(const std::shared_ptr<WtoCycle>& cycle);

    friend void run_forward_analyzer_function(InterleavedFwdFixpointIterator& analyzer);
    friend std::vector<std::pair<Label, std::string>> run_forward_analyzer(const Program& prog, EbpfDomain entry_inv);

    const Program& get_program() {
        return _prog;
    }

    std::stack<Label>& get_frames() {
        return _frames;
    }

    std::stack<std::string>& get_frame_prefixes() {
        return _frame_prefixes;
    }

};

void run_forward_analyzer_function(InterleavedFwdFixpointIterator& analyzer) {
    // Check whether the number of function frames exceeds the limit.
    if (((long)std::ranges::count(analyzer.get_frame_prefixes().top(), STACK_FRAME_DELIMITER) + 2) >= MAX_CALL_STACK_FRAMES) {
        throw InvalidControlFlow{"too many call stack frames"};
    }

    // _frames.top() was set before the call to run_forward_analyzer_function(). pop() is called in the caller function.
    for (const auto& component : analyzer.get_program().wto(analyzer._frames.top())) {
        std::visit(analyzer, component); // Return when component has reached a fixpoint

        // Check assertions
        if (!analyzer.get_check_assertions() && analyzer.get_wto_cycle_level() == 0 && analyzer.get_frames().size() == 1) {
            analyzer.set_check_assertions(true);
            std::visit(analyzer, component);
            analyzer.set_check_assertions(false);
        }
    }
}

std::vector<std::pair<Label, std::string>> run_forward_analyzer(const Program& prog, EbpfDomain entry_inv) {
    // Go over the CFG in weak topological order (accounting for loops).
    InterleavedFwdFixpointIterator analyzer(prog);

    /*
    if (thread_local_options.cfg_opts.check_for_termination) {
        // Initialize loop counters for potential loop headers.
        // This enables enforcement of upper bounds on loop iterations
        // during program verification.
        // TODO: Consider making this an instruction instead of an explicit call.
        analyzer._wto.for_each_loop_head(
            [&](const Label& label) { ebpf_domain_initialize_loop_counter(entry_inv, label); });
    }
    */

    const auto& entry_point = prog.get_entry_point();
    analyzer.get_frames().push(entry_point);
    analyzer.get_frame_prefixes().push("");

    analyzer.get_program().set_shortcut_instructions(entry_point);
    analyzer.get_program().set_shortcut_cfg(entry_point);
    analyzer.set_shortcut_invariants(entry_point);
    analyzer.set_pre(prog.cfg(entry_point).entry_label(), entry_inv);
    run_forward_analyzer_function(analyzer);
    analyzer.get_program().reset_shortcut_instructions();
    analyzer.get_program().reset_shortcut_cfg();
    analyzer.reset_shortcut_invariants();

    analyzer.get_frames().pop();
    analyzer.get_frame_prefixes().pop();

    if (analyzer.get_frames().size() != analyzer.get_frame_prefixes().size() || analyzer.get_frames().size() != 0) {
        throw InvalidControlFlow("Invalid control flow in forward analyzer");
    }

    return std::move(analyzer._report);
}

static EbpfDomain extrapolate(const EbpfDomain& before, const EbpfDomain& after, const unsigned int iteration) {
    /// number of iterations until triggering widening
    constexpr auto _widening_delay = 2;

    if (iteration < _widening_delay) {
        return before | after;
    }
    return before.widen(after, iteration == _widening_delay);
}

static EbpfDomain refine(const EbpfDomain& before, const EbpfDomain& after, const unsigned int iteration) {
    if (iteration == 1) {
        return before & after;
    } else {
        return before.narrow(after);
    }
}

void InterleavedFwdFixpointIterator::operator()(const Label& node) {
    /** decide whether skip vertex or not **/
    if (_skip && node == _prog.cfg(_frames.top()).entry_label()) {
        _skip = false;
    }
    if (_skip) {
        return;
    }

    if (_check_assertions) {
        check_assertions_of_inv(_prog.instruction_at(node), _frames.top(), node, _frame_prefixes.top(), get_pre(node), get_post(node), _report);

        if (thread_local_options.verbosity_opts.print_invariants) {
            print_invariants(InvariantMapPair{get_pre(node), get_post(node)}, node, _prog.instruction_at(node));
        }

        if (node.special_label == SpecialLabel::CallLocal) {
            const auto call_local = std::get_if<CallLocal>(&(_prog.instruction_at(node)));
            _skip = true; // Reset as the verifier is about to iter over another CFG.

            // Update the verification step to check the invariants of the function
            _prog.reset_shortcut_instructions();
            _prog.reset_shortcut_cfg();
            reset_shortcut_invariants();
            _prog.set_shortcut_instructions(call_local->target);
            _prog.set_shortcut_cfg(call_local->target);
            set_shortcut_invariants(call_local->target);
            _frames.push(call_local->target);
            _frame_prefixes.push(_frame_prefixes.top() + to_string(node) + "/");

            // Check the function.
            run_forward_analyzer_function(*this);

            // Restore current verification state
            _prog.reset_shortcut_instructions();
            _prog.reset_shortcut_cfg();
            reset_shortcut_invariants();
            _frames.pop();
            _frame_prefixes.pop();
            _prog.set_shortcut_instructions(_frames.top());
            _prog.set_shortcut_cfg(_frames.top());
            set_shortcut_invariants(_frames.top());
            _skip = false;
        }
    }
    else {
        EbpfDomain pre = join_all_prevs(node);
        set_pre(node, pre);
        transform_to_post(node, std::move(pre));
        if (node.special_label == SpecialLabel::CallLocal) {
            const auto call_local = std::get_if<CallLocal>(&(_prog.instruction_at(node)));
            _skip = true; // Reset as the verifier is about to iter over another CFG.

            pre = get_post(node); // get the current post.

            // Update the verification step for the function to be verified
            _prog.reset_shortcut_instructions();
            _prog.reset_shortcut_cfg();
            reset_shortcut_invariants();
            _prog.set_shortcut_instructions(call_local->target);
            _prog.set_shortcut_cfg(call_local->target);
            set_shortcut_invariants(call_local->target);
            _frames.push(call_local->target);
            _frame_prefixes.push(_frame_prefixes.top() + to_string(node) + "/");
            set_pre(_prog.cfg(call_local->target).entry_label(), pre); // Set the entry pre-invariant for the function to be verified.

            // Check the function.
            run_forward_analyzer_function(*this);
            // Return from function.

            // Restore current verification state
            _prog.reset_shortcut_instructions();
            _prog.reset_shortcut_cfg();
            reset_shortcut_invariants();
            _frames.pop();
            _frame_prefixes.pop();
            // Set the CallLocal post-invariant as the exit post-invariant of the verified function
            set_post(node, _frames.top(), get_post(call_local->target, _prog.cfg(call_local->target).exit_label()));
            _prog.set_shortcut_instructions(_frames.top());
            _prog.set_shortcut_cfg(_frames.top());
            set_shortcut_invariants(_frames.top());
            _skip = false;
        }
    }
}

void InterleavedFwdFixpointIterator::operator()(const std::shared_ptr<WtoCycle>& cycle) {
    const Label head = cycle->head();

    /** decide whether to skip cycle or not **/
    const auto& cfg = _prog.cfg(_frames.top());
    bool entry_in_this_cycle = false;
    if (_skip) {
        // We only skip the analysis of cycle if entry_label is not a
        // component of it, included nested components.
        entry_in_this_cycle = is_component_member(cfg.entry_label(), cycle);
        _skip = !entry_in_this_cycle;
        if (_skip) {
            return;
        }
    }


    if (_check_assertions) {
        incr_wto_cycle_level();

        check_assertions_of_inv(_prog.instruction_at(head), _frames.top(), head, _frame_prefixes.top(), get_pre(head), get_post(head), _report);
        if (thread_local_options.verbosity_opts.print_invariants) {
            print_invariants(InvariantMapPair{get_pre(head), get_post(head)}, head, _prog.instruction_at(head));
        }
        for (const auto& component : *cycle) {
            std::visit(*this, component);
        }

        decr_wto_cycle_level();
        return;
    }


    EbpfDomain invariant = EbpfDomain::bottom();

    incr_wto_cycle_level();

    if (entry_in_this_cycle) {
        invariant = get_pre(cfg.entry_label());
    } else {
        const auto& wto = _prog.wto(_frames.top());
        const WtoNesting cycle_nesting = wto.nesting(head);
        for (const Label& prev : cfg.parents_of(head)) {
            if (!(wto.nesting(prev) > cycle_nesting)) {
                invariant |= get_post(prev);
            }
        }
    }

    for (unsigned int iteration = 1;; ++iteration) {
        // Increasing iteration sequence with widening
        set_pre(head, invariant);
        transform_to_post(head, invariant);
        for (const auto& component : *cycle) {
            const auto plabel = std::get_if<Label>(&component);
            if (!plabel || *plabel != head) {
                std::visit(*this, component);
            }
        }
        EbpfDomain new_pre = join_all_prevs(head);
        if (new_pre <= invariant) {
            // Post-fixpoint reached
            set_pre(head, new_pre);
            invariant = std::move(new_pre);
            break;
        } else {
            invariant = extrapolate(invariant, new_pre, iteration);
        }
    }

    for (unsigned int iteration = 1;; ++iteration) {
        // Decreasing iteration sequence with narrowing
        transform_to_post(head, invariant);

        for (const auto& component : *cycle) {
            const auto plabel = std::get_if<Label>(&component);
            if (!plabel || *plabel != head) {
                std::visit(*this, component);
            }
        }
        EbpfDomain new_pre = join_all_prevs(head);
        if (invariant <= new_pre) {
            // No more refinement possible(pre == new_pre)
            break;
        } else {
            if (iteration > _descending_iterations) {
                break;
            }
            invariant = refine(invariant, new_pre, iteration);
            set_pre(head, invariant);
        }
    }

    decr_wto_cycle_level();
}

} // namespace prevail
