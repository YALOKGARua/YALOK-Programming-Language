#include "yalok/interpreter.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <random>

namespace yalok {

Environment::Environment(Environment* parent) : parent_(parent) {}

void Environment::define(const std::string& name, Value val, bool is_cell) {
    vars_[name] = {std::move(val), is_cell};
}

Value& Environment::get(const std::string& name) {
    auto it = vars_.find(name);
    if (it != vars_.end()) return it->second.value;
    if (parent_) return parent_->get(name);
    throw RuntimeError("undefined: '" + name + "'");
}

void Environment::set(const std::string& name, const Value& val) {
    auto it = vars_.find(name);
    if (it != vars_.end()) {
        if (!it->second.is_cell)
            throw RuntimeError("'" + name + "' is immutable (use 'cell' to make it mutable)");
        it->second.value = val;
        return;
    }
    if (parent_) { parent_->set(name, val); return; }
    throw RuntimeError("undefined: '" + name + "'");
}

bool Environment::has(const std::string& name) const {
    if (vars_.count(name)) return true;
    if (parent_) return parent_->has(name);
    return false;
}

Interpreter::Interpreter() : global_(std::make_unique<Environment>()) {
    registerBuiltins();
}

void Interpreter::registerBuiltins() {
    global_->define("emit", Value(NativeFn([](std::vector<Value>& args) -> Value {
        for (size_t i = 0; i < args.size(); ++i) {
            if (i) std::cout << " ";
            std::cout << args[i].toString();
        }
        return Value();
    })));

    global_->define("echo", Value(NativeFn([](std::vector<Value>& args) -> Value {
        for (size_t i = 0; i < args.size(); ++i) {
            if (i) std::cout << " ";
            std::cout << args[i].toString();
        }
        std::cout << "\n";
        return Value();
    })));

    global_->define("size", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.empty()) throw RuntimeError("size() takes 1 argument");
        if (args[0].isStr()) return Value(static_cast<int64_t>(args[0].asStr().size()));
        if (args[0].isBuf()) return Value(static_cast<int64_t>(args[0].asBuf().size()));
        throw RuntimeError("size() expects str or buf");
    })));

    global_->define("hex", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.empty()) throw RuntimeError("hex() takes 1 argument");
        return Value(args[0].toHex());
    })));

    global_->define("bits", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.empty()) throw RuntimeError("bits() takes 1 argument");
        if (!args[0].isInt()) throw RuntimeError("bits() expects i64");
        std::string result = "0b";
        int64_t val = args[0].asInt();
        if (val == 0) return Value(std::string("0b0"));
        bool started = false;
        for (int i = 63; i >= 0; --i) {
            if (val & (1LL << i)) { started = true; result += '1'; }
            else if (started) result += '0';
        }
        return Value(result);
    })));

    global_->define("alloc", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.empty() || !args[0].isInt()) throw RuntimeError("alloc() takes i64 size");
        auto sz = args[0].asInt();
        if (sz < 0 || sz > 1024 * 1024 * 64)
            throw RuntimeError("alloc() size out of range");
        return Value(Value::Buf(static_cast<size_t>(sz), 0));
    })));

    global_->define("hexdump", Value(NativeFn([this](std::vector<Value>& args) -> Value {
        if (args.empty()) throw RuntimeError("hexdump() takes 1 argument");
        if (args[0].isBuf()) hexdump(args[0].asBuf());
        else std::cout << args[0].toString() << "\n";
        return Value();
    })));

    global_->define("identify", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.empty()) throw RuntimeError("identify() takes 1 argument");
        return Value(args[0].typeName());
    })));

    global_->define("str", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.empty()) throw RuntimeError("str() takes 1 argument");
        return Value(args[0].toString());
    })));

    global_->define("i64", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.empty()) throw RuntimeError("i64() takes 1 argument");
        if (args[0].isInt()) return args[0];
        if (args[0].isFloat()) return Value(static_cast<int64_t>(args[0].asFloat()));
        if (args[0].isStr()) return Value(std::stoll(args[0].asStr()));
        if (args[0].isBool()) return Value(static_cast<int64_t>(args[0].asBool()));
        throw RuntimeError("cannot convert to i64");
    })));

    global_->define("f64", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.empty()) throw RuntimeError("f64() takes 1 argument");
        if (args[0].isFloat()) return args[0];
        if (args[0].isInt()) return Value(static_cast<double>(args[0].asInt()));
        if (args[0].isStr()) return Value(std::stod(args[0].asStr()));
        throw RuntimeError("cannot convert to f64");
    })));

    global_->define("input", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (!args.empty()) std::cout << args[0].toString();
        std::string line;
        std::getline(std::cin, line);
        return Value(line);
    })));

    global_->define("tick", Value(NativeFn([](std::vector<Value>&) -> Value {
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        return Value(static_cast<int64_t>(ms));
    })));

    global_->define("rand", Value(NativeFn([](std::vector<Value>& args) -> Value {
        static std::mt19937_64 rng(std::random_device{}());
        if (args.size() >= 2 && args[0].isInt() && args[1].isInt()) {
            std::uniform_int_distribution<int64_t> dist(args[0].asInt(), args[1].asInt());
            return Value(dist(rng));
        }
        std::uniform_int_distribution<int64_t> dist(0, INT64_MAX);
        return Value(dist(rng));
    })));

    global_->define("push", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.size() < 2 || !args[0].isBuf() || !args[1].isInt())
            throw RuntimeError("push() expects (buf, i64)");
        args[0].asBuf().push_back(static_cast<uint8_t>(args[1].asInt() & 0xFF));
        return Value();
    })));

    global_->define("pop", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.empty() || !args[0].isBuf()) throw RuntimeError("pop() expects buf");
        if (args[0].asBuf().empty()) throw RuntimeError("pop() on empty buf");
        auto val = args[0].asBuf().back();
        args[0].asBuf().pop_back();
        return Value(static_cast<int64_t>(val));
    })));

    global_->define("slice", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.size() < 3 || !args[0].isBuf() || !args[1].isInt() || !args[2].isInt())
            throw RuntimeError("slice() expects (buf, start, end)");
        auto& b = args[0].asBuf();
        auto start = args[1].asInt();
        auto end = args[2].asInt();
        if (start < 0 || end < start || static_cast<size_t>(end) > b.size())
            throw RuntimeError("slice() out of range");
        return Value(Value::Buf(b.begin() + start, b.begin() + end));
    })));

    global_->define("chr", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.empty() || !args[0].isInt()) throw RuntimeError("chr() expects i64");
        return Value(std::string(1, static_cast<char>(args[0].asInt())));
    })));

    global_->define("ord", Value(NativeFn([](std::vector<Value>& args) -> Value {
        if (args.empty() || !args[0].isStr() || args[0].asStr().empty())
            throw RuntimeError("ord() expects non-empty str");
        return Value(static_cast<int64_t>(static_cast<uint8_t>(args[0].asStr()[0])));
    })));

    global_->define("kill", Value(NativeFn([](std::vector<Value>& args) -> Value {
        int code = 0;
        if (!args.empty() && args[0].isInt()) code = static_cast<int>(args[0].asInt());
        std::exit(code);
        return Value();
    })));
}

void Interpreter::execute(const std::vector<StmtPtr>& program) {
    executeInEnv(program, *global_);
}

void Interpreter::executeInEnv(const std::vector<StmtPtr>& program, Environment& env) {
    for (auto& stmt : program) {
        exec(stmt.get(), env);
    }
}

void Interpreter::exec(const Stmt* stmt, Environment& env) {
    if (!stmt) return;

    if (auto s = dynamic_cast<const ExprStmt*>(stmt)) {
        eval(s->expr.get(), env);
        return;
    }

    if (auto s = dynamic_cast<const LoadStmt*>(stmt)) {
        Value init;
        if (s->init) init = eval(s->init.get(), env);
        env.define(s->name, std::move(init), s->is_cell);
        return;
    }

    if (auto s = dynamic_cast<const BlockStmt*>(stmt)) {
        execBlock(s, env);
        return;
    }

    if (auto s = dynamic_cast<const CheckStmt*>(stmt)) {
        if (eval(s->condition.get(), env).truthy())
            exec(s->then_branch.get(), env);
        else if (s->alt_branch)
            exec(s->alt_branch.get(), env);
        return;
    }

    if (auto s = dynamic_cast<const LoopStmt*>(stmt)) {
        while (eval(s->condition.get(), env).truthy()) {
            try { exec(s->body.get(), env); }
            catch (HaltSignal&) { break; }
            catch (SkipSignal&) { continue; }
        }
        return;
    }

    if (auto s = dynamic_cast<const ScanStmt*>(stmt)) {
        int64_t start_val = eval(s->start.get(), env).asInt();
        int64_t end_val = eval(s->end.get(), env).asInt();
        Environment loop_env(&env);
        loop_env.define(s->var_name, Value(start_val), true);

        for (int64_t i = start_val; i < end_val; ++i) {
            loop_env.set(s->var_name, Value(i));
            try { exec(s->body.get(), loop_env); }
            catch (HaltSignal&) { break; }
            catch (SkipSignal&) { continue; }
        }
        return;
    }

    if (auto s = dynamic_cast<const ProcStmt*>(stmt)) {
        auto fn = std::make_shared<Function>();
        fn->name = s->name;
        fn->params = s->params;
        fn->return_type = s->return_type;
        fn->body = s->body.get();
        fn->closure = &env;
        env.define(s->name, Value(fn), false);
        return;
    }

    if (auto s = dynamic_cast<const RetStmt*>(stmt)) {
        Value val;
        if (s->value) val = eval(s->value.get(), env);
        throw RetSignal{std::move(val)};
    }

    if (dynamic_cast<const HaltStmt*>(stmt)) { throw HaltSignal{}; }
    if (dynamic_cast<const SkipStmt*>(stmt)) { throw SkipSignal{}; }

    if (auto s = dynamic_cast<const PacketStmt*>(stmt)) {
        PacketDef def;
        def.name = s->name;
        for (auto& [fname, ftype] : s->fields) def.fields.push_back(fname);
        packets_[s->name] = std::move(def);
        return;
    }

    if (auto s = dynamic_cast<const ProbeStmt*>(stmt)) {
        auto val = eval(s->target.get(), env);
        probeValue(val);
        return;
    }

    if (auto s = dynamic_cast<const BreachStmt*>(stmt)) {
        bool prev = in_breach_;
        in_breach_ = true;
        exec(s->body.get(), env);
        in_breach_ = prev;
        return;
    }

    if (auto s = dynamic_cast<const GateStmt*>(stmt)) {
        auto target = eval(s->target.get(), env);
        for (auto& arm : s->arms) {
            if (arm.is_wildcard) {
                exec(arm.body.get(), env);
                return;
            }
            auto pattern = eval(arm.pattern.get(), env);
            bool matches = false;
            if (target.isInt() && pattern.isInt())
                matches = target.asInt() == pattern.asInt();
            else if (target.isStr() && pattern.isStr())
                matches = target.asStr() == pattern.asStr();
            else if (target.isBool() && pattern.isBool())
                matches = target.asBool() == pattern.asBool();
            else
                matches = target.toString() == pattern.toString();

            if (matches) {
                exec(arm.body.get(), env);
                return;
            }
        }
        return;
    }

    throw RuntimeError("unknown statement");
}

void Interpreter::execBlock(const BlockStmt* block, Environment& env) {
    Environment local(&env);
    for (auto& stmt : block->stmts) {
        exec(stmt.get(), local);
    }
}

Value Interpreter::eval(const Expr* expr, Environment& env) {
    if (!expr) return Value();

    if (auto e = dynamic_cast<const LiteralExpr*>(expr)) {
        return e->value;
    }

    if (auto e = dynamic_cast<const IdentExpr*>(expr)) {
        return env.get(e->name);
    }

    if (auto e = dynamic_cast<const UnaryExpr*>(expr)) {
        auto val = eval(e->operand.get(), env);
        switch (e->op) {
            case TokenType::Minus:
                if (val.isInt()) return Value(-val.asInt());
                if (val.isFloat()) return Value(-val.asFloat());
                throw RuntimeError("unary '-' expects number");
            case TokenType::Bang:
                return Value(!val.truthy());
            case TokenType::Tilde:
                if (val.isInt()) return Value(~val.asInt());
                throw RuntimeError("'~' expects i64");
            default:
                throw RuntimeError("unknown unary op");
        }
    }

    if (auto e = dynamic_cast<const BinaryExpr*>(expr)) {
        auto left = eval(e->left.get(), env);
        auto right = eval(e->right.get(), env);

        if (e->op == TokenType::AmpAmp) return Value(left.truthy() && right.truthy());
        if (e->op == TokenType::PipePipe) return Value(left.truthy() || right.truthy());

        if (left.isInt() && right.isInt()) {
            int64_t a = left.asInt(), b = right.asInt();
            switch (e->op) {
                case TokenType::Plus:    return Value(a + b);
                case TokenType::Minus:   return Value(a - b);
                case TokenType::Star:    return Value(a * b);
                case TokenType::Slash:
                    if (b == 0) throw RuntimeError("division by zero");
                    return Value(a / b);
                case TokenType::Percent:
                    if (b == 0) throw RuntimeError("modulo by zero");
                    return Value(a % b);
                case TokenType::Amp:     return Value(a & b);
                case TokenType::Pipe:    return Value(a | b);
                case TokenType::Caret:   return Value(a ^ b);
                case TokenType::Shl:     return Value(a << b);
                case TokenType::Shr:     return Value(a >> b);
                case TokenType::EqEq:    return Value(a == b);
                case TokenType::BangEq:  return Value(a != b);
                case TokenType::Lt:      return Value(a < b);
                case TokenType::Gt:      return Value(a > b);
                case TokenType::LtEq:    return Value(a <= b);
                case TokenType::GtEq:    return Value(a >= b);
                default: break;
            }
        }

        if ((left.isInt() || left.isFloat()) && (right.isInt() || right.isFloat())) {
            double a = left.toNumber(), b = right.toNumber();
            switch (e->op) {
                case TokenType::Plus:    return Value(a + b);
                case TokenType::Minus:   return Value(a - b);
                case TokenType::Star:    return Value(a * b);
                case TokenType::Slash:
                    if (b == 0.0) throw RuntimeError("division by zero");
                    return Value(a / b);
                case TokenType::EqEq:    return Value(a == b);
                case TokenType::BangEq:  return Value(a != b);
                case TokenType::Lt:      return Value(a < b);
                case TokenType::Gt:      return Value(a > b);
                case TokenType::LtEq:    return Value(a <= b);
                case TokenType::GtEq:    return Value(a >= b);
                default: break;
            }
        }

        if (left.isStr() && e->op == TokenType::Plus)
            return Value(left.asStr() + right.toString());

        if (left.isStr() && right.isStr()) {
            if (e->op == TokenType::EqEq) return Value(left.asStr() == right.asStr());
            if (e->op == TokenType::BangEq) return Value(left.asStr() != right.asStr());
        }

        if (left.isBuf() && right.isBuf() && e->op == TokenType::Plus) {
            auto result = left.asBuf();
            auto& rb = right.asBuf();
            result.insert(result.end(), rb.begin(), rb.end());
            return Value(std::move(result));
        }

        if (left.isBool() && right.isBool()) {
            if (e->op == TokenType::EqEq) return Value(left.asBool() == right.asBool());
            if (e->op == TokenType::BangEq) return Value(left.asBool() != right.asBool());
        }

        throw RuntimeError("invalid operands for '" + std::string(Token::typeName(e->op)) + "'");
    }

    if (auto e = dynamic_cast<const AssignExpr*>(expr)) {
        auto val = eval(e->value.get(), env);
        if (e->op == TokenType::Eq) {
            env.set(e->name, val);
            return val;
        }
        auto& current = env.get(e->name);
        if (current.isInt() && val.isInt()) {
            int64_t a = current.asInt(), b = val.asInt();
            int64_t result;
            switch (e->op) {
                case TokenType::PlusEq:    result = a + b; break;
                case TokenType::MinusEq:   result = a - b; break;
                case TokenType::StarEq:    result = a * b; break;
                case TokenType::SlashEq:   result = a / b; break;
                case TokenType::PercentEq: result = a % b; break;
                case TokenType::AmpEq:     result = a & b; break;
                case TokenType::PipeEq:    result = a | b; break;
                case TokenType::CaretEq:   result = a ^ b; break;
                case TokenType::ShlEq:     result = a << b; break;
                case TokenType::ShrEq:     result = a >> b; break;
                default: throw RuntimeError("unknown compound assignment");
            }
            env.set(e->name, Value(result));
            return Value(result);
        }
        if (current.isStr() && e->op == TokenType::PlusEq) {
            auto result = current.asStr() + val.toString();
            env.set(e->name, Value(result));
            return Value(result);
        }
        throw RuntimeError("invalid compound assignment");
    }

    if (auto e = dynamic_cast<const CallExpr*>(expr)) {
        auto callee = eval(e->callee.get(), env);
        std::vector<Value> args;
        for (auto& arg : e->args) args.push_back(eval(arg.get(), env));
        return callFunction(callee, args, env);
    }

    if (auto e = dynamic_cast<const IndexExpr*>(expr)) {
        auto obj = eval(e->object.get(), env);
        auto idx = eval(e->index.get(), env);
        if (obj.isBuf() && idx.isInt()) {
            auto i = idx.asInt();
            if (i < 0 || static_cast<size_t>(i) >= obj.asBuf().size())
                throw RuntimeError("buf index out of range");
            return Value(static_cast<int64_t>(obj.asBuf()[i]));
        }
        if (obj.isStr() && idx.isInt()) {
            auto i = idx.asInt();
            if (i < 0 || static_cast<size_t>(i) >= obj.asStr().size())
                throw RuntimeError("str index out of range");
            return Value(std::string(1, obj.asStr()[i]));
        }
        throw RuntimeError("indexing requires buf or str");
    }

    if (auto e = dynamic_cast<const IndexAssignExpr*>(expr)) {
        auto obj_expr = dynamic_cast<const IdentExpr*>(e->object.get());
        if (!obj_expr) throw RuntimeError("can only index-assign to variables");
        auto& obj = env.get(obj_expr->name);
        auto idx = eval(e->index.get(), env);
        auto val = eval(e->value.get(), env);
        if (obj.isBuf() && idx.isInt()) {
            auto i = idx.asInt();
            if (i < 0 || static_cast<size_t>(i) >= obj.asBuf().size())
                throw RuntimeError("buf index out of range");
            obj.asBuf()[i] = static_cast<uint8_t>(val.asInt() & 0xFF);
            return val;
        }
        throw RuntimeError("index assignment requires cell buf");
    }

    if (auto e = dynamic_cast<const DotExpr*>(expr)) {
        auto obj = eval(e->object.get(), env);
        if (obj.isPacket()) {
            auto pkt = obj.asPacket();
            auto it = pkt->fields.find(e->field);
            if (it == pkt->fields.end())
                throw RuntimeError("packet '" + pkt->name + "' has no field '" + e->field + "'");
            return it->second;
        }
        throw RuntimeError("dot access requires packet");
    }

    if (auto e = dynamic_cast<const DotAssignExpr*>(expr)) {
        auto obj_expr = dynamic_cast<const IdentExpr*>(e->object.get());
        if (!obj_expr) throw RuntimeError("can only dot-assign to variables");
        auto& obj = env.get(obj_expr->name);
        auto val = eval(e->value.get(), env);
        if (obj.isPacket()) {
            obj.asPacket()->fields[e->field] = val;
            return val;
        }
        throw RuntimeError("dot assign requires packet");
    }

    if (auto e = dynamic_cast<const ArrayExpr*>(expr)) {
        Value::Buf buf;
        for (auto& elem : e->elements) {
            auto v = eval(elem.get(), env);
            if (v.isInt()) buf.push_back(static_cast<uint8_t>(v.asInt() & 0xFF));
            else throw RuntimeError("buf literal elements must be integers");
        }
        return Value(std::move(buf));
    }

    if (auto e = dynamic_cast<const PipeExpr*>(expr)) {
        auto left_val = eval(e->left.get(), env);
        if (auto call = dynamic_cast<const CallExpr*>(e->right.get())) {
            auto callee = eval(call->callee.get(), env);
            std::vector<Value> args;
            args.push_back(std::move(left_val));
            for (auto& arg : call->args) args.push_back(eval(arg.get(), env));
            return callFunction(callee, args, env);
        }
        auto callee = eval(e->right.get(), env);
        std::vector<Value> args;
        args.push_back(std::move(left_val));
        return callFunction(callee, args, env);
    }

    if (auto e = dynamic_cast<const PacketInitExpr*>(expr)) {
        auto it = packets_.find(e->name);
        if (it == packets_.end())
            throw RuntimeError("unknown packet '" + e->name + "'");
        auto pkt = std::make_shared<PacketInstance>();
        pkt->name = e->name;
        for (auto& [fname, fexpr] : e->fields)
            pkt->fields[fname] = eval(fexpr.get(), env);
        return Value(pkt);
    }

    throw RuntimeError("unknown expression");
}

Value Interpreter::callFunction(const Value& callee, std::vector<Value>& args, Environment& env) {
    if (callee.isNative()) return callee.asNative()(args);

    if (callee.isFunc()) {
        auto fn = callee.asFunc();
        Environment fn_env(fn->closure ? fn->closure : &env);

        if (args.size() != fn->params.size())
            throw RuntimeError("proc '" + fn->name + "' expects " +
                             std::to_string(fn->params.size()) + " args, got " +
                             std::to_string(args.size()));

        for (size_t i = 0; i < fn->params.size(); ++i)
            fn_env.define(fn->params[i].first, std::move(args[i]), true);

        try {
            exec(fn->body, fn_env);
        } catch (RetSignal& ret) {
            return std::move(ret.value);
        }
        return Value();
    }

    throw RuntimeError("not callable");
}

void Interpreter::probeValue(const Value& val) {
    std::cout << "\033[32m[PROBE]\033[0m ";

    if (val.isBuf()) {
        auto& buf = val.asBuf();
        std::cout << "\033[33m<buf:" << buf.size() << ">\033[0m ";
        for (size_t i = 0; i < buf.size() && i < 64; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << std::uppercase << (int)buf[i] << " ";
        if (buf.size() > 64) std::cout << "... ";
        std::cout << "\033[90m|";
        for (size_t i = 0; i < buf.size() && i < 64; ++i) {
            char c = static_cast<char>(buf[i]);
            std::cout << (std::isprint(c) ? c : '.');
        }
        std::cout << "|\033[0m" << std::dec << "\n";
        return;
    }

    if (val.isPacket()) {
        auto pkt = val.asPacket();
        std::cout << "\033[33m<" << pkt->name << ">\033[0m";
        for (auto& [k, v] : pkt->fields) {
            std::cout << " " << k << "=";
            if (v.isInt()) std::cout << "0x" << std::hex << std::uppercase << v.asInt() << std::dec;
            else std::cout << v.toString();
        }
        std::cout << "\n";
        return;
    }

    std::cout << "\033[33m<" << val.typeName() << ">\033[0m "
              << val.toString();
    if (val.isInt())
        std::cout << " \033[90m(0x" << std::hex << std::uppercase
                  << val.asInt() << std::dec << ")\033[0m";
    std::cout << "\n";
}

void Interpreter::hexdump(const Value::Buf& buf) {
    for (size_t offset = 0; offset < buf.size(); offset += 16) {
        std::cout << "\033[90m" << std::hex << std::setw(8) << std::setfill('0')
                  << offset << "\033[0m  ";

        for (size_t i = 0; i < 16; ++i) {
            if (offset + i < buf.size())
                std::cout << std::setw(2) << std::setfill('0')
                          << std::hex << std::uppercase << (int)buf[offset + i] << " ";
            else
                std::cout << "   ";
            if (i == 7) std::cout << " ";
        }

        std::cout << " \033[90m|";
        for (size_t i = 0; i < 16 && offset + i < buf.size(); ++i) {
            char c = static_cast<char>(buf[offset + i]);
            std::cout << (std::isprint(c) ? c : '.');
        }
        std::cout << "|\033[0m" << std::dec << "\n";
    }
}

}
