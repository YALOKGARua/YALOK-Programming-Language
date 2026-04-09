#pragma once
#include "ast.hpp"
#include "value.hpp"
#include <string>
#include <unordered_map>
#include <memory>
#include <vector>
#include <stdexcept>

namespace yalok {

struct RuntimeError : std::runtime_error {
    int line;
    RuntimeError(const std::string& msg, int l = 0)
        : std::runtime_error(msg), line(l) {}
};

struct RetSignal {
    Value value;
};

struct HaltSignal {};
struct SkipSignal {};

class Environment {
public:
    explicit Environment(Environment* parent = nullptr);

    void define(const std::string& name, Value val, bool is_cell = true);
    Value& get(const std::string& name);
    void set(const std::string& name, const Value& val);
    bool has(const std::string& name) const;
    Environment* parent() const { return parent_; }

private:
    struct Binding { Value value; bool is_cell; };
    std::unordered_map<std::string, Binding> vars_;
    Environment* parent_;
};

class Interpreter {
public:
    Interpreter();
    void execute(const std::vector<StmtPtr>& program);
    void executeInEnv(const std::vector<StmtPtr>& program, Environment& env);

private:
    std::unique_ptr<Environment> global_;
    std::unordered_map<std::string, PacketDef> packets_;
    bool in_breach_ = false;

    void registerBuiltins();

    void exec(const Stmt* stmt, Environment& env);
    void execBlock(const BlockStmt* block, Environment& env);

    Value eval(const Expr* expr, Environment& env);
    Value callFunction(const Value& callee, std::vector<Value>& args, Environment& env);

    void probeValue(const Value& val);
    void hexdump(const Value::Buf& buf);
};

}
