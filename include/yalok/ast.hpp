#pragma once
#include "token.hpp"
#include "value.hpp"
#include <memory>
#include <vector>
#include <string>

namespace yalok {

struct Expr;
struct Stmt;
using ExprPtr = std::unique_ptr<Expr>;
using StmtPtr = std::unique_ptr<Stmt>;

struct Expr {
    int line = 0;
    virtual ~Expr() = default;
};

struct LiteralExpr : Expr {
    Value value;
    LiteralExpr(Value v) : value(std::move(v)) {}
};

struct IdentExpr : Expr {
    std::string name;
    IdentExpr(std::string n) : name(std::move(n)) {}
};

struct UnaryExpr : Expr {
    TokenType op;
    ExprPtr operand;
    UnaryExpr(TokenType o, ExprPtr rhs) : op(o), operand(std::move(rhs)) {}
};

struct BinaryExpr : Expr {
    TokenType op;
    ExprPtr left, right;
    BinaryExpr(TokenType o, ExprPtr l, ExprPtr r)
        : op(o), left(std::move(l)), right(std::move(r)) {}
};

struct AssignExpr : Expr {
    std::string name;
    TokenType op;
    ExprPtr value;
    AssignExpr(std::string n, TokenType o, ExprPtr v)
        : name(std::move(n)), op(o), value(std::move(v)) {}
};

struct CallExpr : Expr {
    ExprPtr callee;
    std::vector<ExprPtr> args;
    CallExpr(ExprPtr c, std::vector<ExprPtr> a)
        : callee(std::move(c)), args(std::move(a)) {}
};

struct IndexExpr : Expr {
    ExprPtr object;
    ExprPtr index;
    IndexExpr(ExprPtr o, ExprPtr i)
        : object(std::move(o)), index(std::move(i)) {}
};

struct DotExpr : Expr {
    ExprPtr object;
    std::string field;
    DotExpr(ExprPtr o, std::string f)
        : object(std::move(o)), field(std::move(f)) {}
};

struct ArrayExpr : Expr {
    std::vector<ExprPtr> elements;
    ArrayExpr(std::vector<ExprPtr> e) : elements(std::move(e)) {}
};

struct PipeExpr : Expr {
    ExprPtr left;
    ExprPtr right;
    PipeExpr(ExprPtr l, ExprPtr r)
        : left(std::move(l)), right(std::move(r)) {}
};

struct PacketInitExpr : Expr {
    std::string name;
    std::vector<std::pair<std::string, ExprPtr>> fields;
    PacketInitExpr(std::string n, std::vector<std::pair<std::string, ExprPtr>> f)
        : name(std::move(n)), fields(std::move(f)) {}
};

struct IndexAssignExpr : Expr {
    ExprPtr object;
    ExprPtr index;
    ExprPtr value;
    IndexAssignExpr(ExprPtr o, ExprPtr i, ExprPtr v)
        : object(std::move(o)), index(std::move(i)), value(std::move(v)) {}
};

struct DotAssignExpr : Expr {
    ExprPtr object;
    std::string field;
    ExprPtr value;
    DotAssignExpr(ExprPtr o, std::string f, ExprPtr v)
        : object(std::move(o)), field(std::move(f)), value(std::move(v)) {}
};

struct Stmt {
    int line = 0;
    virtual ~Stmt() = default;
};

struct ExprStmt : Stmt {
    ExprPtr expr;
    ExprStmt(ExprPtr e) : expr(std::move(e)) {}
};

struct LoadStmt : Stmt {
    std::string name;
    std::string type_hint;
    bool is_cell;
    ExprPtr init;
    LoadStmt(std::string n, std::string t, bool cell, ExprPtr i)
        : name(std::move(n)), type_hint(std::move(t)), is_cell(cell), init(std::move(i)) {}
};

struct BlockStmt : Stmt {
    std::vector<StmtPtr> stmts;
    BlockStmt(std::vector<StmtPtr> s) : stmts(std::move(s)) {}
};

struct CheckStmt : Stmt {
    ExprPtr condition;
    StmtPtr then_branch;
    StmtPtr alt_branch;
    CheckStmt(ExprPtr c, StmtPtr t, StmtPtr a)
        : condition(std::move(c)), then_branch(std::move(t)), alt_branch(std::move(a)) {}
};

struct LoopStmt : Stmt {
    ExprPtr condition;
    StmtPtr body;
    LoopStmt(ExprPtr c, StmtPtr b)
        : condition(std::move(c)), body(std::move(b)) {}
};

struct ScanStmt : Stmt {
    std::string var_name;
    ExprPtr start;
    ExprPtr end;
    StmtPtr body;
    ScanStmt(std::string v, ExprPtr s, ExprPtr e, StmtPtr b)
        : var_name(std::move(v)), start(std::move(s)), end(std::move(e)), body(std::move(b)) {}
};

struct ProcStmt : Stmt {
    std::string name;
    std::vector<std::pair<std::string, std::string>> params;
    std::string return_type;
    StmtPtr body;
    ProcStmt(std::string n, std::vector<std::pair<std::string, std::string>> p,
             std::string rt, StmtPtr b)
        : name(std::move(n)), params(std::move(p)),
          return_type(std::move(rt)), body(std::move(b)) {}
};

struct RetStmt : Stmt {
    ExprPtr value;
    RetStmt(ExprPtr v) : value(std::move(v)) {}
};

struct HaltStmt : Stmt {};
struct SkipStmt : Stmt {};

struct PacketStmt : Stmt {
    std::string name;
    std::vector<std::pair<std::string, std::string>> fields;
    PacketStmt(std::string n, std::vector<std::pair<std::string, std::string>> f)
        : name(std::move(n)), fields(std::move(f)) {}
};

struct ProbeStmt : Stmt {
    ExprPtr target;
    ProbeStmt(ExprPtr t) : target(std::move(t)) {}
};

struct BreachStmt : Stmt {
    StmtPtr body;
    BreachStmt(StmtPtr b) : body(std::move(b)) {}
};

struct GateArm {
    ExprPtr pattern;
    bool is_wildcard = false;
    StmtPtr body;
};

struct GateStmt : Stmt {
    ExprPtr target;
    std::vector<GateArm> arms;
    GateStmt(ExprPtr t, std::vector<GateArm> a)
        : target(std::move(t)), arms(std::move(a)) {}
};

}
