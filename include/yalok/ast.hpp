#pragma once

#include "value.hpp"
#include <memory>
#include <vector>
#include <string>

namespace yalok {

struct ASTNode {
    virtual ~ASTNode() = default;
};

struct Expression : ASTNode {
    virtual ~Expression() = default;
};

struct Statement : ASTNode {
    virtual ~Statement() = default;
};

struct NumberLiteral : Expression {
    Value value;
    NumberLiteral(const Value& v) : value(v) {}
};

struct StringLiteral : Expression {
    Value value;
    StringLiteral(const std::string& str) : value(str) {}
};

struct BooleanLiteral : Expression {
    Value value;
    BooleanLiteral(bool b) : value(b) {}
};

struct NilLiteral : Expression {
    Value value;
    NilLiteral() : value() {}
};

struct ArrayLiteral : Expression {
    std::vector<std::unique_ptr<Expression>> elements;
};

struct ObjectLiteral : Expression {
    std::map<std::string, std::unique_ptr<Expression>> properties;
};

struct Identifier : Expression {
    std::string name;
    Identifier(const std::string& n) : name(n) {}
};

struct BinaryOperation : Expression {
    std::unique_ptr<Expression> left;
    std::string operator_;
    std::unique_ptr<Expression> right;
    
    BinaryOperation(std::unique_ptr<Expression> l, const std::string& op, std::unique_ptr<Expression> r)
        : left(std::move(l)), operator_(op), right(std::move(r)) {}
};

struct UnaryOperation : Expression {
    std::string operator_;
    std::unique_ptr<Expression> operand;
    
    UnaryOperation(const std::string& op, std::unique_ptr<Expression> expr)
        : operator_(op), operand(std::move(expr)) {}
};

struct TernaryOperation : Expression {
    std::unique_ptr<Expression> condition;
    std::unique_ptr<Expression> true_expr;
    std::unique_ptr<Expression> false_expr;
    
    TernaryOperation(std::unique_ptr<Expression> cond, std::unique_ptr<Expression> true_e, std::unique_ptr<Expression> false_e)
        : condition(std::move(cond)), true_expr(std::move(true_e)), false_expr(std::move(false_e)) {}
};

struct Assignment : Statement {
    std::string variable;
    std::unique_ptr<Expression> value;
    std::string operator_;
    
    Assignment(const std::string& var, std::unique_ptr<Expression> val, const std::string& op = "=")
        : variable(var), value(std::move(val)), operator_(op) {}
};

struct IfStatement : Statement {
    std::unique_ptr<Expression> condition;
    std::vector<std::unique_ptr<Statement>> then_branch;
    std::vector<std::unique_ptr<Statement>> else_branch;
    
    IfStatement(std::unique_ptr<Expression> cond) : condition(std::move(cond)) {}
};

struct WhileStatement : Statement {
    std::unique_ptr<Expression> condition;
    std::vector<std::unique_ptr<Statement>> body;
    
    WhileStatement(std::unique_ptr<Expression> cond) : condition(std::move(cond)) {}
};

struct ForStatement : Statement {
    std::unique_ptr<Statement> init;
    std::unique_ptr<Expression> condition;
    std::unique_ptr<Expression> increment;
    std::vector<std::unique_ptr<Statement>> body;
    
    ForStatement(std::unique_ptr<Statement> i, std::unique_ptr<Expression> c, std::unique_ptr<Expression> inc)
        : init(std::move(i)), condition(std::move(c)), increment(std::move(inc)) {}
};

struct FunctionDeclaration : Statement {
    std::string name;
    std::vector<std::string> parameters;
    std::vector<std::unique_ptr<Statement>> body;
    
    FunctionDeclaration(const std::string& n) : name(n) {}
};

struct FunctionCall : Expression {
    std::string name;
    std::vector<std::unique_ptr<Expression>> arguments;
    
    FunctionCall(const std::string& n) : name(n) {}
};

struct ReturnStatement : Statement {
    std::unique_ptr<Expression> value;
    
    ReturnStatement(std::unique_ptr<Expression> val) : value(std::move(val)) {}
};

struct BreakStatement : Statement {};

struct ContinueStatement : Statement {};

struct ExpressionStatement : Statement {
    std::unique_ptr<Expression> expression;
    
    ExpressionStatement(std::unique_ptr<Expression> expr) : expression(std::move(expr)) {}
};

struct BlockStatement : Statement {
    std::vector<std::unique_ptr<Statement>> statements;
};

struct ImportStatement : Statement {
    std::string module_name;
    std::vector<std::string> imports;
    
    ImportStatement(const std::string& module) : module_name(module) {}
};

struct ArrayAccess : Expression {
    std::unique_ptr<Expression> array;
    std::unique_ptr<Expression> index;
    
    ArrayAccess(std::unique_ptr<Expression> arr, std::unique_ptr<Expression> idx)
        : array(std::move(arr)), index(std::move(idx)) {}
};

struct PropertyAccess : Expression {
    std::unique_ptr<Expression> object;
    std::string property;
    
    PropertyAccess(std::unique_ptr<Expression> obj, const std::string& prop)
        : object(std::move(obj)), property(prop) {}
};

} 