#pragma once
#include "token.hpp"
#include "ast.hpp"
#include <vector>
#include <stdexcept>

namespace yalok {

struct ParseError : std::runtime_error {
    int line, col;
    ParseError(const std::string& msg, int l, int c)
        : std::runtime_error(msg), line(l), col(c) {}
};

class Parser {
public:
    explicit Parser(std::vector<Token> tokens);
    std::vector<StmtPtr> parse();

private:
    std::vector<Token> tokens_;
    size_t pos_;

    const Token& current() const;
    const Token& previous() const;
    const Token& advance();
    bool check(TokenType t) const;
    bool match(TokenType t);
    Token expect(TokenType t, const std::string& msg);
    bool atEnd() const;
    ParseError error(const std::string& msg);

    StmtPtr declaration();
    StmtPtr statement();
    StmtPtr loadDecl();
    StmtPtr procDecl();
    StmtPtr packetDecl();
    StmtPtr checkStmt();
    StmtPtr loopStmt();
    StmtPtr scanStmt();
    StmtPtr gateStmt();
    StmtPtr retStmt();
    StmtPtr haltStmt();
    StmtPtr skipStmt();
    StmtPtr probeStmt();
    StmtPtr breachStmt();
    StmtPtr block();
    StmtPtr exprStatement();

    ExprPtr expression();
    ExprPtr assignment();
    ExprPtr pipe();
    ExprPtr logicOr();
    ExprPtr logicAnd();
    ExprPtr bitwiseOr();
    ExprPtr bitwiseXor();
    ExprPtr bitwiseAnd();
    ExprPtr equality();
    ExprPtr comparison();
    ExprPtr shift();
    ExprPtr addition();
    ExprPtr multiplication();
    ExprPtr unary();
    ExprPtr postfix();
    ExprPtr primary();
};

}
