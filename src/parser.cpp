#include "yalok/parser.hpp"

namespace yalok {

Parser::Parser(std::vector<Token> tokens)
    : tokens_(std::move(tokens)), pos_(0) {}

const Token& Parser::current() const { return tokens_[pos_]; }
const Token& Parser::previous() const { return tokens_[pos_ - 1]; }

const Token& Parser::advance() {
    if (!atEnd()) pos_++;
    return previous();
}

bool Parser::check(TokenType t) const { return !atEnd() && current().type == t; }
bool Parser::atEnd() const { return current().type == TokenType::Eof; }

bool Parser::match(TokenType t) {
    if (check(t)) { advance(); return true; }
    return false;
}

Token Parser::expect(TokenType t, const std::string& msg) {
    if (check(t)) return advance();
    throw error(msg);
}

ParseError Parser::error(const std::string& msg) {
    auto& tok = current();
    return ParseError(msg + " (got '" + tok.value + "')", tok.line, tok.col);
}

std::vector<StmtPtr> Parser::parse() {
    std::vector<StmtPtr> program;
    while (!atEnd()) {
        program.push_back(declaration());
    }
    return program;
}

StmtPtr Parser::declaration() {
    if (check(TokenType::Load) || check(TokenType::Cell)) return loadDecl();
    if (check(TokenType::Proc)) return procDecl();
    if (check(TokenType::Packet)) return packetDecl();
    return statement();
}

StmtPtr Parser::statement() {
    if (check(TokenType::Check)) return checkStmt();
    if (check(TokenType::Loop)) return loopStmt();
    if (check(TokenType::Scan)) return scanStmt();
    if (check(TokenType::Gate)) return gateStmt();
    if (check(TokenType::Ret)) return retStmt();
    if (check(TokenType::Halt)) return haltStmt();
    if (check(TokenType::Skip)) return skipStmt();
    if (check(TokenType::Probe)) return probeStmt();
    if (check(TokenType::Breach)) return breachStmt();
    if (check(TokenType::LBrace)) return block();
    return exprStatement();
}

StmtPtr Parser::loadDecl() {
    bool is_cell = match(TokenType::Cell);
    if (!is_cell) expect(TokenType::Load, "expected 'load'");

    auto name = expect(TokenType::Ident, "expected variable name").value;

    std::string type_hint;
    if (match(TokenType::Colon)) {
        type_hint = expect(TokenType::Ident, "expected type").value;
    }

    ExprPtr init = nullptr;
    if (match(TokenType::Eq)) {
        init = expression();
    }

    match(TokenType::Semi);
    return std::make_unique<LoadStmt>(std::move(name), std::move(type_hint), is_cell, std::move(init));
}

StmtPtr Parser::procDecl() {
    expect(TokenType::Proc, "expected 'proc'");
    auto name = expect(TokenType::Ident, "expected proc name").value;
    expect(TokenType::LParen, "expected '('");

    std::vector<std::pair<std::string, std::string>> params;
    if (!check(TokenType::RParen)) {
        do {
            auto pname = expect(TokenType::Ident, "expected parameter name").value;
            std::string ptype;
            if (match(TokenType::Colon)) {
                ptype = expect(TokenType::Ident, "expected parameter type").value;
            }
            params.emplace_back(std::move(pname), std::move(ptype));
        } while (match(TokenType::Comma));
    }
    expect(TokenType::RParen, "expected ')'");

    std::string return_type;
    if (match(TokenType::Arrow)) {
        return_type = expect(TokenType::Ident, "expected return type").value;
    }

    auto body = block();
    return std::make_unique<ProcStmt>(std::move(name), std::move(params),
                                      std::move(return_type), std::move(body));
}

StmtPtr Parser::packetDecl() {
    expect(TokenType::Packet, "expected 'packet'");
    auto name = expect(TokenType::Ident, "expected packet name").value;
    expect(TokenType::LBrace, "expected '{'");

    std::vector<std::pair<std::string, std::string>> fields;
    while (!check(TokenType::RBrace) && !atEnd()) {
        auto fname = expect(TokenType::Ident, "expected field name").value;
        expect(TokenType::Colon, "expected ':'");
        auto ftype = expect(TokenType::Ident, "expected field type").value;
        fields.emplace_back(std::move(fname), std::move(ftype));
        match(TokenType::Comma);
    }
    expect(TokenType::RBrace, "expected '}'");

    return std::make_unique<PacketStmt>(std::move(name), std::move(fields));
}

StmtPtr Parser::checkStmt() {
    expect(TokenType::Check, "expected 'check'");
    auto cond = expression();
    auto then_b = block();
    StmtPtr alt_b = nullptr;
    if (match(TokenType::Alt)) {
        if (check(TokenType::Check)) {
            alt_b = checkStmt();
        } else {
            alt_b = block();
        }
    }
    return std::make_unique<CheckStmt>(std::move(cond), std::move(then_b), std::move(alt_b));
}

StmtPtr Parser::loopStmt() {
    expect(TokenType::Loop, "expected 'loop'");
    auto cond = expression();
    auto body = block();
    return std::make_unique<LoopStmt>(std::move(cond), std::move(body));
}

StmtPtr Parser::scanStmt() {
    expect(TokenType::Scan, "expected 'scan'");
    auto var_name = expect(TokenType::Ident, "expected variable name").value;
    expect(TokenType::Thru, "expected 'thru'");
    auto start = expression();
    expect(TokenType::DotDot, "expected '..'");
    auto end = expression();
    auto body = block();
    return std::make_unique<ScanStmt>(std::move(var_name), std::move(start),
                                      std::move(end), std::move(body));
}

StmtPtr Parser::gateStmt() {
    expect(TokenType::Gate, "expected 'gate'");
    auto target = expression();
    expect(TokenType::LBrace, "expected '{'");

    std::vector<GateArm> arms;
    while (!check(TokenType::RBrace) && !atEnd()) {
        GateArm arm;
        if (match(TokenType::Underscore)) {
            arm.is_wildcard = true;
            arm.pattern = nullptr;
        } else {
            arm.pattern = expression();
            arm.is_wildcard = false;
        }
        expect(TokenType::FatArrow, "expected '=>'");

        if (check(TokenType::LBrace)) {
            arm.body = block();
        } else {
            auto expr = expression();
            arm.body = std::make_unique<ExprStmt>(std::move(expr));
        }
        match(TokenType::Comma);
        arms.push_back(std::move(arm));
    }
    expect(TokenType::RBrace, "expected '}'");
    return std::make_unique<GateStmt>(std::move(target), std::move(arms));
}

StmtPtr Parser::retStmt() {
    expect(TokenType::Ret, "expected 'ret'");
    ExprPtr val = nullptr;
    if (!check(TokenType::Semi) && !check(TokenType::RBrace) && !atEnd()) {
        val = expression();
    }
    match(TokenType::Semi);
    return std::make_unique<RetStmt>(std::move(val));
}

StmtPtr Parser::haltStmt() {
    expect(TokenType::Halt, "expected 'halt'");
    match(TokenType::Semi);
    return std::make_unique<HaltStmt>();
}

StmtPtr Parser::skipStmt() {
    expect(TokenType::Skip, "expected 'skip'");
    match(TokenType::Semi);
    return std::make_unique<SkipStmt>();
}

StmtPtr Parser::probeStmt() {
    int ln = current().line;
    expect(TokenType::Probe, "expected 'probe'");
    auto target = expression();
    match(TokenType::Semi);
    auto stmt = std::make_unique<ProbeStmt>(std::move(target));
    stmt->line = ln;
    return stmt;
}

StmtPtr Parser::breachStmt() {
    expect(TokenType::Breach, "expected 'breach'");
    auto body = block();
    return std::make_unique<BreachStmt>(std::move(body));
}

StmtPtr Parser::block() {
    expect(TokenType::LBrace, "expected '{'");
    std::vector<StmtPtr> stmts;
    while (!check(TokenType::RBrace) && !atEnd()) {
        stmts.push_back(declaration());
    }
    expect(TokenType::RBrace, "expected '}'");
    return std::make_unique<BlockStmt>(std::move(stmts));
}

StmtPtr Parser::exprStatement() {
    auto expr = expression();
    match(TokenType::Semi);
    return std::make_unique<ExprStmt>(std::move(expr));
}

ExprPtr Parser::expression() {
    return assignment();
}

ExprPtr Parser::assignment() {
    auto expr = pipe();

    if (auto ident = dynamic_cast<IdentExpr*>(expr.get())) {
        if (check(TokenType::Eq) || check(TokenType::PlusEq) || check(TokenType::MinusEq) ||
            check(TokenType::StarEq) || check(TokenType::SlashEq) || check(TokenType::PercentEq) ||
            check(TokenType::AmpEq) || check(TokenType::PipeEq) || check(TokenType::CaretEq) ||
            check(TokenType::ShlEq) || check(TokenType::ShrEq)) {
            TokenType op = advance().type;
            auto val = expression();
            return std::make_unique<AssignExpr>(ident->name, op, std::move(val));
        }
    }

    if (auto idx = dynamic_cast<IndexExpr*>(expr.get())) {
        if (match(TokenType::Eq)) {
            auto val = expression();
            return std::make_unique<IndexAssignExpr>(
                std::move(idx->object), std::move(idx->index), std::move(val));
        }
    }

    if (auto dot = dynamic_cast<DotExpr*>(expr.get())) {
        if (match(TokenType::Eq)) {
            auto val = expression();
            return std::make_unique<DotAssignExpr>(
                std::move(dot->object), dot->field, std::move(val));
        }
    }

    return expr;
}

ExprPtr Parser::pipe() {
    auto left = logicOr();
    while (match(TokenType::PipeGt)) {
        auto right = logicOr();
        left = std::make_unique<PipeExpr>(std::move(left), std::move(right));
    }
    return left;
}

ExprPtr Parser::logicOr() {
    auto left = logicAnd();
    while (match(TokenType::PipePipe)) {
        auto right = logicAnd();
        left = std::make_unique<BinaryExpr>(TokenType::PipePipe, std::move(left), std::move(right));
    }
    return left;
}

ExprPtr Parser::logicAnd() {
    auto left = bitwiseOr();
    while (match(TokenType::AmpAmp)) {
        auto right = bitwiseOr();
        left = std::make_unique<BinaryExpr>(TokenType::AmpAmp, std::move(left), std::move(right));
    }
    return left;
}

ExprPtr Parser::bitwiseOr() {
    auto left = bitwiseXor();
    while (match(TokenType::Pipe)) {
        auto right = bitwiseXor();
        left = std::make_unique<BinaryExpr>(TokenType::Pipe, std::move(left), std::move(right));
    }
    return left;
}

ExprPtr Parser::bitwiseXor() {
    auto left = bitwiseAnd();
    while (match(TokenType::Caret)) {
        auto right = bitwiseAnd();
        left = std::make_unique<BinaryExpr>(TokenType::Caret, std::move(left), std::move(right));
    }
    return left;
}

ExprPtr Parser::bitwiseAnd() {
    auto left = equality();
    while (match(TokenType::Amp)) {
        auto right = equality();
        left = std::make_unique<BinaryExpr>(TokenType::Amp, std::move(left), std::move(right));
    }
    return left;
}

ExprPtr Parser::equality() {
    auto left = comparison();
    while (check(TokenType::EqEq) || check(TokenType::BangEq)) {
        auto op = advance().type;
        auto right = comparison();
        left = std::make_unique<BinaryExpr>(op, std::move(left), std::move(right));
    }
    return left;
}

ExprPtr Parser::comparison() {
    auto left = shift();
    while (check(TokenType::Lt) || check(TokenType::Gt) ||
           check(TokenType::LtEq) || check(TokenType::GtEq)) {
        auto op = advance().type;
        auto right = shift();
        left = std::make_unique<BinaryExpr>(op, std::move(left), std::move(right));
    }
    return left;
}

ExprPtr Parser::shift() {
    auto left = addition();
    while (check(TokenType::Shl) || check(TokenType::Shr)) {
        auto op = advance().type;
        auto right = addition();
        left = std::make_unique<BinaryExpr>(op, std::move(left), std::move(right));
    }
    return left;
}

ExprPtr Parser::addition() {
    auto left = multiplication();
    while (check(TokenType::Plus) || check(TokenType::Minus)) {
        auto op = advance().type;
        auto right = multiplication();
        left = std::make_unique<BinaryExpr>(op, std::move(left), std::move(right));
    }
    return left;
}

ExprPtr Parser::multiplication() {
    auto left = unary();
    while (check(TokenType::Star) || check(TokenType::Slash) || check(TokenType::Percent)) {
        auto op = advance().type;
        auto right = unary();
        left = std::make_unique<BinaryExpr>(op, std::move(left), std::move(right));
    }
    return left;
}

ExprPtr Parser::unary() {
    if (check(TokenType::Minus) || check(TokenType::Bang) || check(TokenType::Tilde)) {
        auto op = advance().type;
        auto operand = unary();
        return std::make_unique<UnaryExpr>(op, std::move(operand));
    }
    return postfix();
}

ExprPtr Parser::postfix() {
    auto expr = primary();

    while (true) {
        if (match(TokenType::LParen)) {
            std::vector<ExprPtr> args;
            if (!check(TokenType::RParen)) {
                do {
                    args.push_back(expression());
                } while (match(TokenType::Comma));
            }
            expect(TokenType::RParen, "expected ')'");
            expr = std::make_unique<CallExpr>(std::move(expr), std::move(args));
        } else if (match(TokenType::LBrack)) {
            auto index = expression();
            expect(TokenType::RBrack, "expected ']'");
            expr = std::make_unique<IndexExpr>(std::move(expr), std::move(index));
        } else if (match(TokenType::Dot)) {
            auto field = expect(TokenType::Ident, "expected field name").value;
            expr = std::make_unique<DotExpr>(std::move(expr), std::move(field));
        } else {
            break;
        }
    }

    return expr;
}

ExprPtr Parser::primary() {
    if (match(TokenType::IntLit)) {
        auto& tok = previous();
        if (tok.value.find('.') != std::string::npos)
            return std::make_unique<LiteralExpr>(Value(std::stod(tok.value)));
        return std::make_unique<LiteralExpr>(Value(std::stoll(tok.value)));
    }

    if (match(TokenType::FloatLit)) {
        return std::make_unique<LiteralExpr>(Value(std::stod(previous().value)));
    }

    if (match(TokenType::StrLit)) {
        return std::make_unique<LiteralExpr>(Value(previous().value));
    }

    if (match(TokenType::BoolLit)) {
        return std::make_unique<LiteralExpr>(Value(previous().value == "on"));
    }

    if (match(TokenType::NilLit)) {
        return std::make_unique<LiteralExpr>(Value());
    }

    if (check(TokenType::Ident)) {
        auto name = advance().value;

        if (check(TokenType::LBrace)) {
            size_t saved = pos_;
            advance();
            if (check(TokenType::Ident)) {
                size_t saved2 = pos_;
                advance();
                if (check(TokenType::Colon)) {
                    pos_ = saved;
                    advance();
                    std::vector<std::pair<std::string, ExprPtr>> fields;
                    if (!check(TokenType::RBrace)) {
                        do {
                            auto fname = expect(TokenType::Ident, "expected field name").value;
                            expect(TokenType::Colon, "expected ':'");
                            auto fval = expression();
                            fields.emplace_back(std::move(fname), std::move(fval));
                        } while (match(TokenType::Comma));
                    }
                    expect(TokenType::RBrace, "expected '}'");
                    return std::make_unique<PacketInitExpr>(std::move(name), std::move(fields));
                }
                pos_ = saved2;
            }
            pos_ = saved;
        }

        return std::make_unique<IdentExpr>(std::move(name));
    }

    if (match(TokenType::LBrack)) {
        std::vector<ExprPtr> elements;
        if (!check(TokenType::RBrack)) {
            do {
                elements.push_back(expression());
            } while (match(TokenType::Comma));
        }
        expect(TokenType::RBrack, "expected ']'");
        return std::make_unique<ArrayExpr>(std::move(elements));
    }

    if (match(TokenType::LParen)) {
        auto expr = expression();
        expect(TokenType::RParen, "expected ')'");
        return expr;
    }

    throw error("unexpected token");
}

}
