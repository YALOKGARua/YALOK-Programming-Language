#include "yalok/parser.hpp"
#include "yalok/token.hpp"
#include "yalok/ast.hpp"
#include <iostream>
#include <sstream>

namespace yalok {

Parser::Parser(const std::vector<Token>& tokens) : tokens(tokens), current(0) {}

Token Parser::peek() {
    if (is_at_end()) {
        return Token(TokenType::EOF_TOKEN, "", 0, 0);
    }
    return tokens[current];
}

Token Parser::previous() {
    if (current > 0) {
        return tokens[current - 1];
    }
    return Token(TokenType::EOF_TOKEN, "", 0, 0);
}

Token Parser::advance() {
    if (!is_at_end()) {
        current++;
    }
    return previous();
}

bool Parser::is_at_end() {
    return current >= tokens.size() || peek().type == TokenType::EOF_TOKEN;
}

bool Parser::check(TokenType type) {
    if (is_at_end()) {
        return false;
    }
    return peek().type == type;
}

bool Parser::match(std::initializer_list<TokenType> types) {
    for (TokenType type : types) {
        if (check(type)) {
            advance();
            return true;
        }
    }
    return false;
}

void Parser::skip_newlines() {
    while (match({TokenType::NEWLINE})) {
        // Skip newlines
    }
}

Token Parser::consume(TokenType type, const std::string& message) {
    if (check(type)) {
        return advance();
    }
    
    Token current_token = peek();
    throw ParseError(message + " at line " + std::to_string(current_token.line) + 
                    ", column " + std::to_string(current_token.column));
}

void Parser::synchronize() {
    advance();
    
    while (!is_at_end()) {
        if (previous().type == TokenType::SEMICOLON) {
            return;
        }
        
        TokenType type = peek().type;
        if (type == TokenType::CLASS || type == TokenType::FUNC || 
            type == TokenType::VAR || type == TokenType::FOR || 
            type == TokenType::IF || type == TokenType::WHILE || 
            type == TokenType::RETURN) {
            return;
        }
        
        advance();
    }
}

std::unique_ptr<Expression> Parser::parse_primary() {
    if (match({TokenType::TRUE})) {
        return std::make_unique<LiteralExpression>(Value(true));
    }
    
    if (match({TokenType::FALSE})) {
        return std::make_unique<LiteralExpression>(Value(false));
    }
    
    if (match({TokenType::NIL})) {
        return std::make_unique<LiteralExpression>(Value());
    }
    
    if (match({TokenType::NUMBER})) {
        std::string value = previous().lexeme;
        return std::make_unique<LiteralExpression>(Value(std::stod(value)));
    }
    
    if (match({TokenType::STRING})) {
        std::string value = previous().lexeme;
        return std::make_unique<LiteralExpression>(Value(value));
    }
    
    if (match({TokenType::IDENTIFIER})) {
        std::string name = previous().lexeme;
        
        if (check(TokenType::LEFT_PAREN)) {
            return parse_function_call(name);
        }
        
        return std::make_unique<VariableExpression>(name);
    }
    
    if (match({TokenType::LEFT_PAREN})) {
        auto expr = parse_expression();
        consume(TokenType::RIGHT_PAREN, "Expected ')' after expression");
        return expr;
    }
    
    if (match({TokenType::LEFT_BRACKET})) {
        return parse_array_literal();
    }
    
    if (match({TokenType::LEFT_BRACE})) {
        return parse_object_literal();
    }
    
    throw ParseError("Unexpected token: " + peek().lexeme);
}

std::unique_ptr<Expression> Parser::parse_postfix() {
    auto expr = parse_primary();
    
    while (true) {
        if (match({TokenType::LEFT_BRACKET})) {
            auto index = parse_expression();
            consume(TokenType::RIGHT_BRACKET, "Expected ']' after array index");
            expr = std::make_unique<AccessExpression>(std::move(expr), std::move(index));
        } else if (match({TokenType::DOT})) {
            std::string property = consume(TokenType::IDENTIFIER, "Expected property name").lexeme;
            auto property_expr = std::make_unique<LiteralExpression>(Value(property));
            expr = std::make_unique<AccessExpression>(std::move(expr), std::move(property_expr));
        } else {
            break;
        }
    }
    
    return expr;
}

std::unique_ptr<Expression> Parser::parse_unary() {
    if (match({TokenType::MINUS, TokenType::BANG})) {
        std::string operator_ = previous().lexeme;
        auto operand = parse_unary();
        return std::make_unique<UnaryExpression>(operator_, std::move(operand));
    }
    
    return parse_postfix();
}

std::unique_ptr<Expression> Parser::parse_multiplicative() {
    auto expr = parse_unary();
    
    while (match({TokenType::STAR, TokenType::SLASH, TokenType::PERCENT})) {
        std::string operator_ = previous().lexeme;
        auto right = parse_unary();
        expr = std::make_unique<BinaryExpression>(std::move(expr), operator_, std::move(right));
    }
    
    return expr;
}

std::unique_ptr<Expression> Parser::parse_additive() {
    auto expr = parse_multiplicative();
    
    while (match({TokenType::PLUS, TokenType::MINUS})) {
        std::string operator_ = previous().lexeme;
        auto right = parse_multiplicative();
        expr = std::make_unique<BinaryExpression>(std::move(expr), operator_, std::move(right));
    }
    
    return expr;
}

std::unique_ptr<Expression> Parser::parse_relational() {
    auto expr = parse_additive();
    
    while (match({TokenType::GREATER, TokenType::GREATER_EQUAL, 
                  TokenType::LESS, TokenType::LESS_EQUAL})) {
        std::string operator_ = previous().lexeme;
        auto right = parse_additive();
        expr = std::make_unique<BinaryExpression>(std::move(expr), operator_, std::move(right));
    }
    
    return expr;
}

std::unique_ptr<Expression> Parser::parse_equality() {
    auto expr = parse_relational();
    
    while (match({TokenType::EQUAL_EQUAL, TokenType::BANG_EQUAL})) {
        std::string operator_ = previous().lexeme;
        auto right = parse_relational();
        expr = std::make_unique<BinaryExpression>(std::move(expr), operator_, std::move(right));
    }
    
    return expr;
}

std::unique_ptr<Expression> Parser::parse_logical_and() {
    auto expr = parse_equality();
    
    while (match({TokenType::AND})) {
        std::string operator_ = previous().lexeme;
        auto right = parse_equality();
        expr = std::make_unique<BinaryExpression>(std::move(expr), operator_, std::move(right));
    }
    
    return expr;
}

std::unique_ptr<Expression> Parser::parse_logical_or() {
    auto expr = parse_logical_and();
    
    while (match({TokenType::OR})) {
        std::string operator_ = previous().lexeme;
        auto right = parse_logical_and();
        expr = std::make_unique<BinaryExpression>(std::move(expr), operator_, std::move(right));
    }
    
    return expr;
}

std::unique_ptr<Expression> Parser::parse_ternary() {
    auto expr = parse_logical_or();
    
    if (match({TokenType::QUESTION})) {
        auto then_expr = parse_expression();
        consume(TokenType::COLON, "Expected ':' after ternary then expression");
        auto else_expr = parse_ternary();
        return std::make_unique<TernaryExpression>(std::move(expr), std::move(then_expr), std::move(else_expr));
    }
    
    return expr;
}

std::unique_ptr<Expression> Parser::parse_assignment() {
    auto expr = parse_ternary();
    
    if (match({TokenType::EQUAL})) {
        auto value = parse_assignment();
        
        if (auto variable = dynamic_cast<VariableExpression*>(expr.get())) {
            return std::make_unique<AssignmentExpression>(variable->name, std::move(value));
        }
        
        throw ParseError("Invalid assignment target");
    }
    
    return expr;
}

std::unique_ptr<Expression> Parser::parse_expression() {
    return parse_assignment();
}

std::unique_ptr<Statement> Parser::parse_expression_statement() {
    auto expr = parse_expression();
    
    if (match({TokenType::SEMICOLON})) {
        // Optional semicolon
    }
    
    return std::make_unique<ExpressionStatement>(std::move(expr));
}

std::unique_ptr<Statement> Parser::parse_variable_declaration() {
    std::string name = consume(TokenType::IDENTIFIER, "Expected variable name").lexeme;
    
    std::unique_ptr<Expression> initializer;
    if (match({TokenType::EQUAL})) {
        initializer = parse_expression();
    }
    
    if (match({TokenType::SEMICOLON})) {
        // Optional semicolon
    }
    
    return std::make_unique<VariableStatement>(name, std::move(initializer));
}

std::unique_ptr<Statement> Parser::parse_function_declaration() {
    std::string name = consume(TokenType::IDENTIFIER, "Expected function name").lexeme;
    
    consume(TokenType::LEFT_PAREN, "Expected '(' after function name");
    
    std::vector<std::string> parameters;
    if (!check(TokenType::RIGHT_PAREN)) {
        do {
            parameters.push_back(consume(TokenType::IDENTIFIER, "Expected parameter name").lexeme);
        } while (match({TokenType::COMMA}));
    }
    
    consume(TokenType::RIGHT_PAREN, "Expected ')' after parameters");
    
    consume(TokenType::LEFT_BRACE, "Expected '{' before function body");
    
    std::vector<std::unique_ptr<Statement>> body;
    while (!check(TokenType::RIGHT_BRACE) && !is_at_end()) {
        body.push_back(parse_statement());
    }
    
    consume(TokenType::RIGHT_BRACE, "Expected '}' after function body");
    
    return std::make_unique<FunctionStatement>(name, parameters, std::move(body));
}

std::unique_ptr<Statement> Parser::parse_if_statement() {
    consume(TokenType::LEFT_PAREN, "Expected '(' after 'if'");
    auto condition = parse_expression();
    consume(TokenType::RIGHT_PAREN, "Expected ')' after if condition");
    
    auto then_branch = parse_statement();
    
    std::unique_ptr<Statement> else_branch;
    if (match({TokenType::ELSE})) {
        else_branch = parse_statement();
    }
    
    return std::make_unique<IfStatement>(std::move(condition), std::move(then_branch), std::move(else_branch));
}

std::unique_ptr<Statement> Parser::parse_while_statement() {
    consume(TokenType::LEFT_PAREN, "Expected '(' after 'while'");
    auto condition = parse_expression();
    consume(TokenType::RIGHT_PAREN, "Expected ')' after while condition");
    
    auto body = parse_statement();
    
    return std::make_unique<WhileStatement>(std::move(condition), std::move(body));
}

std::unique_ptr<Statement> Parser::parse_for_statement() {
    consume(TokenType::LEFT_PAREN, "Expected '(' after 'for'");
    
    std::unique_ptr<Statement> initializer;
    if (match({TokenType::SEMICOLON})) {
        initializer = nullptr;
    } else if (match({TokenType::VAR})) {
        initializer = parse_variable_declaration();
    } else {
        initializer = parse_expression_statement();
    }
    
    std::unique_ptr<Expression> condition;
    if (!check(TokenType::SEMICOLON)) {
        condition = parse_expression();
    }
    consume(TokenType::SEMICOLON, "Expected ';' after for condition");
    
    std::unique_ptr<Expression> increment;
    if (!check(TokenType::RIGHT_PAREN)) {
        increment = parse_expression();
    }
    consume(TokenType::RIGHT_PAREN, "Expected ')' after for clauses");
    
    auto body = parse_statement();
    
    return std::make_unique<ForStatement>(std::move(initializer), std::move(condition), 
                                         std::move(increment), std::move(body));
}

std::unique_ptr<Statement> Parser::parse_return_statement() {
    std::unique_ptr<Expression> value;
    if (!check(TokenType::SEMICOLON) && !check(TokenType::NEWLINE)) {
        value = parse_expression();
    }
    
    if (match({TokenType::SEMICOLON})) {
        // Optional semicolon
    }
    
    return std::make_unique<ReturnStatement>(std::move(value));
}

std::unique_ptr<Statement> Parser::parse_break_statement() {
    if (match({TokenType::SEMICOLON})) {
        // Optional semicolon
    }
    
    return std::make_unique<BreakStatement>();
}

std::unique_ptr<Statement> Parser::parse_continue_statement() {
    if (match({TokenType::SEMICOLON})) {
        // Optional semicolon
    }
    
    return std::make_unique<ContinueStatement>();
}

std::unique_ptr<Statement> Parser::parse_block_statement() {
    std::vector<std::unique_ptr<Statement>> statements;
    
    while (!check(TokenType::RIGHT_BRACE) && !is_at_end()) {
        statements.push_back(parse_statement());
    }
    
    consume(TokenType::RIGHT_BRACE, "Expected '}' after block");
    
    return std::make_unique<BlockStatement>(std::move(statements));
}

std::unique_ptr<Statement> Parser::parse_import_statement() {
    std::string module = consume(TokenType::STRING, "Expected module name").lexeme;
    
    if (match({TokenType::SEMICOLON})) {
        // Optional semicolon
    }
    
    return std::make_unique<ImportStatement>(module);
}

std::unique_ptr<Statement> Parser::parse_statement() {
    skip_newlines();
    
    if (match({TokenType::IF})) {
        return parse_if_statement();
    }
    
    if (match({TokenType::WHILE})) {
        return parse_while_statement();
    }
    
    if (match({TokenType::FOR})) {
        return parse_for_statement();
    }
    
    if (match({TokenType::RETURN})) {
        return parse_return_statement();
    }
    
    if (match({TokenType::BREAK})) {
        return parse_break_statement();
    }
    
    if (match({TokenType::CONTINUE})) {
        return parse_continue_statement();
    }
    
    if (match({TokenType::LEFT_BRACE})) {
        return parse_block_statement();
    }
    
    if (match({TokenType::VAR})) {
        return parse_variable_declaration();
    }
    
    if (match({TokenType::FUNC})) {
        return parse_function_declaration();
    }
    
    if (match({TokenType::IMPORT})) {
        return parse_import_statement();
    }
    
    return parse_expression_statement();
}

std::unique_ptr<Expression> Parser::parse_array_literal() {
    std::vector<std::unique_ptr<Expression>> elements;
    
    if (!check(TokenType::RIGHT_BRACKET)) {
        do {
            elements.push_back(parse_expression());
        } while (match({TokenType::COMMA}));
    }
    
    consume(TokenType::RIGHT_BRACKET, "Expected ']' after array elements");
    
    return std::make_unique<ArrayExpression>(std::move(elements));
}

std::unique_ptr<Expression> Parser::parse_object_literal() {
    std::vector<std::pair<std::string, std::unique_ptr<Expression>>> properties;
    
    if (!check(TokenType::RIGHT_BRACE)) {
        do {
            std::string key;
            if (check(TokenType::STRING)) {
                key = advance().lexeme;
            } else if (check(TokenType::IDENTIFIER)) {
                key = advance().lexeme;
            } else {
                throw ParseError("Expected property name");
            }
            
            consume(TokenType::COLON, "Expected ':' after property name");
            auto value = parse_expression();
            
            properties.emplace_back(key, std::move(value));
        } while (match({TokenType::COMMA}));
    }
    
    consume(TokenType::RIGHT_BRACE, "Expected '}' after object properties");
    
    return std::make_unique<ObjectExpression>(std::move(properties));
}

std::unique_ptr<Expression> Parser::parse_function_call(const std::string& name) {
    consume(TokenType::LEFT_PAREN, "Expected '(' after function name");
    
    std::vector<std::unique_ptr<Expression>> arguments;
    if (!check(TokenType::RIGHT_PAREN)) {
        do {
            arguments.push_back(parse_expression());
        } while (match({TokenType::COMMA}));
    }
    
    consume(TokenType::RIGHT_PAREN, "Expected ')' after arguments");
    
    return std::make_unique<CallExpression>(name, std::move(arguments));
}

std::vector<std::unique_ptr<Statement>> Parser::parse() {
    std::vector<std::unique_ptr<Statement>> statements;
    
    while (!is_at_end()) {
        try {
            statements.push_back(parse_statement());
        } catch (const ParseError& e) {
            std::cerr << "Parse error: " << e.what() << std::endl;
            synchronize();
        }
    }
    
    return statements;
}

std::unique_ptr<Expression> Parser::parse_single_expression() {
    return parse_expression();
}

void Parser::reset() {
    current = 0;
}

} 