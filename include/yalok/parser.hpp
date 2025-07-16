#pragma once

#include "token.hpp"
#include "ast.hpp"
#include <vector>
#include <memory>
#include <stdexcept>

namespace yalok {

class ParseError : public std::runtime_error {
public:
    ParseError(const std::string& message) : std::runtime_error(message) {}
};

class Parser {
private:
    std::vector<Token> tokens;
    size_t current;
    
    Token peek();
    Token previous();
    Token advance();
    bool is_at_end();
    bool check(TokenType type);
    bool match(std::initializer_list<TokenType> types);
    
    void skip_newlines();
    Token consume(TokenType type, const std::string& message);
    void synchronize();
    
    std::unique_ptr<Expression> parse_primary();
    std::unique_ptr<Expression> parse_postfix();
    std::unique_ptr<Expression> parse_unary();
    std::unique_ptr<Expression> parse_multiplicative();
    std::unique_ptr<Expression> parse_additive();
    std::unique_ptr<Expression> parse_relational();
    std::unique_ptr<Expression> parse_equality();
    std::unique_ptr<Expression> parse_logical_and();
    std::unique_ptr<Expression> parse_logical_or();
    std::unique_ptr<Expression> parse_ternary();
    std::unique_ptr<Expression> parse_assignment();
    std::unique_ptr<Expression> parse_expression();
    
    std::unique_ptr<Statement> parse_expression_statement();
    std::unique_ptr<Statement> parse_variable_declaration();
    std::unique_ptr<Statement> parse_function_declaration();
    std::unique_ptr<Statement> parse_if_statement();
    std::unique_ptr<Statement> parse_while_statement();
    std::unique_ptr<Statement> parse_for_statement();
    std::unique_ptr<Statement> parse_return_statement();
    std::unique_ptr<Statement> parse_break_statement();
    std::unique_ptr<Statement> parse_continue_statement();
    std::unique_ptr<Statement> parse_block_statement();
    std::unique_ptr<Statement> parse_import_statement();
    std::unique_ptr<Statement> parse_statement();
    
    std::unique_ptr<Expression> parse_array_literal();
    std::unique_ptr<Expression> parse_object_literal();
    std::unique_ptr<Expression> parse_function_call(const std::string& name);
    
public:
    Parser(const std::vector<Token>& tokens);
    
    std::vector<std::unique_ptr<Statement>> parse();
    std::unique_ptr<Expression> parse_single_expression();
    
    void reset();
    size_t get_current_position() const { return current; }
};

} 