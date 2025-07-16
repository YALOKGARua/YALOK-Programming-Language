#pragma once

#include "token.hpp"
#include <string>
#include <vector>
#include <map>

namespace yalok {

class Lexer {
private:
    std::string source;
    size_t position;
    size_t line;
    size_t column;
    std::map<std::string, TokenType> keywords;
    
    char current_char();
    char peek_char();
    char peek_ahead(size_t offset);
    void advance();
    void skip_whitespace();
    void skip_comment();
    
    std::string read_identifier();
    std::string read_number();
    std::string read_string();
    std::string read_char();
    
    Token make_token(TokenType type, const std::string& value);
    Token make_number_token(const std::string& value);
    Token make_string_token(const std::string& value);
    Token make_identifier_token(const std::string& value);
    
    bool is_at_end();
    bool is_alpha(char c);
    bool is_digit(char c);
    bool is_alnum(char c);
    
public:
    Lexer(const std::string& source);
    
    Token next_token();
    std::vector<Token> tokenize();
    
    void reset();
    size_t get_position() const { return position; }
    size_t get_line() const { return line; }
    size_t get_column() const { return column; }
};

} 