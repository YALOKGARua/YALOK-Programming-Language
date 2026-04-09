#pragma once
#include "token.hpp"
#include <vector>
#include <string>
#include <string_view>

namespace yalok {

class Lexer {
public:
    explicit Lexer(std::string_view source);
    std::vector<Token> tokenize();

private:
    std::string_view src_;
    size_t pos_;
    int line_;
    int col_;

    char peek() const;
    char peekNext() const;
    char advance();
    bool atEnd() const;
    bool match(char expected);
    void skipWhitespace();
    void skipLineComment();
    void skipBlockComment();

    Token makeToken(TokenType type, const std::string& val);
    Token scanNumber();
    Token scanString();
    Token scanIdentifier();
    Token nextToken();
};

}
