#pragma once

#include <string>
#include <map>

namespace yalok {

enum class TokenType {
    IDENTIFIER, NUMBER, STRING, OPERATOR, KEYWORD, DELIMITER,
    ASSIGN, PLUS, MINUS, MULTIPLY, DIVIDE, MODULO, POWER,
    EQUALS, NOT_EQUALS, LESS_THAN, GREATER_THAN, LESS_EQUAL, GREATER_EQUAL,
    AND, OR, NOT, IF, ELSE, WHILE, FOR, FUNCTION, RETURN, VAR, CONST, IMPORT,
    LPAREN, RPAREN, LBRACE, RBRACE, LBRACKET, RBRACKET, SEMICOLON, COMMA,
    DOT, ARROW, NEWLINE, EOF_TOKEN, COLON, QUESTION, INCREMENT, DECREMENT,
    PLUS_ASSIGN, MINUS_ASSIGN, MULTIPLY_ASSIGN, DIVIDE_ASSIGN,
    
    // Hacker-style operators
    LSHIFT, RSHIFT, BITWISE_AND, BITWISE_OR, BITWISE_XOR, BITWISE_NOT,
    LSHIFT_ASSIGN, RSHIFT_ASSIGN, AND_ASSIGN, OR_ASSIGN, XOR_ASSIGN,
    
    // Hacker-style keywords
    HACK, CRACK, PWN, EXPLOIT, INJECT, PAYLOAD, SHELL, ROOT, ADMIN,
    ENCRYPT, DECRYPT, HASH, SCAN, PROBE, BREACH, BACKDOOR, TROJAN,
    VIRUS, WORM, KEYLOG, SNIFF, SPOOF, MASK, GHOST, PHANTOM,
    BINARY, HEX, BYTE, WORD, DWORD, QWORD, BUFFER, STACK, HEAP,
    MEMORY, REGISTER, SYSCALL, INTERRUPT, TRAP, SIGNAL
};

struct Token {
    TokenType type;
    std::string value;
    int line;
    int column;
    
    Token() : type(TokenType::EOF_TOKEN), line(0), column(0) {}
    Token(TokenType t, const std::string& v, int l, int c) : type(t), value(v), line(l), column(c) {}
};

class TokenHelper {
public:
    static std::string token_type_to_string(TokenType type);
    static bool is_binary_operator(TokenType type);
    static bool is_unary_operator(TokenType type);
    static int get_precedence(TokenType type);
    static std::map<std::string, TokenType> get_keywords();
};

} 