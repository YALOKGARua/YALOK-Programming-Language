#include <yalok/token.hpp>

namespace yalok {

std::string TokenHelper::token_type_to_string(TokenType type) {
    switch (type) {
        case TokenType::IDENTIFIER: return "IDENTIFIER";
        case TokenType::NUMBER: return "NUMBER";
        case TokenType::STRING: return "STRING";
        case TokenType::HACK: return "HACK";
        case TokenType::CRACK: return "CRACK";
        case TokenType::PWN: return "PWN";
        case TokenType::EXPLOIT: return "EXPLOIT";
        case TokenType::INJECT: return "INJECT";
        case TokenType::PAYLOAD: return "PAYLOAD";
        case TokenType::SHELL: return "SHELL";
        case TokenType::ROOT: return "ROOT";
        case TokenType::ADMIN: return "ADMIN";
        case TokenType::ENCRYPT: return "ENCRYPT";
        case TokenType::DECRYPT: return "DECRYPT";
        case TokenType::HASH: return "HASH";
        case TokenType::SCAN: return "SCAN";
        case TokenType::PROBE: return "PROBE";
        case TokenType::BREACH: return "BREACH";
        case TokenType::BACKDOOR: return "BACKDOOR";
        case TokenType::GHOST: return "GHOST";
        case TokenType::PHANTOM: return "PHANTOM";
        case TokenType::BINARY: return "BINARY";
        case TokenType::HEX: return "HEX";
        case TokenType::BYTE: return "BYTE";
        case TokenType::BUFFER: return "BUFFER";
        case TokenType::STACK: return "STACK";
        case TokenType::HEAP: return "HEAP";
        case TokenType::MEMORY: return "MEMORY";
        case TokenType::SYSCALL: return "SYSCALL";
        case TokenType::LSHIFT: return "LSHIFT";
        case TokenType::RSHIFT: return "RSHIFT";
        case TokenType::BITWISE_AND: return "BITWISE_AND";
        case TokenType::BITWISE_OR: return "BITWISE_OR";
        case TokenType::BITWISE_XOR: return "BITWISE_XOR";
        case TokenType::BITWISE_NOT: return "BITWISE_NOT";
        default: return "UNKNOWN";
    }
}

bool TokenHelper::is_binary_operator(TokenType type) {
    switch (type) {
        case TokenType::PLUS:
        case TokenType::MINUS:
        case TokenType::MULTIPLY:
        case TokenType::DIVIDE:
        case TokenType::MODULO:
        case TokenType::POWER:
        case TokenType::EQUALS:
        case TokenType::NOT_EQUALS:
        case TokenType::LESS_THAN:
        case TokenType::GREATER_THAN:
        case TokenType::LESS_EQUAL:
        case TokenType::GREATER_EQUAL:
        case TokenType::AND:
        case TokenType::OR:
        case TokenType::LSHIFT:
        case TokenType::RSHIFT:
        case TokenType::BITWISE_AND:
        case TokenType::BITWISE_OR:
        case TokenType::BITWISE_XOR:
            return true;
        default:
            return false;
    }
}

bool TokenHelper::is_unary_operator(TokenType type) {
    switch (type) {
        case TokenType::MINUS:
        case TokenType::NOT:
        case TokenType::BITWISE_NOT:
        case TokenType::INCREMENT:
        case TokenType::DECREMENT:
            return true;
        default:
            return false;
    }
}

int TokenHelper::get_precedence(TokenType type) {
    switch (type) {
        case TokenType::OR: return 1;
        case TokenType::AND: return 2;
        case TokenType::BITWISE_OR: return 3;
        case TokenType::BITWISE_XOR: return 4;
        case TokenType::BITWISE_AND: return 5;
        case TokenType::EQUALS:
        case TokenType::NOT_EQUALS: return 6;
        case TokenType::LESS_THAN:
        case TokenType::GREATER_THAN:
        case TokenType::LESS_EQUAL:
        case TokenType::GREATER_EQUAL: return 7;
        case TokenType::LSHIFT:
        case TokenType::RSHIFT: return 8;
        case TokenType::PLUS:
        case TokenType::MINUS: return 9;
        case TokenType::MULTIPLY:
        case TokenType::DIVIDE:
        case TokenType::MODULO: return 10;
        case TokenType::POWER: return 11;
        default: return 0;
    }
}

std::map<std::string, TokenType> TokenHelper::get_keywords() {
    return {
        {"hack", TokenType::HACK},
        {"crack", TokenType::CRACK},
        {"pwn", TokenType::PWN},
        {"exploit", TokenType::EXPLOIT},
        {"inject", TokenType::INJECT},
        {"payload", TokenType::PAYLOAD},
        {"shell", TokenType::SHELL},
        {"root", TokenType::ROOT},
        {"admin", TokenType::ADMIN},
        {"encrypt", TokenType::ENCRYPT},
        {"decrypt", TokenType::DECRYPT},
        {"hash", TokenType::HASH},
        {"scan", TokenType::SCAN},
        {"probe", TokenType::PROBE},
        {"breach", TokenType::BREACH},
        {"backdoor", TokenType::BACKDOOR},
        {"trojan", TokenType::TROJAN},
        {"virus", TokenType::VIRUS},
        {"worm", TokenType::WORM},
        {"keylog", TokenType::KEYLOG},
        {"sniff", TokenType::SNIFF},
        {"spoof", TokenType::SPOOF},
        {"mask", TokenType::MASK},
        {"ghost", TokenType::GHOST},
        {"phantom", TokenType::PHANTOM},
        {"binary", TokenType::BINARY},
        {"hex", TokenType::HEX},
        {"byte", TokenType::BYTE},
        {"word", TokenType::WORD},
        {"dword", TokenType::DWORD},
        {"qword", TokenType::QWORD},
        {"buffer", TokenType::BUFFER},
        {"stack", TokenType::STACK},
        {"heap", TokenType::HEAP},
        {"memory", TokenType::MEMORY},
        {"register", TokenType::REGISTER},
        {"syscall", TokenType::SYSCALL},
        {"interrupt", TokenType::INTERRUPT},
        {"trap", TokenType::TRAP},
        {"signal", TokenType::SIGNAL},
        {"if", TokenType::IF},
        {"else", TokenType::ELSE},
        {"while", TokenType::WHILE},
        {"for", TokenType::FOR},
        {"func", TokenType::FUNCTION},
        {"return", TokenType::RETURN},
        {"var", TokenType::VAR},
        {"const", TokenType::CONST},
        {"import", TokenType::IMPORT},
        {"true", TokenType::IDENTIFIER},
        {"false", TokenType::IDENTIFIER},
        {"nil", TokenType::IDENTIFIER},
        {"and", TokenType::AND},
        {"or", TokenType::OR},
        {"not", TokenType::NOT}
    };
}

} 