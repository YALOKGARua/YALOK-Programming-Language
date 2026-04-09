#include "yalok/lexer.hpp"
#include <stdexcept>
#include <unordered_map>
#include <algorithm>

namespace yalok {

static const std::unordered_map<std::string, TokenType> keywords = {
    {"load",     TokenType::Load},
    {"cell",     TokenType::Cell},
    {"proc",     TokenType::Proc},
    {"ret",      TokenType::Ret},
    {"check",    TokenType::Check},
    {"alt",      TokenType::Alt},
    {"loop",     TokenType::Loop},
    {"scan",     TokenType::Scan},
    {"thru",     TokenType::Thru},
    {"gate",     TokenType::Gate},
    {"packet",   TokenType::Packet},
    {"probe",    TokenType::Probe},
    {"breach",   TokenType::Breach},
    {"halt",     TokenType::Halt},
    {"skip",     TokenType::Skip},
    {"on",       TokenType::On},
    {"off",      TokenType::Off},
    {"nil",      TokenType::Nil},
};

std::string_view Token::typeName(TokenType t) {
    switch (t) {
        case TokenType::IntLit:    return "IntLit";
        case TokenType::FloatLit:  return "FloatLit";
        case TokenType::StrLit:    return "StrLit";
        case TokenType::BoolLit:   return "BoolLit";
        case TokenType::NilLit:    return "NilLit";
        case TokenType::Ident:     return "Ident";
        case TokenType::Load:      return "load";
        case TokenType::Cell:      return "cell";
        case TokenType::Proc:      return "proc";
        case TokenType::Ret:       return "ret";
        case TokenType::Check:     return "check";
        case TokenType::Alt:       return "alt";
        case TokenType::Loop:      return "loop";
        case TokenType::Scan:      return "scan";
        case TokenType::Thru:      return "thru";
        case TokenType::Gate:      return "gate";
        case TokenType::Packet:    return "packet";
        case TokenType::Probe:     return "probe";
        case TokenType::Breach:    return "breach";
        case TokenType::Halt:      return "halt";
        case TokenType::Skip:      return "skip";
        case TokenType::On:        return "on";
        case TokenType::Off:       return "off";
        case TokenType::Nil:       return "nil";
        case TokenType::Plus:      return "+";
        case TokenType::Minus:     return "-";
        case TokenType::Star:      return "*";
        case TokenType::Slash:     return "/";
        case TokenType::Percent:   return "%";
        case TokenType::Amp:       return "&";
        case TokenType::Pipe:      return "|";
        case TokenType::Caret:     return "^";
        case TokenType::Tilde:     return "~";
        case TokenType::Shl:       return "<<";
        case TokenType::Shr:       return ">>";
        case TokenType::AmpAmp:    return "&&";
        case TokenType::PipePipe:  return "||";
        case TokenType::Bang:      return "!";
        case TokenType::Eq:        return "=";
        case TokenType::EqEq:      return "==";
        case TokenType::BangEq:    return "!=";
        case TokenType::Lt:        return "<";
        case TokenType::Gt:        return ">";
        case TokenType::LtEq:      return "<=";
        case TokenType::GtEq:      return ">=";
        case TokenType::PlusEq:    return "+=";
        case TokenType::MinusEq:   return "-=";
        case TokenType::StarEq:    return "*=";
        case TokenType::SlashEq:   return "/=";
        case TokenType::PercentEq: return "%=";
        case TokenType::AmpEq:     return "&=";
        case TokenType::PipeEq:    return "|=";
        case TokenType::CaretEq:   return "^=";
        case TokenType::ShlEq:     return "<<=";
        case TokenType::ShrEq:     return ">>=";
        case TokenType::PipeGt:    return "|>";
        case TokenType::Arrow:     return "->";
        case TokenType::FatArrow:  return "=>";
        case TokenType::DotDot:    return "..";
        case TokenType::Dot:       return ".";
        case TokenType::Comma:     return ",";
        case TokenType::Colon:     return ":";
        case TokenType::Semi:      return ";";
        case TokenType::Underscore:return "_";
        case TokenType::LParen:    return "(";
        case TokenType::RParen:    return ")";
        case TokenType::LBrace:    return "{";
        case TokenType::RBrace:    return "}";
        case TokenType::LBrack:    return "[";
        case TokenType::RBrack:    return "]";
        case TokenType::Eof:       return "EOF";
        case TokenType::Error:     return "Error";
    }
    return "?";
}

Lexer::Lexer(std::string_view source)
    : src_(source), pos_(0), line_(1), col_(1) {}

char Lexer::peek() const {
    return atEnd() ? '\0' : src_[pos_];
}

char Lexer::peekNext() const {
    return (pos_ + 1 >= src_.size()) ? '\0' : src_[pos_ + 1];
}

char Lexer::advance() {
    char c = src_[pos_++];
    if (c == '\n') { line_++; col_ = 1; }
    else { col_++; }
    return c;
}

bool Lexer::atEnd() const {
    return pos_ >= src_.size();
}

bool Lexer::match(char expected) {
    if (atEnd() || src_[pos_] != expected) return false;
    advance();
    return true;
}

void Lexer::skipWhitespace() {
    while (!atEnd()) {
        char c = peek();
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            advance();
        } else if (c == '/' && peekNext() == '/') {
            skipLineComment();
        } else if (c == '/' && peekNext() == '*') {
            skipBlockComment();
        } else if (c == '#') {
            skipLineComment();
        } else {
            break;
        }
    }
}

void Lexer::skipLineComment() {
    while (!atEnd() && peek() != '\n') advance();
}

void Lexer::skipBlockComment() {
    advance(); advance();
    while (!atEnd()) {
        if (peek() == '*' && peekNext() == '/') {
            advance(); advance();
            return;
        }
        advance();
    }
}

Token Lexer::makeToken(TokenType type, const std::string& val) {
    return Token(type, val, line_, col_);
}

Token Lexer::scanNumber() {
    int startLine = line_, startCol = col_;
    size_t start = pos_;

    if (peek() == '0' && (peekNext() == 'x' || peekNext() == 'X')) {
        advance(); advance();
        while (!atEnd() && (std::isxdigit(peek()) || peek() == '_')) advance();
        std::string raw(src_.substr(start, pos_ - start));
        raw.erase(std::remove(raw.begin(), raw.end(), '_'), raw.end());
        int64_t val = std::stoll(raw, nullptr, 16);
        return Token(TokenType::IntLit, std::to_string(val), startLine, startCol);
    }

    if (peek() == '0' && (peekNext() == 'b' || peekNext() == 'B')) {
        advance(); advance();
        while (!atEnd() && (peek() == '0' || peek() == '1' || peek() == '_')) advance();
        std::string raw(src_.substr(start + 2, pos_ - start - 2));
        raw.erase(std::remove(raw.begin(), raw.end(), '_'), raw.end());
        int64_t val = std::stoll(raw, nullptr, 2);
        return Token(TokenType::IntLit, std::to_string(val), startLine, startCol);
    }

    while (!atEnd() && (std::isdigit(peek()) || peek() == '_')) advance();

    bool isFloat = false;
    if (peek() == '.' && peekNext() != '.') {
        isFloat = true;
        advance();
        while (!atEnd() && (std::isdigit(peek()) || peek() == '_')) advance();
    }

    if (peek() == 'e' || peek() == 'E') {
        isFloat = true;
        advance();
        if (peek() == '+' || peek() == '-') advance();
        while (!atEnd() && std::isdigit(peek())) advance();
    }

    std::string raw(src_.substr(start, pos_ - start));
    raw.erase(std::remove(raw.begin(), raw.end(), '_'), raw.end());

    if (isFloat) {
        return Token(TokenType::FloatLit, raw, startLine, startCol);
    }
    return Token(TokenType::IntLit, raw, startLine, startCol);
}

Token Lexer::scanString() {
    int startLine = line_, startCol = col_;
    char quote = advance();
    std::string result;

    while (!atEnd() && peek() != quote) {
        if (peek() == '\\') {
            advance();
            switch (peek()) {
                case 'n':  result += '\n'; break;
                case 't':  result += '\t'; break;
                case 'r':  result += '\r'; break;
                case '\\': result += '\\'; break;
                case '0':  result += '\0'; break;
                case 'x': {
                    advance();
                    std::string hex;
                    if (!atEnd() && std::isxdigit(peek())) hex += advance();
                    if (!atEnd() && std::isxdigit(peek())) hex += advance();
                    result += static_cast<char>(std::stoi(hex, nullptr, 16));
                    continue;
                }
                default:
                    if (peek() == quote) result += quote;
                    else { result += '\\'; result += peek(); }
                    break;
            }
            advance();
        } else {
            result += advance();
        }
    }

    if (!atEnd()) advance();
    return Token(TokenType::StrLit, result, startLine, startCol);
}

Token Lexer::scanIdentifier() {
    int startLine = line_, startCol = col_;
    size_t start = pos_;

    while (!atEnd() && (std::isalnum(peek()) || peek() == '_')) advance();

    std::string word(src_.substr(start, pos_ - start));

    auto it = keywords.find(word);
    if (it != keywords.end()) {
        if (it->second == TokenType::On || it->second == TokenType::Off)
            return Token(TokenType::BoolLit, word, startLine, startCol);
        if (it->second == TokenType::Nil)
            return Token(TokenType::NilLit, word, startLine, startCol);
        return Token(it->second, word, startLine, startCol);
    }

    if (word == "_") return Token(TokenType::Underscore, word, startLine, startCol);

    return Token(TokenType::Ident, word, startLine, startCol);
}

Token Lexer::nextToken() {
    skipWhitespace();
    if (atEnd()) return Token(TokenType::Eof, "", line_, col_);

    int startLine = line_, startCol = col_;
    char c = peek();

    if (std::isdigit(c)) return scanNumber();
    if (c == '"' || c == '\'') return scanString();
    if (std::isalpha(c) || c == '_') return scanIdentifier();

    advance();
    switch (c) {
        case '+': return match('=') ? Token(TokenType::PlusEq, "+=", startLine, startCol)
                                    : Token(TokenType::Plus, "+", startLine, startCol);
        case '-': return match('>') ? Token(TokenType::Arrow, "->", startLine, startCol)
                       : match('=') ? Token(TokenType::MinusEq, "-=", startLine, startCol)
                                    : Token(TokenType::Minus, "-", startLine, startCol);
        case '*': return match('=') ? Token(TokenType::StarEq, "*=", startLine, startCol)
                                    : Token(TokenType::Star, "*", startLine, startCol);
        case '/': return match('=') ? Token(TokenType::SlashEq, "/=", startLine, startCol)
                                    : Token(TokenType::Slash, "/", startLine, startCol);
        case '%': return match('=') ? Token(TokenType::PercentEq, "%=", startLine, startCol)
                                    : Token(TokenType::Percent, "%", startLine, startCol);
        case '&': return match('&') ? Token(TokenType::AmpAmp, "&&", startLine, startCol)
                       : match('=') ? Token(TokenType::AmpEq, "&=", startLine, startCol)
                                    : Token(TokenType::Amp, "&", startLine, startCol);
        case '|': return match('>') ? Token(TokenType::PipeGt, "|>", startLine, startCol)
                       : match('|') ? Token(TokenType::PipePipe, "||", startLine, startCol)
                       : match('=') ? Token(TokenType::PipeEq, "|=", startLine, startCol)
                                    : Token(TokenType::Pipe, "|", startLine, startCol);
        case '^': return match('=') ? Token(TokenType::CaretEq, "^=", startLine, startCol)
                                    : Token(TokenType::Caret, "^", startLine, startCol);
        case '~': return Token(TokenType::Tilde, "~", startLine, startCol);
        case '!': return match('=') ? Token(TokenType::BangEq, "!=", startLine, startCol)
                                    : Token(TokenType::Bang, "!", startLine, startCol);
        case '=': return match('=') ? Token(TokenType::EqEq, "==", startLine, startCol)
                       : match('>') ? Token(TokenType::FatArrow, "=>", startLine, startCol)
                                    : Token(TokenType::Eq, "=", startLine, startCol);
        case '<': return match('<') ? (match('=') ? Token(TokenType::ShlEq, "<<=", startLine, startCol)
                                                  : Token(TokenType::Shl, "<<", startLine, startCol))
                       : match('=') ? Token(TokenType::LtEq, "<=", startLine, startCol)
                                    : Token(TokenType::Lt, "<", startLine, startCol);
        case '>': return match('>') ? (match('=') ? Token(TokenType::ShrEq, ">>=", startLine, startCol)
                                                  : Token(TokenType::Shr, ">>", startLine, startCol))
                       : match('=') ? Token(TokenType::GtEq, ">=", startLine, startCol)
                                    : Token(TokenType::Gt, ">", startLine, startCol);
        case '.': return match('.') ? Token(TokenType::DotDot, "..", startLine, startCol)
                                    : Token(TokenType::Dot, ".", startLine, startCol);
        case ',': return Token(TokenType::Comma, ",", startLine, startCol);
        case ':': return Token(TokenType::Colon, ":", startLine, startCol);
        case ';': return Token(TokenType::Semi, ";", startLine, startCol);
        case '(': return Token(TokenType::LParen, "(", startLine, startCol);
        case ')': return Token(TokenType::RParen, ")", startLine, startCol);
        case '{': return Token(TokenType::LBrace, "{", startLine, startCol);
        case '}': return Token(TokenType::RBrace, "}", startLine, startCol);
        case '[': return Token(TokenType::LBrack, "[", startLine, startCol);
        case ']': return Token(TokenType::RBrack, "]", startLine, startCol);
        default:
            return Token(TokenType::Error, std::string(1, c), startLine, startCol);
    }
}

std::vector<Token> Lexer::tokenize() {
    std::vector<Token> tokens;
    while (true) {
        Token tok = nextToken();
        tokens.push_back(tok);
        if (tok.is(TokenType::Eof) || tok.is(TokenType::Error)) break;
    }
    return tokens;
}

}
