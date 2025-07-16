#include <yalok/lexer.hpp>
#include <cctype>
#include <stdexcept>

namespace yalok {

Lexer::Lexer(const std::string& source) : source(source), position(0), line(1), column(1) {
    keywords = TokenHelper::get_keywords();
}

char Lexer::current_char() {
    if (position >= source.length()) return '\0';
    return source[position];
}

char Lexer::peek_char() {
    if (position + 1 >= source.length()) return '\0';
    return source[position + 1];
}

char Lexer::peek_ahead(size_t offset) {
    if (position + offset >= source.length()) return '\0';
    return source[position + offset];
}

void Lexer::advance() {
    if (position < source.length()) {
        if (source[position] == '\n') {
            line++;
            column = 1;
        } else {
            column++;
        }
        position++;
    }
}

void Lexer::skip_whitespace() {
    while (current_char() == ' ' || current_char() == '\t' || current_char() == '\r') {
        advance();
    }
}

void Lexer::skip_comment() {
    if (current_char() == '/' && peek_char() == '/') {
        while (current_char() != '\n' && current_char() != '\0') {
            advance();
        }
    } else if (current_char() == '/' && peek_char() == '*') {
        advance();
        advance();
        while (current_char() != '\0') {
            if (current_char() == '*' && peek_char() == '/') {
                advance();
                advance();
                break;
            }
            advance();
        }
    }
}

std::string Lexer::read_identifier() {
    std::string result;
    while (is_alnum(current_char()) || current_char() == '_') {
        result += current_char();
        advance();
    }
    return result;
}

std::string Lexer::read_number() {
    std::string result;
    bool has_dot = false;
    
    if (current_char() == '0' && peek_char() == 'x') {
        result += current_char();
        advance();
        result += current_char();
        advance();
        
        while (std::isdigit(current_char()) || 
               (current_char() >= 'a' && current_char() <= 'f') ||
               (current_char() >= 'A' && current_char() <= 'F')) {
            result += current_char();
            advance();
        }
        return result;
    }
    
    if (current_char() == '0' && peek_char() == 'b') {
        result += current_char();
        advance();
        result += current_char();
        advance();
        
        while (current_char() == '0' || current_char() == '1') {
            result += current_char();
            advance();
        }
        return result;
    }
    
    while (std::isdigit(current_char()) || (current_char() == '.' && !has_dot)) {
        if (current_char() == '.') {
            has_dot = true;
        }
        result += current_char();
        advance();
    }
    
    return result;
}

std::string Lexer::read_string() {
    std::string result;
    char quote = current_char();
    advance();
    
    while (current_char() != quote && current_char() != '\0') {
        if (current_char() == '\\') {
            advance();
            switch (current_char()) {
                case 'n': result += '\n'; break;
                case 't': result += '\t'; break;
                case 'r': result += '\r'; break;
                case '\\': result += '\\'; break;
                case '"': result += '"'; break;
                case '\'': result += '\''; break;
                case '0': result += '\0'; break;
                case 'x': {
                    advance();
                    char hex1 = current_char();
                    advance();
                    char hex2 = current_char();
                    int val = 0;
                    if (hex1 >= '0' && hex1 <= '9') val += (hex1 - '0') * 16;
                    else if (hex1 >= 'a' && hex1 <= 'f') val += (hex1 - 'a' + 10) * 16;
                    else if (hex1 >= 'A' && hex1 <= 'F') val += (hex1 - 'A' + 10) * 16;
                    
                    if (hex2 >= '0' && hex2 <= '9') val += (hex2 - '0');
                    else if (hex2 >= 'a' && hex2 <= 'f') val += (hex2 - 'a' + 10);
                    else if (hex2 >= 'A' && hex2 <= 'F') val += (hex2 - 'A' + 10);
                    
                    result += static_cast<char>(val);
                    break;
                }
                default: result += current_char(); break;
            }
        } else {
            result += current_char();
        }
        advance();
    }
    
    if (current_char() == quote) advance();
    return result;
}

std::string Lexer::read_char() {
    std::string result;
    advance();
    
    if (current_char() == '\\') {
        advance();
        switch (current_char()) {
            case 'n': result = "\n"; break;
            case 't': result = "\t"; break;
            case 'r': result = "\r"; break;
            case '\\': result = "\\"; break;
            case '\'': result = "'"; break;
            case '0': result = "\0"; break;
            default: result = std::string(1, current_char()); break;
        }
    } else {
        result = std::string(1, current_char());
    }
    
    advance();
    if (current_char() == '\'') advance();
    return result;
}

Token Lexer::make_token(TokenType type, const std::string& value) {
    return Token(type, value, line, column);
}

Token Lexer::make_number_token(const std::string& value) {
    return make_token(TokenType::NUMBER, value);
}

Token Lexer::make_string_token(const std::string& value) {
    return make_token(TokenType::STRING, value);
}

Token Lexer::make_identifier_token(const std::string& value) {
    auto it = keywords.find(value);
    if (it != keywords.end()) {
        return make_token(it->second, value);
    }
    return make_token(TokenType::IDENTIFIER, value);
}

bool Lexer::is_at_end() {
    return position >= source.length();
}

bool Lexer::is_alpha(char c) {
    return std::isalpha(c) || c == '_';
}

bool Lexer::is_digit(char c) {
    return std::isdigit(c);
}

bool Lexer::is_alnum(char c) {
    return std::isalnum(c) || c == '_';
}

Token Lexer::next_token() {
    while (!is_at_end()) {
        skip_whitespace();
        
        if (is_at_end()) break;
        
        if (current_char() == '/' && (peek_char() == '/' || peek_char() == '*')) {
            skip_comment();
            continue;
        }
        
        if (current_char() == '\n') {
            Token token = make_token(TokenType::NEWLINE, "\n");
            advance();
            return token;
        }
        
        if (is_alpha(current_char())) {
            return make_identifier_token(read_identifier());
        }
        
        if (is_digit(current_char()) || 
            (current_char() == '0' && (peek_char() == 'x' || peek_char() == 'b'))) {
            return make_number_token(read_number());
        }
        
        if (current_char() == '"') {
            return make_string_token(read_string());
        }
        
        if (current_char() == '\'') {
            return make_string_token(read_char());
        }
        
        char ch = current_char();
        size_t start_column = column;
        advance();
        
        switch (ch) {
            case '+':
                if (current_char() == '+') {
                    advance();
                    return make_token(TokenType::INCREMENT, "++");
                } else if (current_char() == '=') {
                    advance();
                    return make_token(TokenType::PLUS_ASSIGN, "+=");
                }
                return make_token(TokenType::PLUS, "+");
                
            case '-':
                if (current_char() == '-') {
                    advance();
                    return make_token(TokenType::DECREMENT, "--");
                } else if (current_char() == '=') {
                    advance();
                    return make_token(TokenType::MINUS_ASSIGN, "-=");
                } else if (current_char() == '>') {
                    advance();
                    return make_token(TokenType::ARROW, "->");
                }
                return make_token(TokenType::MINUS, "-");
                
            case '*':
                if (current_char() == '*') {
                    advance();
                    return make_token(TokenType::POWER, "**");
                } else if (current_char() == '=') {
                    advance();
                    return make_token(TokenType::MULTIPLY_ASSIGN, "*=");
                }
                return make_token(TokenType::MULTIPLY, "*");
                
            case '/':
                if (current_char() == '=') {
                    advance();
                    return make_token(TokenType::DIVIDE_ASSIGN, "/=");
                }
                return make_token(TokenType::DIVIDE, "/");
                
            case '%':
                return make_token(TokenType::MODULO, "%");
                
            case '=':
                if (current_char() == '=') {
                    advance();
                    return make_token(TokenType::EQUALS, "==");
                }
                return make_token(TokenType::ASSIGN, "=");
                
            case '!':
                if (current_char() == '=') {
                    advance();
                    return make_token(TokenType::NOT_EQUALS, "!=");
                }
                return make_token(TokenType::NOT, "!");
                
            case '<':
                if (current_char() == '<') {
                    advance();
                    if (current_char() == '=') {
                        advance();
                        return make_token(TokenType::LSHIFT_ASSIGN, "<<=");
                    }
                    return make_token(TokenType::LSHIFT, "<<");
                } else if (current_char() == '=') {
                    advance();
                    return make_token(TokenType::LESS_EQUAL, "<=");
                }
                return make_token(TokenType::LESS_THAN, "<");
                
            case '>':
                if (current_char() == '>') {
                    advance();
                    if (current_char() == '=') {
                        advance();
                        return make_token(TokenType::RSHIFT_ASSIGN, ">>=");
                    }
                    return make_token(TokenType::RSHIFT, ">>");
                } else if (current_char() == '=') {
                    advance();
                    return make_token(TokenType::GREATER_EQUAL, ">=");
                }
                return make_token(TokenType::GREATER_THAN, ">");
                
            case '&':
                if (current_char() == '&') {
                    advance();
                    return make_token(TokenType::AND, "&&");
                } else if (current_char() == '=') {
                    advance();
                    return make_token(TokenType::AND_ASSIGN, "&=");
                }
                return make_token(TokenType::BITWISE_AND, "&");
                
            case '|':
                if (current_char() == '|') {
                    advance();
                    return make_token(TokenType::OR, "||");
                } else if (current_char() == '=') {
                    advance();
                    return make_token(TokenType::OR_ASSIGN, "|=");
                }
                return make_token(TokenType::BITWISE_OR, "|");
                
            case '^':
                if (current_char() == '=') {
                    advance();
                    return make_token(TokenType::XOR_ASSIGN, "^=");
                }
                return make_token(TokenType::BITWISE_XOR, "^");
                
            case '~':
                return make_token(TokenType::BITWISE_NOT, "~");
                
            case '(':
                return make_token(TokenType::LPAREN, "(");
            case ')':
                return make_token(TokenType::RPAREN, ")");
            case '{':
                return make_token(TokenType::LBRACE, "{");
            case '}':
                return make_token(TokenType::RBRACE, "}");
            case '[':
                return make_token(TokenType::LBRACKET, "[");
            case ']':
                return make_token(TokenType::RBRACKET, "]");
            case ';':
                return make_token(TokenType::SEMICOLON, ";");
            case ',':
                return make_token(TokenType::COMMA, ",");
            case '.':
                return make_token(TokenType::DOT, ".");
            case ':':
                return make_token(TokenType::COLON, ":");
            case '?':
                return make_token(TokenType::QUESTION, "?");
                
            default:
                return make_token(TokenType::OPERATOR, std::string(1, ch));
        }
    }
    
    return make_token(TokenType::EOF_TOKEN, "");
}

std::vector<Token> Lexer::tokenize() {
    std::vector<Token> tokens;
    
    Token token;
    do {
        token = next_token();
        tokens.push_back(token);
    } while (token.type != TokenType::EOF_TOKEN);
    
    return tokens;
}

void Lexer::reset() {
    position = 0;
    line = 1;
    column = 1;
}

} 