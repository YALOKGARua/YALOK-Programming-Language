#pragma once
#include <string>
#include <string_view>
#include <cstdint>

namespace yalok {

enum class TokenType : uint8_t {
    IntLit, FloatLit, StrLit, BoolLit, NilLit,

    Ident,

    Load, Cell, Proc, Ret,
    Check, Alt, Loop, Scan, Thru,
    Gate, Packet, Probe, Breach,
    Halt, Skip,
    On, Off, Nil,

    Plus, Minus, Star, Slash, Percent,
    Amp, Pipe, Caret, Tilde, Shl, Shr,
    AmpAmp, PipePipe, Bang,

    Eq, EqEq, BangEq, Lt, Gt, LtEq, GtEq,
    PlusEq, MinusEq, StarEq, SlashEq, PercentEq,
    AmpEq, PipeEq, CaretEq, ShlEq, ShrEq,

    PipeGt,
    Arrow, FatArrow,
    DotDot,
    Dot,
    Comma, Colon, Semi, Underscore,
    LParen, RParen, LBrace, RBrace, LBrack, RBrack,

    Eof, Error
};

struct Token {
    TokenType type;
    std::string value;
    int line;
    int col;

    Token() : type(TokenType::Eof), line(0), col(0) {}
    Token(TokenType t, std::string v, int ln, int c)
        : type(t), value(std::move(v)), line(ln), col(c) {}

    bool is(TokenType t) const { return type == t; }
    bool isNot(TokenType t) const { return type != t; }

    static std::string_view typeName(TokenType t);
};

}
