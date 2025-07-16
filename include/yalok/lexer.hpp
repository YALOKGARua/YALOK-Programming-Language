#pragma once

#include "token.hpp"
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <concepts>
#include <ranges>
#include <string_view>
#include <span>
#include <optional>
#include <expected>
#include <coroutine>
#include <generator>
#include <memory_resource>
#include <regex>
#include <chrono>
#include <simd>
#include <execution>
#include <format>

namespace yalok {

template<typename T>
concept CharType = std::same_as<T, char> || std::same_as<T, char8_t> || std::same_as<T, char16_t> || std::same_as<T, char32_t>;

template<typename T>
concept StringLike = std::convertible_to<T, std::string_view> || std::same_as<T, std::string>;

template<typename T>
concept Tokenizable = requires(T t) {
    { t.begin() } -> std::forward_iterator;
    { t.end() } -> std::forward_iterator;
    typename T::value_type;
} && CharType<typename T::value_type>;

template<typename T>
concept TokenStream = std::ranges::range<T> && std::same_as<std::ranges::range_value_t<T>, Token>;

enum class LexerMode : uint8_t {
    NORMAL = 0,
    HACKER = 1,
    BINARY = 2,
    CRYPTO = 3,
    ASSEMBLY = 4,
    EXPLOIT = 5
};

struct LexerError {
    std::string message;
    size_t line;
    size_t column;
    size_t position;
    std::string context;
    
    std::string format() const {
        return std::format("LexerError at {}:{} (pos {}): {}\nContext: {}", 
                          line, column, position, message, context);
    }
};

using LexerResult = std::expected<Token, LexerError>;
using TokenResult = std::expected<std::vector<Token>, LexerError>;

template<typename Allocator = std::allocator<Token>>
class BasicLexer {
private:
    std::string_view source_;
    size_t position_;
    size_t line_;
    size_t column_;
    LexerMode mode_;
    std::pmr::unordered_map<std::string, TokenType> keywords_;
    std::pmr::unordered_map<std::string, TokenType> operators_;
    std::pmr::unordered_map<std::string, TokenType> hacker_keywords_;
    std::pmr::memory_resource* memory_resource_;
    
    struct SIMDMatcher {
        static constexpr size_t SIMD_WIDTH = 32;
        alignas(32) std::array<char, SIMD_WIDTH> pattern_;
        alignas(32) std::array<char, SIMD_WIDTH> mask_;
        
        template<size_t N>
        constexpr SIMDMatcher(const char (&pattern)[N]) {
            std::fill(pattern_.begin(), pattern_.end(), '\0');
            std::fill(mask_.begin(), mask_.end(), '\0');
            std::copy_n(pattern, std::min(N, SIMD_WIDTH), pattern_.begin());
            std::fill_n(mask_.begin(), std::min(N, SIMD_WIDTH), '\xFF');
        }
        
        bool match(std::string_view text, size_t pos) const noexcept;
    };
    
    static inline const SIMDMatcher HACK_PATTERN{"hack"};
    static inline const SIMDMatcher CRACK_PATTERN{"crack"};
    static inline const SIMDMatcher EXPLOIT_PATTERN{"exploit"};
    static inline const SIMDMatcher BINARY_PATTERN{"0b"};
    static inline const SIMDMatcher HEX_PATTERN{"0x"};
    
    constexpr char current_char() const noexcept {
        return position_ < source_.size() ? source_[position_] : '\0';
    }
    
    constexpr char peek_char(size_t offset = 1) const noexcept {
        return (position_ + offset) < source_.size() ? source_[position_ + offset] : '\0';
    }
    
    constexpr std::string_view peek_string(size_t length) const noexcept {
        return source_.substr(position_, std::min(length, source_.size() - position_));
    }
    
    constexpr void advance() noexcept {
        if (position_ < source_.size()) {
            if (source_[position_] == '\n') {
                line_++;
                column_ = 1;
            } else {
                column_++;
            }
            position_++;
        }
    }
    
    constexpr void advance_by(size_t count) noexcept {
        for (size_t i = 0; i < count && position_ < source_.size(); ++i) {
            advance();
        }
    }
    
    void skip_whitespace() noexcept {
        while (position_ < source_.size() && std::isspace(current_char())) {
            advance();
        }
    }
    
    void skip_comment();
    void skip_multiline_comment();
    
    std::expected<std::string, LexerError> read_identifier();
    std::expected<std::string, LexerError> read_number();
    std::expected<std::string, LexerError> read_string();
    std::expected<std::string, LexerError> read_char();
    std::expected<std::string, LexerError> read_raw_string();
    std::expected<std::string, LexerError> read_hex_literal();
    std::expected<std::string, LexerError> read_binary_literal();
    std::expected<std::string, LexerError> read_float_literal();
    std::expected<std::string, LexerError> read_scientific_notation();
    std::expected<std::string, LexerError> read_regex_literal();
    std::expected<std::string, LexerError> read_template_literal();
    
    template<typename Pred>
    std::string read_while(Pred&& predicate) {
        std::string result;
        while (position_ < source_.size() && predicate(current_char())) {
            result += current_char();
            advance();
        }
        return result;
    }
    
    template<typename Pred>
    constexpr bool match_sequence(Pred&& predicate) const noexcept {
        return predicate(current_char());
    }
    
    LexerResult make_token(TokenType type, std::string_view value);
    LexerResult make_error(std::string_view message);
    
    std::string get_context(size_t radius = 10) const;
    
    constexpr bool is_at_end() const noexcept {
        return position_ >= source_.size();
    }
    
    constexpr bool is_alpha(char c) const noexcept {
        return std::isalpha(c) || c == '_';
    }
    
    constexpr bool is_digit(char c) const noexcept {
        return std::isdigit(c);
    }
    
    constexpr bool is_alnum(char c) const noexcept {
        return std::isalnum(c) || c == '_';
    }
    
    constexpr bool is_hex_digit(char c) const noexcept {
        return std::isxdigit(c);
    }
    
    constexpr bool is_binary_digit(char c) const noexcept {
        return c == '0' || c == '1';
    }
    
    constexpr bool is_octal_digit(char c) const noexcept {
        return c >= '0' && c <= '7';
    }
    
    TokenType get_keyword_type(std::string_view identifier) const;
    TokenType get_operator_type(std::string_view op) const;
    TokenType get_hacker_keyword_type(std::string_view identifier) const;
    
    void initialize_keywords();
    void initialize_operators();
    void initialize_hacker_keywords();
    
    LexerResult scan_identifier();
    LexerResult scan_number();
    LexerResult scan_string();
    LexerResult scan_char();
    LexerResult scan_operator();
    LexerResult scan_punctuation();
    LexerResult scan_hacker_token();
    LexerResult scan_binary_literal();
    LexerResult scan_hex_literal();
    LexerResult scan_float();
    LexerResult scan_scientific();
    LexerResult scan_regex();
    LexerResult scan_template();
    
public:
    explicit BasicLexer(std::string_view source, 
                       std::pmr::memory_resource* mr = std::pmr::get_default_resource())
        : source_(source), position_(0), line_(1), column_(1), mode_(LexerMode::NORMAL), 
          keywords_(mr), operators_(mr), hacker_keywords_(mr), memory_resource_(mr) {
        initialize_keywords();
        initialize_operators();
        initialize_hacker_keywords();
    }
    
    LexerResult next_token();
    TokenResult tokenize();
    
    std::generator<Token> token_stream() {
        while (!is_at_end()) {
            auto result = next_token();
            if (result) {
                co_yield *result;
            } else {
                throw std::runtime_error(result.error().format());
            }
        }
        co_yield Token{TokenType::EOF_TOKEN, "", line_, column_};
    }
    
    template<std::ranges::range R>
    requires std::same_as<std::ranges::range_value_t<R>, char>
    static TokenResult tokenize_range(R&& range) {
        std::string source(std::ranges::begin(range), std::ranges::end(range));
        BasicLexer lexer(source);
        return lexer.tokenize();
    }
    
    template<StringLike S>
    static TokenResult tokenize_string(S&& str) {
        BasicLexer lexer(std::string_view(str));
        return lexer.tokenize();
    }
    
    void reset(std::string_view new_source = {}) {
        if (!new_source.empty()) {
            source_ = new_source;
        }
        position_ = 0;
        line_ = 1;
        column_ = 1;
    }
    
    void set_mode(LexerMode mode) { mode_ = mode; }
    LexerMode get_mode() const { return mode_; }
    
    constexpr size_t get_position() const noexcept { return position_; }
    constexpr size_t get_line() const noexcept { return line_; }
    constexpr size_t get_column() const noexcept { return column_; }
    std::string_view get_source() const { return source_; }
    
    auto get_remaining() const {
        return source_.substr(position_);
    }
    
    auto get_processed() const {
        return source_.substr(0, position_);
    }
    
    struct Position {
        size_t pos;
        size_t line;
        size_t column;
    };
    
    Position save_position() const {
        return {position_, line_, column_};
    }
    
    void restore_position(const Position& pos) {
        position_ = pos.pos;
        line_ = pos.line;
        column_ = pos.column;
    }
    
    bool match_keyword(std::string_view keyword) const;
    bool match_operator(std::string_view op) const;
    bool match_hacker_keyword(std::string_view keyword) const;
    
    template<typename... Keywords>
    bool match_any_keyword(Keywords&&... keywords) const {
        return (match_keyword(keywords) || ...);
    }
    
    template<typename... Operators>
    bool match_any_operator(Operators&&... operators) const {
        return (match_operator(operators) || ...);
    }
    
    std::vector<Token> peek_tokens(size_t count) const;
    std::optional<Token> peek_token(size_t offset = 1) const;
    
    class TokenIterator {
    private:
        BasicLexer* lexer_;
        mutable std::optional<Token> current_;
        
    public:
        using iterator_category = std::forward_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using value_type = Token;
        using pointer = Token*;
        using reference = Token&;
        
        explicit TokenIterator(BasicLexer* lexer) : lexer_(lexer) {}
        
        const Token& operator*() const {
            if (!current_) {
                auto result = lexer_->next_token();
                if (!result) {
                    throw std::runtime_error(result.error().format());
                }
                current_ = *result;
            }
            return *current_;
        }
        
        const Token* operator->() const {
            return &operator*();
        }
        
        TokenIterator& operator++() {
            current_.reset();
            return *this;
        }
        
        TokenIterator operator++(int) {
            auto temp = *this;
            ++(*this);
            return temp;
        }
        
        bool operator==(const TokenIterator& other) const {
            return lexer_ == other.lexer_ && 
                   (lexer_->is_at_end() || other.lexer_->is_at_end());
        }
        
        bool operator!=(const TokenIterator& other) const {
            return !(*this == other);
        }
    };
    
    TokenIterator begin() { return TokenIterator(this); }
    TokenIterator end() { return TokenIterator(nullptr); }
    
    class ParallelTokenizer {
    private:
        std::string_view source_;
        size_t chunk_size_;
        
    public:
        explicit ParallelTokenizer(std::string_view source, size_t chunk_size = 1024)
            : source_(source), chunk_size_(chunk_size) {}
        
        TokenResult tokenize_parallel() {
            std::vector<std::string_view> chunks;
            for (size_t i = 0; i < source_.size(); i += chunk_size_) {
                chunks.push_back(source_.substr(i, chunk_size_));
            }
            
            std::vector<std::vector<Token>> results(chunks.size());
            
            std::for_each(std::execution::par_unseq, chunks.begin(), chunks.end(),
                [&results, &chunks](const auto& chunk) {
                    auto index = &chunk - chunks.data();
                    BasicLexer lexer(chunk);
                    auto result = lexer.tokenize();
                    if (result) {
                        results[index] = std::move(*result);
                    }
                });
            
            std::vector<Token> merged;
            for (const auto& result : results) {
                merged.insert(merged.end(), result.begin(), result.end());
            }
            
            return merged;
        }
    };
    
    ParallelTokenizer parallel_tokenizer(size_t chunk_size = 1024) {
        return ParallelTokenizer(source_, chunk_size);
    }
    
    struct Statistics {
        size_t total_tokens = 0;
        size_t total_characters = 0;
        size_t total_lines = 0;
        std::chrono::nanoseconds tokenization_time{};
        std::unordered_map<TokenType, size_t> token_counts;
        
        void add_token(TokenType type) {
            total_tokens++;
            token_counts[type]++;
        }
        
        double tokens_per_second() const {
            if (tokenization_time.count() == 0) return 0.0;
            return static_cast<double>(total_tokens) / 
                   (static_cast<double>(tokenization_time.count()) / 1e9);
        }
        
        std::string report() const {
            return std::format("Tokens: {}, Characters: {}, Lines: {}, Speed: {:.2f} tokens/sec",
                              total_tokens, total_characters, total_lines, tokens_per_second());
        }
    };
    
    Statistics get_statistics() const;
    
    template<typename Callback>
    void tokenize_with_callback(Callback&& callback) {
        while (!is_at_end()) {
            auto result = next_token();
            if (result) {
                callback(*result);
            } else {
                throw std::runtime_error(result.error().format());
            }
        }
    }
    
    bool validate_syntax() const;
    std::vector<LexerError> get_all_errors() const;
    void enable_error_recovery(bool enable = true);
    void set_error_limit(size_t limit);
};

using Lexer = BasicLexer<>;
using PMRLexer = BasicLexer<std::pmr::polymorphic_allocator<Token>>;

template<typename Lexer>
class LexerFactory {
public:
    template<typename... Args>
    static auto create(Args&&... args) {
        return std::make_unique<Lexer>(std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    static auto create_shared(Args&&... args) {
        return std::make_shared<Lexer>(std::forward<Args>(args)...);
    }
};

using DefaultLexerFactory = LexerFactory<Lexer>;
using PMRLexerFactory = LexerFactory<PMRLexer>;

template<typename T>
concept LexerLike = requires(T lexer) {
    { lexer.next_token() } -> std::same_as<LexerResult>;
    { lexer.tokenize() } -> std::same_as<TokenResult>;
    { lexer.is_at_end() } -> std::same_as<bool>;
};

template<LexerLike L>
class LexerWrapper {
private:
    L lexer_;
    
public:
    template<typename... Args>
    explicit LexerWrapper(Args&&... args) : lexer_(std::forward<Args>(args)...) {}
    
    auto next_token() { return lexer_.next_token(); }
    auto tokenize() { return lexer_.tokenize(); }
    auto is_at_end() const { return lexer_.is_at_end(); }
    
    L& get_lexer() { return lexer_; }
    const L& get_lexer() const { return lexer_; }
};

class StreamingLexer {
private:
    std::string buffer_;
    size_t position_ = 0;
    bool finished_ = false;
    
public:
    void feed(std::string_view data) {
        buffer_ += data;
    }
    
    void finish() {
        finished_ = true;
    }
    
    std::optional<Token> next_token() {
        if (position_ >= buffer_.size() && finished_) {
            return std::nullopt;
        }
        
        BasicLexer lexer(std::string_view(buffer_).substr(position_));
        auto result = lexer.next_token();
        if (result) {
            position_ += result->value.size();
            return *result;
        }
        return std::nullopt;
    }
    
    std::generator<Token> stream() {
        while (auto token = next_token()) {
            co_yield *token;
        }
    }
};

template<typename Source>
auto tokenize(Source&& source) {
    if constexpr (std::same_as<std::decay_t<Source>, std::string_view>) {
        return BasicLexer::tokenize_string(source);
    } else if constexpr (std::ranges::range<Source>) {
        return BasicLexer::tokenize_range(source);
    } else {
        return BasicLexer::tokenize_string(std::string_view(source));
    }
}

template<typename Source>
auto create_lexer(Source&& source) {
    return std::make_unique<BasicLexer<>>(std::string_view(source));
}

template<typename Source>
auto create_streaming_lexer() {
    return std::make_unique<StreamingLexer>();
}

} 