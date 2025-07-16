#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <variant>
#include <concepts>
#include <type_traits>
#include <ranges>
#include <optional>
#include <span>
#include <format>
#include <coroutine>

namespace yalok {

template<typename T>
concept Numeric = std::integral<T> || std::floating_point<T>;

template<typename T>
concept Serializable = requires(T t) {
    t.to_string();
};

template<typename T>
concept Comparable = requires(T a, T b) {
    { a == b } -> std::convertible_to<bool>;
    { a < b } -> std::convertible_to<bool>;
};

template<typename T>
concept Hashable = requires(T t) {
    { std::hash<T>{}(t) } -> std::convertible_to<std::size_t>;
};

class Value;
using ValuePtr = std::unique_ptr<Value>;
using ValueArray = std::vector<Value>;
using ValueMap = std::map<std::string, Value>;
using ValueFunction = std::function<Value(std::span<const Value>)>;

enum class ValueType : uint8_t {
    NIL = 0, INTEGER, FLOAT, STRING, BOOLEAN, 
    ARRAY, OBJECT, FUNCTION, BINARY, CRYPTO,
    SYSCALL, MEMORY, REGISTER, EXPLOIT, PAYLOAD
};

template<ValueType T>
struct ValueTraits;

template<> struct ValueTraits<ValueType::INTEGER> { using type = int64_t; };
template<> struct ValueTraits<ValueType::FLOAT> { using type = double; };
template<> struct ValueTraits<ValueType::STRING> { using type = std::string; };
template<> struct ValueTraits<ValueType::BOOLEAN> { using type = bool; };
template<> struct ValueTraits<ValueType::ARRAY> { using type = ValueArray; };
template<> struct ValueTraits<ValueType::OBJECT> { using type = ValueMap; };
template<> struct ValueTraits<ValueType::FUNCTION> { using type = ValueFunction; };
template<> struct ValueTraits<ValueType::BINARY> { using type = std::vector<uint8_t>; };

template<ValueType T>
using ValueTraits_t = typename ValueTraits<T>::type;

class Value {
private:
    using ValueVariant = std::variant<
        std::monostate,
        int64_t,
        double,
        std::string,
        bool,
        ValueArray,
        ValueMap,
        ValueFunction,
        std::vector<uint8_t>
    >;

    ValueVariant data_;
    ValueType type_;

public:
    Value() : data_(std::monostate{}), type_(ValueType::NIL) {}
    
    template<typename T>
    explicit Value(T&& value) requires std::constructible_from<ValueVariant, T> 
        : data_(std::forward<T>(value)) {
        if constexpr (std::same_as<std::decay_t<T>, int64_t>) type_ = ValueType::INTEGER;
        else if constexpr (std::same_as<std::decay_t<T>, double>) type_ = ValueType::FLOAT;
        else if constexpr (std::same_as<std::decay_t<T>, std::string>) type_ = ValueType::STRING;
        else if constexpr (std::same_as<std::decay_t<T>, bool>) type_ = ValueType::BOOLEAN;
        else if constexpr (std::same_as<std::decay_t<T>, ValueArray>) type_ = ValueType::ARRAY;
        else if constexpr (std::same_as<std::decay_t<T>, ValueMap>) type_ = ValueType::OBJECT;
        else if constexpr (std::same_as<std::decay_t<T>, ValueFunction>) type_ = ValueType::FUNCTION;
        else if constexpr (std::same_as<std::decay_t<T>, std::vector<uint8_t>>) type_ = ValueType::BINARY;
    }

    template<ValueType T>
    constexpr auto& get() {
        return std::get<ValueTraits_t<T>>(data_);
    }

    template<ValueType T>
    constexpr const auto& get() const {
        return std::get<ValueTraits_t<T>>(data_);
    }

    template<ValueType T>
    constexpr bool is() const noexcept {
        return type_ == T;
    }

    constexpr ValueType type() const noexcept { return type_; }

    std::string to_string() const;
    constexpr bool is_truthy() const noexcept;
    bool equals(const Value& other) const noexcept;

    Value operator+(const Value& other) const;
    Value operator-(const Value& other) const;
    Value operator*(const Value& other) const;
    Value operator/(const Value& other) const;
    Value operator%(const Value& other) const;
    Value operator&(const Value& other) const;
    Value operator|(const Value& other) const;
    Value operator^(const Value& other) const;
    Value operator~() const;
    Value operator<<(const Value& other) const;
    Value operator>>(const Value& other) const;
    Value operator<(const Value& other) const;
    Value operator>(const Value& other) const;
    Value operator<=(const Value& other) const;
    Value operator>=(const Value& other) const;
    Value operator==(const Value& other) const;
    Value operator!=(const Value& other) const;
    Value operator&&(const Value& other) const;
    Value operator||(const Value& other) const;
    Value operator!() const;

    template<typename... Args>
    Value call(Args&&... args) const requires (sizeof...(args) <= 16) {
        if (!is<ValueType::FUNCTION>()) {
            throw std::runtime_error("Value is not callable");
        }
        std::array<Value, sizeof...(args)> arg_array{Value(std::forward<Args>(args))...};
        return get<ValueType::FUNCTION>()(std::span<const Value>(arg_array));
    }

    Value& operator[](const std::string& key);
    const Value& operator[](const std::string& key) const;
    Value& operator[](size_t index);
    const Value& operator[](size_t index) const;

    template<std::ranges::range R>
    static Value from_range(R&& range) {
        ValueArray arr;
        for (auto&& item : range) {
            arr.emplace_back(item);
        }
        return Value(std::move(arr));
    }

    struct Iterator {
        using iterator_category = std::forward_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using value_type = Value;
        using pointer = Value*;
        using reference = Value&;

        const Value* container;
        size_t index;

        Iterator(const Value* c, size_t i) : container(c), index(i) {}

        reference operator*() const;
        pointer operator->() const;
        Iterator& operator++();
        Iterator operator++(int);
        bool operator==(const Iterator& other) const;
        bool operator!=(const Iterator& other) const;
    };

    Iterator begin() const;
    Iterator end() const;
    size_t size() const;
    bool empty() const;

    std::optional<Value> try_get(const std::string& key) const;
    std::optional<Value> try_get(size_t index) const;

    template<typename T>
    std::optional<T> try_cast() const {
        if constexpr (std::same_as<T, int64_t> && is<ValueType::INTEGER>()) {
            return get<ValueType::INTEGER>();
        } else if constexpr (std::same_as<T, double> && is<ValueType::FLOAT>()) {
            return get<ValueType::FLOAT>();
        } else if constexpr (std::same_as<T, std::string> && is<ValueType::STRING>()) {
            return get<ValueType::STRING>();
        } else if constexpr (std::same_as<T, bool> && is<ValueType::BOOLEAN>()) {
            return get<ValueType::BOOLEAN>();
        }
        return std::nullopt;
    }

    Value deep_copy() const;
    Value shallow_copy() const;
    void clear();
    void reserve(size_t capacity);
    void resize(size_t size);
    void push_back(const Value& value);
    void push_back(Value&& value);
    void pop_back();
    void insert(const std::string& key, const Value& value);
    void insert(const std::string& key, Value&& value);
    void erase(const std::string& key);
    void erase(size_t index);
    bool contains(const std::string& key) const;
    bool contains(size_t index) const;
};

template<typename T>
class ValueFactory {
public:
    static Value create(T&& value) {
        return Value(std::forward<T>(value));
    }
};

template<>
class ValueFactory<std::vector<uint8_t>> {
public:
    static Value create_binary(const std::vector<uint8_t>& data) {
        return Value(data);
    }
    
    static Value create_hex(const std::string& hex_str) {
        std::vector<uint8_t> data;
        for (size_t i = 0; i < hex_str.length(); i += 2) {
            data.push_back(std::stoi(hex_str.substr(i, 2), nullptr, 16));
        }
        return Value(data);
    }
};

class TypeConverter {
public:
    template<typename Target, typename Source>
    static std::optional<Target> convert(const Source& source) {
        if constexpr (std::same_as<Target, Source>) {
            return source;
        } else if constexpr (std::convertible_to<Source, Target>) {
            return static_cast<Target>(source);
        } else {
            return std::nullopt;
        }
    }
};

template<ValueType T>
class TypedValue {
private:
    ValueTraits_t<T> data_;
    
public:
    using value_type = ValueTraits_t<T>;
    
    explicit TypedValue(value_type data) : data_(std::move(data)) {}
    
    const value_type& get() const { return data_; }
    value_type& get() { return data_; }
    
    operator Value() const { return Value(data_); }
};

using IntValue = TypedValue<ValueType::INTEGER>;
using FloatValue = TypedValue<ValueType::FLOAT>;
using StringValue = TypedValue<ValueType::STRING>;
using BoolValue = TypedValue<ValueType::BOOLEAN>;
using ArrayValue = TypedValue<ValueType::ARRAY>;
using ObjectValue = TypedValue<ValueType::OBJECT>;
using FunctionValue = TypedValue<ValueType::FUNCTION>;
using BinaryValue = TypedValue<ValueType::BINARY>;

template<typename Op>
class ValueOperator {
public:
    template<typename T, typename U>
    static auto apply(const T& lhs, const U& rhs) 
        -> decltype(Op{}(lhs, rhs)) {
        return Op{}(lhs, rhs);
    }
};

struct AddOp {
    template<typename T, typename U>
    auto operator()(const T& lhs, const U& rhs) const -> decltype(lhs + rhs) {
        return lhs + rhs;
    }
};

struct SubOp {
    template<typename T, typename U>
    auto operator()(const T& lhs, const U& rhs) const -> decltype(lhs - rhs) {
        return lhs - rhs;
    }
};

struct MulOp {
    template<typename T, typename U>
    auto operator()(const T& lhs, const U& rhs) const -> decltype(lhs * rhs) {
        return lhs * rhs;
    }
};

struct DivOp {
    template<typename T, typename U>
    auto operator()(const T& lhs, const U& rhs) const -> decltype(lhs / rhs) {
        return lhs / rhs;
    }
};

template<typename F>
class ValueTransformer {
public:
    template<std::ranges::range R>
    static auto transform(R&& range, F&& func) {
        return std::ranges::transform_view(std::forward<R>(range), std::forward<F>(func));
    }
};

class ValueBuilder {
private:
    Value value_;
    
public:
    ValueBuilder() = default;
    
    ValueBuilder& integer(int64_t i) {
        value_ = Value(i);
        return *this;
    }
    
    ValueBuilder& floating(double f) {
        value_ = Value(f);
        return *this;
    }
    
    ValueBuilder& string(const std::string& s) {
        value_ = Value(s);
        return *this;
    }
    
    ValueBuilder& boolean(bool b) {
        value_ = Value(b);
        return *this;
    }
    
    ValueBuilder& array(const ValueArray& arr) {
        value_ = Value(arr);
        return *this;
    }
    
    ValueBuilder& object(const ValueMap& obj) {
        value_ = Value(obj);
        return *this;
    }
    
    ValueBuilder& function(const ValueFunction& func) {
        value_ = Value(func);
        return *this;
    }
    
    ValueBuilder& binary(const std::vector<uint8_t>& data) {
        value_ = Value(data);
        return *this;
    }
    
    Value build() { return std::move(value_); }
};

template<typename T>
struct ValueHash {
    std::size_t operator()(const T& value) const {
        return std::hash<T>{}(value);
    }
};

template<>
struct ValueHash<Value> {
    std::size_t operator()(const Value& value) const;
};

}

template<>
struct std::hash<yalok::Value> {
    std::size_t operator()(const yalok::Value& value) const {
        return yalok::ValueHash<yalok::Value>{}(value);
    }
};

template<>
struct std::formatter<yalok::Value> {
    constexpr auto parse(std::format_parse_context& ctx) {
        return ctx.begin();
    }
    
    template<typename FormatContext>
    auto format(const yalok::Value& value, FormatContext& ctx) {
        return std::format_to(ctx.out(), "{}", value.to_string());
    }
}; 