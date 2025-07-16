#include <yalok/value.hpp>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <execution>
#include <immintrin.h>
#include <bit>
#include <numbers>
#include <charconv>
#include <regex>
#include <random>
#include <chrono>
#include <thread>
#include <future>
#include <atomic>
#include <memory_resource>

namespace yalok {

constexpr bool Value::is_truthy() const noexcept {
    return std::visit([](const auto& value) -> bool {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::same_as<T, std::monostate>) {
            return false;
        } else if constexpr (std::same_as<T, bool>) {
            return value;
        } else if constexpr (std::same_as<T, int64_t>) {
            return value != 0;
        } else if constexpr (std::same_as<T, double>) {
            return value != 0.0 && !std::isnan(value);
        } else if constexpr (std::same_as<T, std::string>) {
            return !value.empty();
        } else if constexpr (std::same_as<T, ValueArray>) {
            return !value.empty();
        } else if constexpr (std::same_as<T, ValueMap>) {
            return !value.empty();
        } else if constexpr (std::same_as<T, ValueFunction>) {
            return static_cast<bool>(value);
        } else if constexpr (std::same_as<T, std::vector<uint8_t>>) {
            return !value.empty();
        } else {
            return false;
        }
    }, data_);
}

std::string Value::to_string() const {
    return std::visit([](const auto& value) -> std::string {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::same_as<T, std::monostate>) {
            return "nil";
        } else if constexpr (std::same_as<T, bool>) {
            return value ? "true" : "false";
        } else if constexpr (std::same_as<T, int64_t>) {
            return std::to_string(value);
        } else if constexpr (std::same_as<T, double>) {
            if (std::isnan(value)) return "NaN";
            if (std::isinf(value)) return value > 0 ? "Infinity" : "-Infinity";
            auto str = std::to_string(value);
            if (str.find('.') != std::string::npos) {
                str.erase(str.find_last_not_of('0') + 1, std::string::npos);
                str.erase(str.find_last_not_of('.') + 1, std::string::npos);
            }
            return str;
        } else if constexpr (std::same_as<T, std::string>) {
            return value;
        } else if constexpr (std::same_as<T, ValueArray>) {
            std::ostringstream oss;
            oss << "[";
            for (size_t i = 0; i < value.size(); ++i) {
                if (i > 0) oss << ", ";
                oss << value[i].to_string();
            }
            oss << "]";
            return oss.str();
        } else if constexpr (std::same_as<T, ValueMap>) {
            std::ostringstream oss;
            oss << "{";
            bool first = true;
            for (const auto& [key, val] : value) {
                if (!first) oss << ", ";
                first = false;
                oss << "\"" << key << "\": " << val.to_string();
            }
            oss << "}";
            return oss.str();
        } else if constexpr (std::same_as<T, ValueFunction>) {
            return "[Function]";
        } else if constexpr (std::same_as<T, std::vector<uint8_t>>) {
            std::ostringstream oss;
            oss << "0x" << std::hex << std::uppercase;
            for (auto byte : value) {
                oss << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
            }
            return oss.str();
        } else {
            return "[Unknown]";
        }
    }, data_);
}

bool Value::equals(const Value& other) const noexcept {
    if (type_ != other.type_) {
        return false;
    }
    
    return std::visit([](const auto& lhs, const auto& rhs) -> bool {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, U>) {
            if constexpr (std::same_as<T, double>) {
                if (std::isnan(lhs) && std::isnan(rhs)) return true;
                if (std::isnan(lhs) || std::isnan(rhs)) return false;
                return std::abs(lhs - rhs) < std::numeric_limits<double>::epsilon();
            } else if constexpr (std::same_as<T, ValueArray>) {
                if (lhs.size() != rhs.size()) return false;
                return std::equal(std::execution::par_unseq, lhs.begin(), lhs.end(), rhs.begin(),
                    [](const Value& a, const Value& b) { return a.equals(b); });
            } else if constexpr (std::same_as<T, ValueMap>) {
                if (lhs.size() != rhs.size()) return false;
                return std::all_of(std::execution::par_unseq, lhs.begin(), lhs.end(),
                    [&rhs](const auto& pair) {
                        auto it = rhs.find(pair.first);
                        return it != rhs.end() && pair.second.equals(it->second);
                    });
            } else if constexpr (std::same_as<T, ValueFunction>) {
                return false;
            } else {
                return lhs == rhs;
            }
        } else {
            return false;
        }
    }, data_, other.data_);
}

namespace {

template<typename T, typename U>
constexpr auto safe_add(T a, U b) noexcept {
    if constexpr (std::is_integral_v<T> && std::is_integral_v<U>) {
        using Result = std::common_type_t<T, U>;
        if constexpr (std::is_signed_v<Result>) {
            if (b > 0 && a > std::numeric_limits<Result>::max() - b) {
                return std::numeric_limits<Result>::max();
            }
            if (b < 0 && a < std::numeric_limits<Result>::min() - b) {
                return std::numeric_limits<Result>::min();
            }
        }
        return static_cast<Result>(a + b);
    } else {
        return a + b;
    }
}

template<typename T, typename U>
constexpr auto safe_sub(T a, U b) noexcept {
    if constexpr (std::is_integral_v<T> && std::is_integral_v<U>) {
        using Result = std::common_type_t<T, U>;
        if constexpr (std::is_signed_v<Result>) {
            if (b < 0 && a > std::numeric_limits<Result>::max() + b) {
                return std::numeric_limits<Result>::max();
            }
            if (b > 0 && a < std::numeric_limits<Result>::min() + b) {
                return std::numeric_limits<Result>::min();
            }
        }
        return static_cast<Result>(a - b);
    } else {
        return a - b;
    }
}

template<typename T, typename U>
constexpr auto safe_mul(T a, U b) noexcept {
    if constexpr (std::is_integral_v<T> && std::is_integral_v<U>) {
        using Result = std::common_type_t<T, U>;
        if (a == 0 || b == 0) return Result{0};
        if constexpr (std::is_signed_v<Result>) {
            if (a > 0 && b > 0 && a > std::numeric_limits<Result>::max() / b) {
                return std::numeric_limits<Result>::max();
            }
            if (a < 0 && b < 0 && a < std::numeric_limits<Result>::max() / b) {
                return std::numeric_limits<Result>::max();
            }
            if (a > 0 && b < 0 && b < std::numeric_limits<Result>::min() / a) {
                return std::numeric_limits<Result>::min();
            }
            if (a < 0 && b > 0 && a < std::numeric_limits<Result>::min() / b) {
                return std::numeric_limits<Result>::min();
            }
        }
        return static_cast<Result>(a * b);
    } else {
        return a * b;
    }
}

template<typename T, typename U>
constexpr auto safe_div(T a, U b) {
    if (b == 0) {
        if constexpr (std::is_floating_point_v<T> || std::is_floating_point_v<U>) {
            return a > 0 ? std::numeric_limits<double>::infinity() : 
                   a < 0 ? -std::numeric_limits<double>::infinity() : 
                   std::numeric_limits<double>::quiet_NaN();
        } else {
            throw std::runtime_error("Division by zero");
        }
    }
    return a / b;
}

template<typename T>
constexpr bool is_power_of_two(T n) noexcept {
    return n > 0 && (n & (n - 1)) == 0;
}

template<typename T>
constexpr T next_power_of_two(T n) noexcept {
    if (n <= 1) return 1;
    return T{1} << (std::bit_width(n - 1));
}

template<typename T>
constexpr T log2_floor(T n) noexcept {
    return std::bit_width(n) - 1;
}

template<typename T>
constexpr T popcount(T n) noexcept {
    return std::popcount(n);
}

void vectorized_add_arrays(const ValueArray& a, const ValueArray& b, ValueArray& result) {
    const size_t size = std::min(a.size(), b.size());
    result.resize(size);
    
    constexpr size_t simd_size = 4;
    const size_t simd_end = (size / simd_size) * simd_size;
    
    size_t i = 0;
    for (; i < simd_end; i += simd_size) {
        __m256d va = _mm256_setr_pd(
            a[i].is<ValueType::FLOAT>() ? a[i].get<ValueType::FLOAT>() : 
            a[i].is<ValueType::INTEGER>() ? static_cast<double>(a[i].get<ValueType::INTEGER>()) : 0.0,
            a[i+1].is<ValueType::FLOAT>() ? a[i+1].get<ValueType::FLOAT>() : 
            a[i+1].is<ValueType::INTEGER>() ? static_cast<double>(a[i+1].get<ValueType::INTEGER>()) : 0.0,
            a[i+2].is<ValueType::FLOAT>() ? a[i+2].get<ValueType::FLOAT>() : 
            a[i+2].is<ValueType::INTEGER>() ? static_cast<double>(a[i+2].get<ValueType::INTEGER>()) : 0.0,
            a[i+3].is<ValueType::FLOAT>() ? a[i+3].get<ValueType::FLOAT>() : 
            a[i+3].is<ValueType::INTEGER>() ? static_cast<double>(a[i+3].get<ValueType::INTEGER>()) : 0.0
        );
        
        __m256d vb = _mm256_setr_pd(
            b[i].is<ValueType::FLOAT>() ? b[i].get<ValueType::FLOAT>() : 
            b[i].is<ValueType::INTEGER>() ? static_cast<double>(b[i].get<ValueType::INTEGER>()) : 0.0,
            b[i+1].is<ValueType::FLOAT>() ? b[i+1].get<ValueType::FLOAT>() : 
            b[i+1].is<ValueType::INTEGER>() ? static_cast<double>(b[i+1].get<ValueType::INTEGER>()) : 0.0,
            b[i+2].is<ValueType::FLOAT>() ? b[i+2].get<ValueType::FLOAT>() : 
            b[i+2].is<ValueType::INTEGER>() ? static_cast<double>(b[i+2].get<ValueType::INTEGER>()) : 0.0,
            b[i+3].is<ValueType::FLOAT>() ? b[i+3].get<ValueType::FLOAT>() : 
            b[i+3].is<ValueType::INTEGER>() ? static_cast<double>(b[i+3].get<ValueType::INTEGER>()) : 0.0
        );
        
        __m256d vresult = _mm256_add_pd(va, vb);
        
        alignas(32) double temp[4];
        _mm256_store_pd(temp, vresult);
        
        for (size_t j = 0; j < simd_size; ++j) {
            result[i + j] = Value(temp[j]);
        }
    }
    
    for (; i < size; ++i) {
        result[i] = a[i] + b[i];
    }
}

void vectorized_bitwise_operation(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b, 
                                 std::vector<uint8_t>& result, int operation) {
    const size_t size = std::min(a.size(), b.size());
    result.resize(size);
    
    constexpr size_t simd_size = 32;
    const size_t simd_end = (size / simd_size) * simd_size;
    
    size_t i = 0;
    for (; i < simd_end; i += simd_size) {
        __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&a[i]));
        __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&b[i]));
        __m256i vresult;
        
        switch (operation) {
            case 0: vresult = _mm256_and_si256(va, vb); break;
            case 1: vresult = _mm256_or_si256(va, vb); break;
            case 2: vresult = _mm256_xor_si256(va, vb); break;
            default: vresult = _mm256_setzero_si256(); break;
        }
        
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&result[i]), vresult);
    }
    
    for (; i < size; ++i) {
        switch (operation) {
            case 0: result[i] = a[i] & b[i]; break;
            case 1: result[i] = a[i] | b[i]; break;
            case 2: result[i] = a[i] ^ b[i]; break;
            default: result[i] = 0; break;
        }
    }
}

template<typename T>
Value fast_power(T base, T exp) {
    if constexpr (std::is_floating_point_v<T>) {
        return Value(std::pow(base, exp));
    } else {
        if (exp == 0) return Value(static_cast<T>(1));
        if (exp == 1) return Value(base);
        if (exp < 0) return Value(1.0 / std::pow(static_cast<double>(base), -exp));
        
        T result = 1;
        T current_power = base;
        T current_exp = exp;
        
        while (current_exp > 0) {
            if (current_exp & 1) {
                result = safe_mul(result, current_power);
            }
            current_power = safe_mul(current_power, current_power);
            current_exp >>= 1;
        }
        
        return Value(result);
    }
}

std::string format_hex(uint64_t value, bool uppercase = true) {
    std::ostringstream oss;
    oss << "0x" << std::hex;
    if (uppercase) oss << std::uppercase;
    oss << value;
    return oss.str();
}

std::string format_binary(uint64_t value) {
    if (value == 0) return "0b0";
    std::string result = "0b";
    bool leading_zero = true;
    for (int i = 63; i >= 0; --i) {
        bool bit = (value >> i) & 1;
        if (bit || !leading_zero) {
            result += bit ? '1' : '0';
            leading_zero = false;
        }
    }
    return result;
}

Value apply_crypto_hash(const std::vector<uint8_t>& data, const std::string& algorithm) {
    std::hash<std::string> hasher;
    std::string data_str(data.begin(), data.end());
    
    if (algorithm == "md5" || algorithm == "sha1" || algorithm == "sha256") {
        auto hash_value = hasher(data_str + algorithm);
        std::vector<uint8_t> result;
        result.resize(32);
        
        for (size_t i = 0; i < 32; ++i) {
            result[i] = static_cast<uint8_t>((hash_value >> (i * 8)) & 0xFF);
        }
        
        return Value(result);
    }
    
    return Value();
}

Value apply_crypto_encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::string& algorithm) {
    if (algorithm == "xor") {
        std::vector<uint8_t> result;
        result.resize(data.size());
        
        for (size_t i = 0; i < data.size(); ++i) {
            result[i] = data[i] ^ key[i % key.size()];
        }
        
        return Value(result);
    }
    
    if (algorithm == "aes" || algorithm == "des") {
        std::vector<uint8_t> result = data;
        
        std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        
        for (size_t i = 0; i < result.size(); ++i) {
            result[i] ^= key[i % key.size()] ^ dist(rng);
        }
        
        return Value(result);
    }
    
    return Value();
}

Value memory_allocate(size_t size) {
    std::vector<uint8_t> memory(size, 0);
    return Value(memory);
}

Value memory_read(const std::vector<uint8_t>& memory, size_t offset, size_t size) {
    if (offset + size > memory.size()) {
        throw std::runtime_error("Memory access out of bounds");
    }
    
    std::vector<uint8_t> result(memory.begin() + offset, memory.begin() + offset + size);
    return Value(result);
}

Value memory_write(std::vector<uint8_t>& memory, size_t offset, const std::vector<uint8_t>& data) {
    if (offset + data.size() > memory.size()) {
        throw std::runtime_error("Memory write out of bounds");
    }
    
    std::copy(data.begin(), data.end(), memory.begin() + offset);
    return Value(true);
}

Value syscall_execute(const std::string& call, const ValueArray& args) {
    if (call == "getpid") {
        return Value(static_cast<int64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id())));
    }
    
    if (call == "time") {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        return Value(static_cast<int64_t>(time_t));
    }
    
    if (call == "sleep") {
        if (!args.empty() && args[0].is<ValueType::INTEGER>()) {
            auto ms = args[0].get<ValueType::INTEGER>();
            std::this_thread::sleep_for(std::chrono::milliseconds(ms));
            return Value(true);
        }
    }
    
    if (call == "random") {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int64_t> dis(0, std::numeric_limits<int64_t>::max());
        return Value(dis(gen));
    }
    
    return Value();
}

Value exploit_buffer_overflow(const std::vector<uint8_t>& buffer, size_t target_size) {
    if (buffer.size() <= target_size) {
        return Value(false);
    }
    
    std::vector<uint8_t> overflow_data(buffer.begin() + target_size, buffer.end());
    return Value(overflow_data);
}

Value exploit_format_string(const std::string& format, const ValueArray& args) {
    std::ostringstream oss;
    size_t pos = 0;
    size_t arg_index = 0;
    
    while (pos < format.size()) {
        if (format[pos] == '%' && pos + 1 < format.size()) {
            char specifier = format[pos + 1];
            if (arg_index < args.size()) {
                switch (specifier) {
                    case 'd':
                        if (args[arg_index].is<ValueType::INTEGER>()) {
                            oss << args[arg_index].get<ValueType::INTEGER>();
                        }
                        break;
                    case 'f':
                        if (args[arg_index].is<ValueType::FLOAT>()) {
                            oss << args[arg_index].get<ValueType::FLOAT>();
                        }
                        break;
                    case 's':
                        if (args[arg_index].is<ValueType::STRING>()) {
                            oss << args[arg_index].get<ValueType::STRING>();
                        }
                        break;
                    case 'x':
                        if (args[arg_index].is<ValueType::INTEGER>()) {
                            oss << std::hex << args[arg_index].get<ValueType::INTEGER>();
                        }
                        break;
                    case 'p':
                        oss << "0x" << std::hex << reinterpret_cast<uintptr_t>(&args[arg_index]);
                        break;
                    default:
                        oss << format[pos] << format[pos + 1];
                        break;
                }
                arg_index++;
            }
            pos += 2;
        } else {
            oss << format[pos];
            pos++;
        }
    }
    
    return Value(oss.str());
}

Value exploit_race_condition(const ValueFunction& func1, const ValueFunction& func2) {
    std::vector<Value> results;
    
    auto future1 = std::async(std::launch::async, [&func1]() {
        return func1(std::span<const Value>{});
    });
    
    auto future2 = std::async(std::launch::async, [&func2]() {
        return func2(std::span<const Value>{});
    });
    
    results.push_back(future1.get());
    results.push_back(future2.get());
    
    return Value(results);
}

std::atomic<int64_t> global_counter{0};

Value exploit_integer_overflow(int64_t value, int64_t increment) {
    int64_t result = value;
    for (int i = 0; i < increment; ++i) {
        if (result == std::numeric_limits<int64_t>::max()) {
            result = std::numeric_limits<int64_t>::min();
        } else {
            result++;
        }
    }
    return Value(result);
}

Value shell_execute(const std::string& command) {
    std::hash<std::string> hasher;
    auto hash_value = hasher(command);
    
    if (command.find("ls") != std::string::npos) {
        return Value(std::string("file1.txt file2.txt directory1/"));
    }
    
    if (command.find("pwd") != std::string::npos) {
        return Value(std::string("/home/user/yalok"));
    }
    
    if (command.find("whoami") != std::string::npos) {
        return Value(std::string("yalokgar"));
    }
    
    if (command.find("ps") != std::string::npos) {
        return Value(std::string("PID  CMD\n1234 yalok\n5678 bash"));
    }
    
    return Value(std::string("Command executed: ") + command);
}

Value network_scan(const std::string& target, const std::string& port_range) {
    std::vector<Value> open_ports;
    
    std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<int> dist(1, 65535);
    
    for (int i = 0; i < 10; ++i) {
        int port = dist(rng);
        if (port % 7 == 0) {
            ValueMap port_info;
            port_info["port"] = Value(static_cast<int64_t>(port));
            port_info["status"] = Value(std::string("open"));
            port_info["service"] = Value(std::string("unknown"));
            open_ports.push_back(Value(port_info));
        }
    }
    
    return Value(open_ports);
}

Value payload_generate(const std::string& type, const ValueMap& options) {
    if (type == "shellcode") {
        std::vector<uint8_t> shellcode = {
            0x48, 0x31, 0xc0, 0x48, 0x31, 0xdb, 0x48, 0x31, 0xc9, 0x48, 0x31, 0xd2,
            0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x53, 0x48,
            0x89, 0xe7, 0x48, 0x31, 0xc0, 0xb0, 0x3b, 0x0f, 0x05
        };
        return Value(shellcode);
    }
    
    if (type == "rop_chain") {
        std::vector<uint8_t> rop_chain;
        std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        
        for (int i = 0; i < 64; ++i) {
            rop_chain.push_back(dist(rng));
        }
        
        return Value(rop_chain);
    }
    
    if (type == "nop_sled") {
        std::vector<uint8_t> nop_sled(1024, 0x90);
        return Value(nop_sled);
    }
    
    return Value();
}

}

Value Value::operator+(const Value& other) const {
    if (type_ == ValueType::ARRAY && other.type_ == ValueType::ARRAY) {
        const auto& a = get<ValueType::ARRAY>();
        const auto& b = other.get<ValueType::ARRAY>();
        ValueArray result;
        vectorized_add_arrays(a, b, result);
        return Value(result);
    }
    
    if (type_ == ValueType::BINARY && other.type_ == ValueType::BINARY) {
        const auto& a = get<ValueType::BINARY>();
        const auto& b = other.get<ValueType::BINARY>();
        std::vector<uint8_t> result;
        result.reserve(a.size() + b.size());
        result.insert(result.end(), a.begin(), a.end());
        result.insert(result.end(), b.begin(), b.end());
        return Value(result);
    }
    
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, int64_t> && std::same_as<U, int64_t>) {
            return Value(safe_add(lhs, rhs));
        } else if constexpr (std::same_as<T, double> && std::same_as<U, double>) {
            return Value(lhs + rhs);
        } else if constexpr (std::same_as<T, int64_t> && std::same_as<U, double>) {
            return Value(static_cast<double>(lhs) + rhs);
        } else if constexpr (std::same_as<T, double> && std::same_as<U, int64_t>) {
            return Value(lhs + static_cast<double>(rhs));
        } else if constexpr (std::same_as<T, std::string> && std::same_as<U, std::string>) {
            return Value(lhs + rhs);
        } else if constexpr (std::same_as<T, std::string>) {
            return Value(lhs + Value(rhs).to_string());
        } else if constexpr (std::same_as<U, std::string>) {
            return Value(Value(lhs).to_string() + rhs);
        } else {
            throw std::runtime_error("Cannot add these types");
        }
    }, data_, other.data_);
}

Value Value::operator-(const Value& other) const {
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, int64_t> && std::same_as<U, int64_t>) {
            return Value(safe_sub(lhs, rhs));
        } else if constexpr (std::same_as<T, double> && std::same_as<U, double>) {
            return Value(lhs - rhs);
        } else if constexpr (std::same_as<T, int64_t> && std::same_as<U, double>) {
            return Value(static_cast<double>(lhs) - rhs);
        } else if constexpr (std::same_as<T, double> && std::same_as<U, int64_t>) {
            return Value(lhs - static_cast<double>(rhs));
        } else {
            throw std::runtime_error("Cannot subtract these types");
        }
    }, data_, other.data_);
}

Value Value::operator*(const Value& other) const {
    if (type_ == ValueType::STRING && other.type_ == ValueType::INTEGER) {
        const auto& str = get<ValueType::STRING>();
        auto count = other.get<ValueType::INTEGER>();
        if (count < 0) count = 0;
        if (count > 10000) count = 10000;
        
        std::string result;
        result.reserve(str.size() * count);
        for (int64_t i = 0; i < count; ++i) {
            result += str;
        }
        return Value(result);
    }
    
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, int64_t> && std::same_as<U, int64_t>) {
            return Value(safe_mul(lhs, rhs));
        } else if constexpr (std::same_as<T, double> && std::same_as<U, double>) {
            return Value(lhs * rhs);
        } else if constexpr (std::same_as<T, int64_t> && std::same_as<U, double>) {
            return Value(static_cast<double>(lhs) * rhs);
        } else if constexpr (std::same_as<T, double> && std::same_as<U, int64_t>) {
            return Value(lhs * static_cast<double>(rhs));
        } else {
            throw std::runtime_error("Cannot multiply these types");
        }
    }, data_, other.data_);
}

Value Value::operator/(const Value& other) const {
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, int64_t> && std::same_as<U, int64_t>) {
            if (rhs == 0) {
                return Value(std::numeric_limits<double>::infinity());
            }
            if (lhs % rhs == 0) {
                return Value(lhs / rhs);
            } else {
                return Value(static_cast<double>(lhs) / static_cast<double>(rhs));
            }
        } else if constexpr (std::same_as<T, double> && std::same_as<U, double>) {
            return Value(safe_div(lhs, rhs));
        } else if constexpr (std::same_as<T, int64_t> && std::same_as<U, double>) {
            return Value(safe_div(static_cast<double>(lhs), rhs));
        } else if constexpr (std::same_as<T, double> && std::same_as<U, int64_t>) {
            return Value(safe_div(lhs, static_cast<double>(rhs)));
        } else {
            throw std::runtime_error("Cannot divide these types");
        }
    }, data_, other.data_);
}

Value Value::operator%(const Value& other) const {
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, int64_t> && std::same_as<U, int64_t>) {
            if (rhs == 0) {
                throw std::runtime_error("Division by zero in modulo operation");
            }
            return Value(lhs % rhs);
        } else if constexpr (std::same_as<T, double> && std::same_as<U, double>) {
            return Value(std::fmod(lhs, rhs));
        } else if constexpr (std::same_as<T, int64_t> && std::same_as<U, double>) {
            return Value(std::fmod(static_cast<double>(lhs), rhs));
        } else if constexpr (std::same_as<T, double> && std::same_as<U, int64_t>) {
            return Value(std::fmod(lhs, static_cast<double>(rhs)));
        } else {
            throw std::runtime_error("Cannot compute modulo for these types");
        }
    }, data_, other.data_);
}

Value Value::operator&(const Value& other) const {
    if (type_ == ValueType::BINARY && other.type_ == ValueType::BINARY) {
        const auto& a = get<ValueType::BINARY>();
        const auto& b = other.get<ValueType::BINARY>();
        std::vector<uint8_t> result;
        vectorized_bitwise_operation(a, b, result, 0);
        return Value(result);
    }
    
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, int64_t> && std::same_as<U, int64_t>) {
            return Value(lhs & rhs);
        } else if constexpr (std::same_as<T, bool> && std::same_as<U, bool>) {
            return Value(lhs && rhs);
        } else {
            throw std::runtime_error("Cannot perform bitwise AND on these types");
        }
    }, data_, other.data_);
}

Value Value::operator|(const Value& other) const {
    if (type_ == ValueType::BINARY && other.type_ == ValueType::BINARY) {
        const auto& a = get<ValueType::BINARY>();
        const auto& b = other.get<ValueType::BINARY>();
        std::vector<uint8_t> result;
        vectorized_bitwise_operation(a, b, result, 1);
        return Value(result);
    }
    
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, int64_t> && std::same_as<U, int64_t>) {
            return Value(lhs | rhs);
        } else if constexpr (std::same_as<T, bool> && std::same_as<U, bool>) {
            return Value(lhs || rhs);
        } else {
            throw std::runtime_error("Cannot perform bitwise OR on these types");
        }
    }, data_, other.data_);
}

Value Value::operator^(const Value& other) const {
    if (type_ == ValueType::BINARY && other.type_ == ValueType::BINARY) {
        const auto& a = get<ValueType::BINARY>();
        const auto& b = other.get<ValueType::BINARY>();
        std::vector<uint8_t> result;
        vectorized_bitwise_operation(a, b, result, 2);
        return Value(result);
    }
    
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, int64_t> && std::same_as<U, int64_t>) {
            return Value(lhs ^ rhs);
        } else if constexpr (std::same_as<T, bool> && std::same_as<U, bool>) {
            return Value(lhs != rhs);
        } else {
            throw std::runtime_error("Cannot perform bitwise XOR on these types");
        }
    }, data_, other.data_);
}

Value Value::operator~() const {
    return std::visit([](const auto& value) -> Value {
        using T = std::decay_t<decltype(value)>;
        
        if constexpr (std::same_as<T, int64_t>) {
            return Value(~value);
        } else if constexpr (std::same_as<T, bool>) {
            return Value(!value);
        } else if constexpr (std::same_as<T, std::vector<uint8_t>>) {
            std::vector<uint8_t> result;
            result.reserve(value.size());
            std::transform(value.begin(), value.end(), std::back_inserter(result),
                [](uint8_t b) { return ~b; });
            return Value(result);
        } else {
            throw std::runtime_error("Cannot perform bitwise NOT on this type");
        }
    }, data_);
}

Value Value::operator<<(const Value& other) const {
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, int64_t> && std::same_as<U, int64_t>) {
            if (rhs < 0 || rhs >= 64) {
                throw std::runtime_error("Shift amount out of range");
            }
            return Value(lhs << rhs);
        } else if constexpr (std::same_as<T, std::vector<uint8_t>> && std::same_as<U, int64_t>) {
            if (rhs < 0 || rhs > 8) {
                throw std::runtime_error("Bit shift amount out of range");
            }
            std::vector<uint8_t> result;
            result.reserve(lhs.size());
            std::transform(lhs.begin(), lhs.end(), std::back_inserter(result),
                [rhs](uint8_t b) { return static_cast<uint8_t>(b << rhs); });
            return Value(result);
        } else {
            throw std::runtime_error("Cannot perform left shift on these types");
        }
    }, data_, other.data_);
}

Value Value::operator>>(const Value& other) const {
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, int64_t> && std::same_as<U, int64_t>) {
            if (rhs < 0 || rhs >= 64) {
                throw std::runtime_error("Shift amount out of range");
            }
            return Value(lhs >> rhs);
        } else if constexpr (std::same_as<T, std::vector<uint8_t>> && std::same_as<U, int64_t>) {
            if (rhs < 0 || rhs > 8) {
                throw std::runtime_error("Bit shift amount out of range");
            }
            std::vector<uint8_t> result;
            result.reserve(lhs.size());
            std::transform(lhs.begin(), lhs.end(), std::back_inserter(result),
                [rhs](uint8_t b) { return static_cast<uint8_t>(b >> rhs); });
            return Value(result);
        } else {
            throw std::runtime_error("Cannot perform right shift on these types");
        }
    }, data_, other.data_);
}

Value Value::operator<(const Value& other) const {
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, U>) {
            if constexpr (std::same_as<T, std::monostate>) {
                return Value(false);
            } else if constexpr (std::same_as<T, ValueFunction>) {
                return Value(false);
            } else if constexpr (std::same_as<T, ValueArray>) {
                return Value(lhs.size() < rhs.size());
            } else if constexpr (std::same_as<T, ValueMap>) {
                return Value(lhs.size() < rhs.size());
            } else {
                return Value(lhs < rhs);
            }
        } else if constexpr ((std::same_as<T, int64_t> && std::same_as<U, double>) ||
                           (std::same_as<T, double> && std::same_as<U, int64_t>)) {
            return Value(static_cast<double>(lhs) < static_cast<double>(rhs));
        } else {
            throw std::runtime_error("Cannot compare these types");
        }
    }, data_, other.data_);
}

Value Value::operator>(const Value& other) const {
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, U>) {
            if constexpr (std::same_as<T, std::monostate>) {
                return Value(false);
            } else if constexpr (std::same_as<T, ValueFunction>) {
                return Value(false);
            } else if constexpr (std::same_as<T, ValueArray>) {
                return Value(lhs.size() > rhs.size());
            } else if constexpr (std::same_as<T, ValueMap>) {
                return Value(lhs.size() > rhs.size());
            } else {
                return Value(lhs > rhs);
            }
        } else if constexpr ((std::same_as<T, int64_t> && std::same_as<U, double>) ||
                           (std::same_as<T, double> && std::same_as<U, int64_t>)) {
            return Value(static_cast<double>(lhs) > static_cast<double>(rhs));
        } else {
            throw std::runtime_error("Cannot compare these types");
        }
    }, data_, other.data_);
}

Value Value::operator<=(const Value& other) const {
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, U>) {
            if constexpr (std::same_as<T, std::monostate>) {
                return Value(true);
            } else if constexpr (std::same_as<T, ValueFunction>) {
                return Value(false);
            } else if constexpr (std::same_as<T, ValueArray>) {
                return Value(lhs.size() <= rhs.size());
            } else if constexpr (std::same_as<T, ValueMap>) {
                return Value(lhs.size() <= rhs.size());
            } else {
                return Value(lhs <= rhs);
            }
        } else if constexpr ((std::same_as<T, int64_t> && std::same_as<U, double>) ||
                           (std::same_as<T, double> && std::same_as<U, int64_t>)) {
            return Value(static_cast<double>(lhs) <= static_cast<double>(rhs));
        } else {
            throw std::runtime_error("Cannot compare these types");
        }
    }, data_, other.data_);
}

Value Value::operator>=(const Value& other) const {
    return std::visit([](const auto& lhs, const auto& rhs) -> Value {
        using T = std::decay_t<decltype(lhs)>;
        using U = std::decay_t<decltype(rhs)>;
        
        if constexpr (std::same_as<T, U>) {
            if constexpr (std::same_as<T, std::monostate>) {
                return Value(true);
            } else if constexpr (std::same_as<T, ValueFunction>) {
                return Value(false);
            } else if constexpr (std::same_as<T, ValueArray>) {
                return Value(lhs.size() >= rhs.size());
            } else if constexpr (std::same_as<T, ValueMap>) {
                return Value(lhs.size() >= rhs.size());
            } else {
                return Value(lhs >= rhs);
            }
        } else if constexpr ((std::same_as<T, int64_t> && std::same_as<U, double>) ||
                           (std::same_as<T, double> && std::same_as<U, int64_t>)) {
            return Value(static_cast<double>(lhs) >= static_cast<double>(rhs));
        } else {
            throw std::runtime_error("Cannot compare these types");
        }
    }, data_, other.data_);
}

Value Value::operator==(const Value& other) const {
    return Value(equals(other));
}

Value Value::operator!=(const Value& other) const {
    return Value(!equals(other));
}

Value Value::operator&&(const Value& other) const {
    if (!is_truthy()) {
        return *this;
    }
    return other;
}

Value Value::operator||(const Value& other) const {
    if (is_truthy()) {
        return *this;
    }
    return other;
}

Value Value::operator!() const {
    return Value(!is_truthy());
}

Value& Value::operator[](const std::string& key) {
    if (type_ == ValueType::OBJECT) {
        return get<ValueType::OBJECT>()[key];
    }
    throw std::runtime_error("Value is not an object");
}

const Value& Value::operator[](const std::string& key) const {
    if (type_ == ValueType::OBJECT) {
        const auto& obj = get<ValueType::OBJECT>();
        auto it = obj.find(key);
        if (it != obj.end()) {
            return it->second;
        }
    }
    throw std::runtime_error("Key not found or value is not an object");
}

Value& Value::operator[](size_t index) {
    if (type_ == ValueType::ARRAY) {
        auto& arr = get<ValueType::ARRAY>();
        if (index < arr.size()) {
            return arr[index];
        }
    }
    throw std::runtime_error("Index out of bounds or value is not an array");
}

const Value& Value::operator[](size_t index) const {
    if (type_ == ValueType::ARRAY) {
        const auto& arr = get<ValueType::ARRAY>();
        if (index < arr.size()) {
            return arr[index];
        }
    }
    throw std::runtime_error("Index out of bounds or value is not an array");
}

Value::Iterator Value::begin() const {
    return Iterator(this, 0);
}

Value::Iterator Value::end() const {
    return Iterator(this, size());
}

size_t Value::size() const {
    return std::visit([](const auto& value) -> size_t {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::same_as<T, std::string>) {
            return value.size();
        } else if constexpr (std::same_as<T, ValueArray>) {
            return value.size();
        } else if constexpr (std::same_as<T, ValueMap>) {
            return value.size();
        } else if constexpr (std::same_as<T, std::vector<uint8_t>>) {
            return value.size();
        } else {
            return 0;
        }
    }, data_);
}

bool Value::empty() const {
    return size() == 0;
}

std::optional<Value> Value::try_get(const std::string& key) const {
    if (type_ == ValueType::OBJECT) {
        const auto& obj = get<ValueType::OBJECT>();
        auto it = obj.find(key);
        if (it != obj.end()) {
            return it->second;
        }
    }
    return std::nullopt;
}

std::optional<Value> Value::try_get(size_t index) const {
    if (type_ == ValueType::ARRAY) {
        const auto& arr = get<ValueType::ARRAY>();
        if (index < arr.size()) {
            return arr[index];
        }
    }
    return std::nullopt;
}

Value Value::deep_copy() const {
    return std::visit([](const auto& value) -> Value {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::same_as<T, ValueArray>) {
            ValueArray result;
            result.reserve(value.size());
            for (const auto& item : value) {
                result.push_back(item.deep_copy());
            }
            return Value(result);
        } else if constexpr (std::same_as<T, ValueMap>) {
            ValueMap result;
            for (const auto& [key, val] : value) {
                result[key] = val.deep_copy();
            }
            return Value(result);
        } else {
            return Value(value);
        }
    }, data_);
}

Value Value::shallow_copy() const {
    return *this;
}

void Value::clear() {
    std::visit([](auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::same_as<T, std::string>) {
            value.clear();
        } else if constexpr (std::same_as<T, ValueArray>) {
            value.clear();
        } else if constexpr (std::same_as<T, ValueMap>) {
            value.clear();
        } else if constexpr (std::same_as<T, std::vector<uint8_t>>) {
            value.clear();
        }
    }, data_);
}

void Value::reserve(size_t capacity) {
    std::visit([capacity](auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::same_as<T, std::string>) {
            value.reserve(capacity);
        } else if constexpr (std::same_as<T, ValueArray>) {
            value.reserve(capacity);
        } else if constexpr (std::same_as<T, std::vector<uint8_t>>) {
            value.reserve(capacity);
        }
    }, data_);
}

void Value::resize(size_t size) {
    std::visit([size](auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::same_as<T, ValueArray>) {
            value.resize(size);
        } else if constexpr (std::same_as<T, std::vector<uint8_t>>) {
            value.resize(size);
        }
    }, data_);
}

void Value::push_back(const Value& value) {
    if (type_ == ValueType::ARRAY) {
        get<ValueType::ARRAY>().push_back(value);
    } else {
        throw std::runtime_error("Value is not an array");
    }
}

void Value::push_back(Value&& value) {
    if (type_ == ValueType::ARRAY) {
        get<ValueType::ARRAY>().push_back(std::move(value));
    } else {
        throw std::runtime_error("Value is not an array");
    }
}

void Value::pop_back() {
    if (type_ == ValueType::ARRAY) {
        auto& arr = get<ValueType::ARRAY>();
        if (!arr.empty()) {
            arr.pop_back();
        }
    } else {
        throw std::runtime_error("Value is not an array");
    }
}

void Value::insert(const std::string& key, const Value& value) {
    if (type_ == ValueType::OBJECT) {
        get<ValueType::OBJECT>()[key] = value;
    } else {
        throw std::runtime_error("Value is not an object");
    }
}

void Value::insert(const std::string& key, Value&& value) {
    if (type_ == ValueType::OBJECT) {
        get<ValueType::OBJECT>()[key] = std::move(value);
    } else {
        throw std::runtime_error("Value is not an object");
    }
}

void Value::erase(const std::string& key) {
    if (type_ == ValueType::OBJECT) {
        get<ValueType::OBJECT>().erase(key);
    } else {
        throw std::runtime_error("Value is not an object");
    }
}

void Value::erase(size_t index) {
    if (type_ == ValueType::ARRAY) {
        auto& arr = get<ValueType::ARRAY>();
        if (index < arr.size()) {
            arr.erase(arr.begin() + index);
        }
    } else {
        throw std::runtime_error("Value is not an array");
    }
}

bool Value::contains(const std::string& key) const {
    if (type_ == ValueType::OBJECT) {
        const auto& obj = get<ValueType::OBJECT>();
        return obj.find(key) != obj.end();
    }
    return false;
}

bool Value::contains(size_t index) const {
    if (type_ == ValueType::ARRAY) {
        return index < get<ValueType::ARRAY>().size();
    }
    return false;
}

Value::Iterator::reference Value::Iterator::operator*() const {
    if (container->type_ == ValueType::ARRAY) {
        return const_cast<Value&>(container->get<ValueType::ARRAY>()[index]);
    } else if (container->type_ == ValueType::OBJECT) {
        auto& obj = const_cast<ValueMap&>(container->get<ValueType::OBJECT>());
        auto it = obj.begin();
        std::advance(it, index);
        return const_cast<Value&>(it->second);
    }
    throw std::runtime_error("Invalid iterator operation");
}

Value::Iterator::pointer Value::Iterator::operator->() const {
    return &operator*();
}

Value::Iterator& Value::Iterator::operator++() {
    ++index;
    return *this;
}

Value::Iterator Value::Iterator::operator++(int) {
    Iterator temp = *this;
    ++index;
    return temp;
}

bool Value::Iterator::operator==(const Iterator& other) const {
    return container == other.container && index == other.index;
}

bool Value::Iterator::operator!=(const Iterator& other) const {
    return !(*this == other);
}

std::size_t ValueHash<Value>::operator()(const Value& value) const {
    return std::visit([](const auto& val) -> std::size_t {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::same_as<T, std::monostate>) {
            return 0;
        } else if constexpr (std::same_as<T, ValueFunction>) {
            return std::hash<const void*>{}(val.target<void>());
        } else if constexpr (std::same_as<T, ValueArray>) {
            std::size_t hash = 0;
            for (const auto& item : val) {
                hash ^= ValueHash<Value>{}(item) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
            }
            return hash;
        } else if constexpr (std::same_as<T, ValueMap>) {
            std::size_t hash = 0;
            for (const auto& [key, item] : val) {
                auto key_hash = std::hash<std::string>{}(key);
                auto val_hash = ValueHash<Value>{}(item);
                hash ^= key_hash ^ val_hash + 0x9e3779b9 + (hash << 6) + (hash >> 2);
            }
            return hash;
        } else {
            return std::hash<T>{}(val);
        }
    }, value.data_);
}

}

namespace std {
    template<>
    struct hash<std::vector<uint8_t>> {
        std::size_t operator()(const std::vector<uint8_t>& v) const {
            std::size_t hash = 0;
            for (auto byte : v) {
                hash ^= std::hash<uint8_t>{}(byte) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
            }
            return hash;
        }
    };
} 