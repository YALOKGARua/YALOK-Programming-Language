#pragma once
#include <string>
#include <variant>
#include <vector>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <functional>
#include <sstream>
#include <iomanip>

namespace yalok {

struct Value;
using ValuePtr = std::shared_ptr<Value>;
using NativeFn = std::function<Value(std::vector<Value>&)>;

struct PacketDef {
    std::string name;
    std::vector<std::string> fields;
};

struct PacketInstance {
    std::string name;
    std::unordered_map<std::string, Value> fields;
};

struct Function {
    std::string name;
    std::vector<std::pair<std::string, std::string>> params;
    std::string return_type;
    struct Stmt* body;
    struct Environment* closure;
};

struct Value {
    using Buf = std::vector<uint8_t>;

    std::variant<
        std::monostate,
        int64_t,
        double,
        bool,
        std::string,
        Buf,
        std::shared_ptr<Function>,
        NativeFn,
        std::shared_ptr<PacketInstance>
    > data;

    Value() : data(std::monostate{}) {}
    Value(int64_t v) : data(v) {}
    Value(int v) : data(static_cast<int64_t>(v)) {}
    Value(double v) : data(v) {}
    Value(bool v) : data(v) {}
    Value(const char* v) : data(std::string(v)) {}
    Value(std::string v) : data(std::move(v)) {}
    Value(Buf v) : data(std::move(v)) {}
    Value(std::shared_ptr<Function> v) : data(std::move(v)) {}
    Value(NativeFn v) : data(std::move(v)) {}
    Value(std::shared_ptr<PacketInstance> v) : data(std::move(v)) {}

    bool isNil() const { return std::holds_alternative<std::monostate>(data); }
    bool isInt() const { return std::holds_alternative<int64_t>(data); }
    bool isFloat() const { return std::holds_alternative<double>(data); }
    bool isBool() const { return std::holds_alternative<bool>(data); }
    bool isStr() const { return std::holds_alternative<std::string>(data); }
    bool isBuf() const { return std::holds_alternative<Buf>(data); }
    bool isFunc() const { return std::holds_alternative<std::shared_ptr<Function>>(data); }
    bool isNative() const { return std::holds_alternative<NativeFn>(data); }
    bool isPacket() const { return std::holds_alternative<std::shared_ptr<PacketInstance>>(data); }

    int64_t asInt() const { return std::get<int64_t>(data); }
    double asFloat() const { return std::get<double>(data); }
    bool asBool() const { return std::get<bool>(data); }
    const std::string& asStr() const { return std::get<std::string>(data); }
    std::string& asStr() { return std::get<std::string>(data); }
    const Buf& asBuf() const { return std::get<Buf>(data); }
    Buf& asBuf() { return std::get<Buf>(data); }
    std::shared_ptr<Function> asFunc() const { return std::get<std::shared_ptr<Function>>(data); }
    const NativeFn& asNative() const { return std::get<NativeFn>(data); }
    std::shared_ptr<PacketInstance> asPacket() const { return std::get<std::shared_ptr<PacketInstance>>(data); }

    double toNumber() const {
        if (isInt()) return static_cast<double>(asInt());
        if (isFloat()) return asFloat();
        return 0.0;
    }

    bool truthy() const {
        if (isNil()) return false;
        if (isBool()) return asBool();
        if (isInt()) return asInt() != 0;
        if (isFloat()) return asFloat() != 0.0;
        if (isStr()) return !asStr().empty();
        if (isBuf()) return !asBuf().empty();
        return true;
    }

    std::string typeName() const {
        if (isNil()) return "nil";
        if (isInt()) return "i64";
        if (isFloat()) return "f64";
        if (isBool()) return "bool";
        if (isStr()) return "str";
        if (isBuf()) return "buf";
        if (isFunc()) return "fn";
        if (isNative()) return "fn";
        if (isPacket()) return asPacket()->name;
        return "unknown";
    }

    std::string toString() const {
        if (isNil()) return "nil";
        if (isBool()) return asBool() ? "true" : "false";
        if (isInt()) return std::to_string(asInt());
        if (isFloat()) {
            std::ostringstream ss;
            ss << asFloat();
            return ss.str();
        }
        if (isStr()) return asStr();
        if (isBuf()) {
            std::ostringstream ss;
            ss << "[buf:" << asBuf().size() << "]";
            for (auto b : asBuf()) ss << " " << std::hex << std::setw(2) << std::setfill('0') << (int)b;
            return ss.str();
        }
        if (isFunc()) return "<fn " + asFunc()->name + ">";
        if (isNative()) return "<native fn>";
        if (isPacket()) {
            std::ostringstream ss;
            auto pkt = asPacket();
            ss << pkt->name << " {";
            bool first = true;
            for (auto& [k, v] : pkt->fields) {
                if (!first) ss << ",";
                ss << " " << k << ": " << v.toString();
                first = false;
            }
            ss << " }";
            return ss.str();
        }
        return "?";
    }

    std::string toHex() const {
        if (isInt()) {
            std::ostringstream ss;
            ss << "0x" << std::hex << std::uppercase << asInt();
            return ss.str();
        }
        if (isBuf()) {
            std::ostringstream ss;
            for (size_t i = 0; i < asBuf().size(); ++i) {
                if (i) ss << " ";
                ss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)asBuf()[i];
            }
            return ss.str();
        }
        return toString();
    }
};

}
