#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace yalok {

struct Value {
    enum Type { 
        NIL, INTEGER, FLOAT, STRING, BOOLEAN, ARRAY, OBJECT, FUNCTION
    } type;
    
    union {
        int64_t integer_value;
        double float_value;
        bool boolean_value;
    };
    
    std::string string_value;
    std::vector<Value> array_value;
    std::map<std::string, Value> object_value;
    std::function<Value(const std::vector<Value>&)> function_value;
    
    Value() : type(NIL) {}
    Value(int64_t i) : type(INTEGER), integer_value(i) {}
    Value(double f) : type(FLOAT), float_value(f) {}
    Value(const std::string& s) : type(STRING), string_value(s) {}
    Value(bool b) : type(BOOLEAN), boolean_value(b) {}
    Value(const std::vector<Value>& arr) : type(ARRAY), array_value(arr) {}
    Value(const std::map<std::string, Value>& obj) : type(OBJECT), object_value(obj) {}
    Value(std::function<Value(const std::vector<Value>&)> func) : type(FUNCTION), function_value(func) {}
    
    std::string to_string() const;
    bool is_truthy() const;
    bool equals(const Value& other) const;
    
    Value operator+(const Value& other) const;
    Value operator-(const Value& other) const;
    Value operator*(const Value& other) const;
    Value operator/(const Value& other) const;
    Value operator%(const Value& other) const;
    Value operator<(const Value& other) const;
    Value operator>(const Value& other) const;
    Value operator<=(const Value& other) const;
    Value operator>=(const Value& other) const;
    Value operator==(const Value& other) const;
    Value operator!=(const Value& other) const;
    Value operator&&(const Value& other) const;
    Value operator||(const Value& other) const;
    Value operator!() const;
};

class ValueHelper {
public:
    static Value convert_to_number(const Value& value);
    static Value convert_to_string(const Value& value);
    static Value convert_to_boolean(const Value& value);
    static bool is_numeric(const Value& value);
    static bool can_convert_to_number(const Value& value);
};

} 