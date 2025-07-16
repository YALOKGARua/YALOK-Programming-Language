#include <yalok/value.hpp>
#include <sstream>
#include <cmath>
#include <iomanip>

namespace yalok {

std::string Value::to_string() const {
    switch (type) {
        case NIL: return "nil";
        case INTEGER: return std::to_string(integer_value);
        case FLOAT: return std::to_string(float_value);
        case STRING: return string_value;
        case BOOLEAN: return boolean_value ? "true" : "false";
        case ARRAY: {
            std::stringstream ss;
            ss << "[";
            for (size_t i = 0; i < array_value.size(); i++) {
                if (i > 0) ss << ", ";
                ss << array_value[i].to_string();
            }
            ss << "]";
            return ss.str();
        }
        case OBJECT: {
            std::stringstream ss;
            ss << "{";
            bool first = true;
            for (const auto& pair : object_value) {
                if (!first) ss << ", ";
                ss << pair.first << ": " << pair.second.to_string();
                first = false;
            }
            ss << "}";
            return ss.str();
        }
        case FUNCTION: return "<function>";
        default: return "<unknown>";
    }
}

bool Value::is_truthy() const {
    switch (type) {
        case NIL: return false;
        case INTEGER: return integer_value != 0;
        case FLOAT: return float_value != 0.0;
        case STRING: return !string_value.empty();
        case BOOLEAN: return boolean_value;
        case ARRAY: return !array_value.empty();
        case OBJECT: return !object_value.empty();
        case FUNCTION: return true;
        default: return false;
    }
}

bool Value::equals(const Value& other) const {
    if (type != other.type) return false;
    
    switch (type) {
        case NIL: return true;
        case INTEGER: return integer_value == other.integer_value;
        case FLOAT: return std::abs(float_value - other.float_value) < 1e-9;
        case STRING: return string_value == other.string_value;
        case BOOLEAN: return boolean_value == other.boolean_value;
        case ARRAY: return array_value == other.array_value;
        case OBJECT: return object_value == other.object_value;
        case FUNCTION: return false;
        default: return false;
    }
}

Value Value::operator+(const Value& other) const {
    if (type == STRING || other.type == STRING) {
        return Value(to_string() + other.to_string());
    }
    
    if (type == INTEGER && other.type == INTEGER) {
        return Value(integer_value + other.integer_value);
    }
    
    if (type == FLOAT || other.type == FLOAT) {
        double left = (type == FLOAT) ? float_value : integer_value;
        double right = (other.type == FLOAT) ? other.float_value : other.integer_value;
        return Value(left + right);
    }
    
    if (type == ARRAY && other.type == ARRAY) {
        std::vector<Value> result = array_value;
        result.insert(result.end(), other.array_value.begin(), other.array_value.end());
        return Value(result);
    }
    
    return Value();
}

Value Value::operator-(const Value& other) const {
    if (type == INTEGER && other.type == INTEGER) {
        return Value(integer_value - other.integer_value);
    }
    
    if (type == FLOAT || other.type == FLOAT) {
        double left = (type == FLOAT) ? float_value : integer_value;
        double right = (other.type == FLOAT) ? other.float_value : other.integer_value;
        return Value(left - right);
    }
    
    return Value();
}

Value Value::operator*(const Value& other) const {
    if (type == INTEGER && other.type == INTEGER) {
        return Value(integer_value * other.integer_value);
    }
    
    if (type == FLOAT || other.type == FLOAT) {
        double left = (type == FLOAT) ? float_value : integer_value;
        double right = (other.type == FLOAT) ? other.float_value : other.integer_value;
        return Value(left * right);
    }
    
    if (type == STRING && other.type == INTEGER) {
        std::string result;
        for (int i = 0; i < other.integer_value; i++) {
            result += string_value;
        }
        return Value(result);
    }
    
    return Value();
}

Value Value::operator/(const Value& other) const {
    if (other.type == INTEGER && other.integer_value == 0) {
        return Value();
    }
    
    if (other.type == FLOAT && other.float_value == 0.0) {
        return Value();
    }
    
    if (type == INTEGER && other.type == INTEGER) {
        return Value(integer_value / other.integer_value);
    }
    
    if (type == FLOAT || other.type == FLOAT) {
        double left = (type == FLOAT) ? float_value : integer_value;
        double right = (other.type == FLOAT) ? other.float_value : other.integer_value;
        return Value(left / right);
    }
    
    return Value();
}

Value Value::operator%(const Value& other) const {
    if (type == INTEGER && other.type == INTEGER && other.integer_value != 0) {
        return Value(integer_value % other.integer_value);
    }
    
    if (type == FLOAT || other.type == FLOAT) {
        double left = (type == FLOAT) ? float_value : integer_value;
        double right = (other.type == FLOAT) ? other.float_value : other.integer_value;
        return Value(std::fmod(left, right));
    }
    
    return Value();
}

Value Value::operator<(const Value& other) const {
    if (type == INTEGER && other.type == INTEGER) {
        return Value(integer_value < other.integer_value);
    }
    
    if (type == FLOAT || other.type == FLOAT) {
        double left = (type == FLOAT) ? float_value : integer_value;
        double right = (other.type == FLOAT) ? other.float_value : other.integer_value;
        return Value(left < right);
    }
    
    if (type == STRING && other.type == STRING) {
        return Value(string_value < other.string_value);
    }
    
    return Value(false);
}

Value Value::operator>(const Value& other) const {
    if (type == INTEGER && other.type == INTEGER) {
        return Value(integer_value > other.integer_value);
    }
    
    if (type == FLOAT || other.type == FLOAT) {
        double left = (type == FLOAT) ? float_value : integer_value;
        double right = (other.type == FLOAT) ? other.float_value : other.integer_value;
        return Value(left > right);
    }
    
    if (type == STRING && other.type == STRING) {
        return Value(string_value > other.string_value);
    }
    
    return Value(false);
}

Value Value::operator<=(const Value& other) const {
    Value less = *this < other;
    Value equal = *this == other;
    return Value(less.boolean_value || equal.boolean_value);
}

Value Value::operator>=(const Value& other) const {
    Value greater = *this > other;
    Value equal = *this == other;
    return Value(greater.boolean_value || equal.boolean_value);
}

Value Value::operator==(const Value& other) const {
    return Value(equals(other));
}

Value Value::operator!=(const Value& other) const {
    return Value(!equals(other));
}

Value Value::operator&&(const Value& other) const {
    return Value(is_truthy() && other.is_truthy());
}

Value Value::operator||(const Value& other) const {
    return Value(is_truthy() || other.is_truthy());
}

Value Value::operator!() const {
    return Value(!is_truthy());
}

Value ValueHelper::convert_to_number(const Value& value) {
    switch (value.type) {
        case Value::INTEGER: return value;
        case Value::FLOAT: return value;
        case Value::STRING: {
            try {
                if (value.string_value.find('.') != std::string::npos) {
                    return Value(std::stod(value.string_value));
                } else {
                    return Value(std::stoll(value.string_value));
                }
            } catch (...) {
                return Value();
            }
        }
        case Value::BOOLEAN: return Value(value.boolean_value ? 1 : 0);
        default: return Value();
    }
}

Value ValueHelper::convert_to_string(const Value& value) {
    return Value(value.to_string());
}

Value ValueHelper::convert_to_boolean(const Value& value) {
    return Value(value.is_truthy());
}

bool ValueHelper::is_numeric(const Value& value) {
    return value.type == Value::INTEGER || value.type == Value::FLOAT;
}

bool ValueHelper::can_convert_to_number(const Value& value) {
    if (is_numeric(value)) return true;
    if (value.type == Value::BOOLEAN) return true;
    if (value.type == Value::STRING) {
        try {
            std::stod(value.string_value);
            return true;
        } catch (...) {
            return false;
        }
    }
    return false;
}

} 