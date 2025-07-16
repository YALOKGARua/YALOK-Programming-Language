#include "yalok/interpreter.hpp"
#include "yalok/ast.hpp"
#include "yalok/value.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <random>
#include <chrono>

namespace yalok {

void Environment::define(const std::string& name, const Value& value) {
    variables[name] = value;
}

Value Environment::get(const std::string& name) {
    auto it = variables.find(name);
    if (it != variables.end()) {
        return it->second;
    }
    
    if (parent) {
        return parent->get(name);
    }
    
    throw RuntimeError("Undefined variable: " + name);
}

void Environment::assign(const std::string& name, const Value& value) {
    auto it = variables.find(name);
    if (it != variables.end()) {
        it->second = value;
        return;
    }
    
    if (parent) {
        parent->assign(name, value);
        return;
    }
    
    throw RuntimeError("Undefined variable: " + name);
}

bool Environment::exists(const std::string& name) {
    if (variables.find(name) != variables.end()) {
        return true;
    }
    
    if (parent) {
        return parent->exists(name);
    }
    
    return false;
}

std::shared_ptr<Environment> Environment::create_child() {
    return std::make_shared<Environment>(shared_from_this());
}

Function::Function(const std::string& name, const std::vector<std::string>& params, 
                   std::vector<std::unique_ptr<Statement>> body, std::shared_ptr<Environment> closure)
    : name(name), parameters(params), body(std::move(body)), closure(closure) {
}

Value Function::call(const std::vector<Value>& arguments, Interpreter& interpreter) {
    if (arguments.size() != parameters.size()) {
        throw RuntimeError("Function '" + name + "' expects " + std::to_string(parameters.size()) + 
                          " arguments, got " + std::to_string(arguments.size()));
    }
    
    auto function_env = closure->create_child();
    
    for (size_t i = 0; i < parameters.size(); ++i) {
        function_env->define(parameters[i], arguments[i]);
    }
    
    interpreter.execute_block(body, function_env);
    
    if (interpreter.get_return_flag()) {
        Value result = interpreter.get_return_value();
        interpreter.set_return_flag(false);
        return result;
    }
    
    return Value();
}

Value NativeFunction::call(const std::vector<Value>& arguments) {
    return function(arguments);
}

Interpreter::Interpreter() {
    globals = std::make_shared<Environment>();
    environment = globals;
    define_native_functions();
}

void Interpreter::define_native_functions() {
    auto print_func = std::make_unique<NativeFunction>("print", [](const std::vector<Value>& args) -> Value {
        for (size_t i = 0; i < args.size(); ++i) {
            if (i > 0) std::cout << " ";
            std::cout << args[i].to_string();
        }
        std::cout << std::endl;
        return Value();
    });
    
    auto len_func = std::make_unique<NativeFunction>("len", [](const std::vector<Value>& args) -> Value {
        if (args.size() != 1) {
            throw RuntimeError("len() takes exactly 1 argument");
        }
        
        const Value& arg = args[0];
        if (arg.is_string()) {
            return Value(static_cast<int>(arg.get_string().length()));
        } else if (arg.is_array()) {
            return Value(static_cast<int>(arg.get_array().size()));
        } else {
            throw RuntimeError("len() argument must be string or array");
        }
    });
    
    auto str_func = std::make_unique<NativeFunction>("str", [](const std::vector<Value>& args) -> Value {
        if (args.size() != 1) {
            throw RuntimeError("str() takes exactly 1 argument");
        }
        return Value(args[0].to_string());
    });
    
    auto int_func = std::make_unique<NativeFunction>("int", [](const std::vector<Value>& args) -> Value {
        if (args.size() != 1) {
            throw RuntimeError("int() takes exactly 1 argument");
        }
        
        const Value& arg = args[0];
        if (arg.is_number()) {
            return Value(static_cast<int>(arg.get_number()));
        } else if (arg.is_string()) {
            try {
                return Value(std::stoi(arg.get_string()));
            } catch (const std::exception&) {
                throw RuntimeError("Cannot convert string to int: " + arg.get_string());
            }
        } else {
            throw RuntimeError("int() argument must be number or string");
        }
    });
    
    auto float_func = std::make_unique<NativeFunction>("float", [](const std::vector<Value>& args) -> Value {
        if (args.size() != 1) {
            throw RuntimeError("float() takes exactly 1 argument");
        }
        
        const Value& arg = args[0];
        if (arg.is_number()) {
            return arg;
        } else if (arg.is_string()) {
            try {
                return Value(std::stod(arg.get_string()));
            } catch (const std::exception&) {
                throw RuntimeError("Cannot convert string to float: " + arg.get_string());
            }
        } else {
            throw RuntimeError("float() argument must be number or string");
        }
    });
    
    auto type_func = std::make_unique<NativeFunction>("type", [](const std::vector<Value>& args) -> Value {
        if (args.size() != 1) {
            throw RuntimeError("type() takes exactly 1 argument");
        }
        
        const Value& arg = args[0];
        if (arg.is_nil()) {
            return Value("nil");
        } else if (arg.is_boolean()) {
            return Value("boolean");
        } else if (arg.is_number()) {
            return Value("number");
        } else if (arg.is_string()) {
            return Value("string");
        } else if (arg.is_array()) {
            return Value("array");
        } else if (arg.is_object()) {
            return Value("object");
        } else {
            return Value("unknown");
        }
    });
    
    auto push_func = std::make_unique<NativeFunction>("push", [](const std::vector<Value>& args) -> Value {
        if (args.size() != 2) {
            throw RuntimeError("push() takes exactly 2 arguments");
        }
        
        Value arr = args[0];
        if (!arr.is_array()) {
            throw RuntimeError("push() first argument must be array");
        }
        
        auto array = arr.get_array();
        array.push_back(args[1]);
        return Value(array);
    });
    
    auto pop_func = std::make_unique<NativeFunction>("pop", [](const std::vector<Value>& args) -> Value {
        if (args.size() != 1) {
            throw RuntimeError("pop() takes exactly 1 argument");
        }
        
        Value arr = args[0];
        if (!arr.is_array()) {
            throw RuntimeError("pop() argument must be array");
        }
        
        auto array = arr.get_array();
        if (array.empty()) {
            throw RuntimeError("pop() from empty array");
        }
        
        Value result = array.back();
        array.pop_back();
        return result;
    });
    
    auto time_func = std::make_unique<NativeFunction>("time", [](const std::vector<Value>& args) -> Value {
        if (args.size() != 0) {
            throw RuntimeError("time() takes no arguments");
        }
        
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        return Value(static_cast<double>(time_t));
    });
    
    auto rand_func = std::make_unique<NativeFunction>("rand", [](const std::vector<Value>& args) -> Value {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        
        if (args.size() == 0) {
            std::uniform_real_distribution<double> dis(0.0, 1.0);
            return Value(dis(gen));
        } else if (args.size() == 1) {
            if (!args[0].is_number()) {
                throw RuntimeError("rand() argument must be number");
            }
            int max_val = static_cast<int>(args[0].get_number());
            std::uniform_int_distribution<int> dis(0, max_val - 1);
            return Value(dis(gen));
        } else {
            throw RuntimeError("rand() takes 0 or 1 arguments");
        }
    });
    
    native_functions["print"] = std::move(print_func);
    native_functions["len"] = std::move(len_func);
    native_functions["str"] = std::move(str_func);
    native_functions["int"] = std::move(int_func);
    native_functions["float"] = std::move(float_func);
    native_functions["type"] = std::move(type_func);
    native_functions["push"] = std::move(push_func);
    native_functions["pop"] = std::move(pop_func);
    native_functions["time"] = std::move(time_func);
    native_functions["rand"] = std::move(rand_func);
}

Value Interpreter::evaluate_binary_operation(const std::string& operator_, const Value& left, const Value& right) {
    if (operator_ == "+") {
        if (left.is_number() && right.is_number()) {
            return Value(left.get_number() + right.get_number());
        } else if (left.is_string() || right.is_string()) {
            return Value(left.to_string() + right.to_string());
        } else {
            throw RuntimeError("Invalid operands for +");
        }
    } else if (operator_ == "-") {
        if (left.is_number() && right.is_number()) {
            return Value(left.get_number() - right.get_number());
        } else {
            throw RuntimeError("Invalid operands for -");
        }
    } else if (operator_ == "*") {
        if (left.is_number() && right.is_number()) {
            return Value(left.get_number() * right.get_number());
        } else {
            throw RuntimeError("Invalid operands for *");
        }
    } else if (operator_ == "/") {
        if (left.is_number() && right.is_number()) {
            if (right.get_number() == 0) {
                throw RuntimeError("Division by zero");
            }
            return Value(left.get_number() / right.get_number());
        } else {
            throw RuntimeError("Invalid operands for /");
        }
    } else if (operator_ == "%") {
        if (left.is_number() && right.is_number()) {
            if (right.get_number() == 0) {
                throw RuntimeError("Division by zero");
            }
            return Value(std::fmod(left.get_number(), right.get_number()));
        } else {
            throw RuntimeError("Invalid operands for %");
        }
    } else if (operator_ == "==") {
        return Value(left.equals(right));
    } else if (operator_ == "!=") {
        return Value(!left.equals(right));
    } else if (operator_ == "<") {
        if (left.is_number() && right.is_number()) {
            return Value(left.get_number() < right.get_number());
        } else {
            throw RuntimeError("Invalid operands for <");
        }
    } else if (operator_ == "<=") {
        if (left.is_number() && right.is_number()) {
            return Value(left.get_number() <= right.get_number());
        } else {
            throw RuntimeError("Invalid operands for <=");
        }
    } else if (operator_ == ">") {
        if (left.is_number() && right.is_number()) {
            return Value(left.get_number() > right.get_number());
        } else {
            throw RuntimeError("Invalid operands for >");
        }
    } else if (operator_ == ">=") {
        if (left.is_number() && right.is_number()) {
            return Value(left.get_number() >= right.get_number());
        } else {
            throw RuntimeError("Invalid operands for >=");
        }
    } else if (operator_ == "&&") {
        return Value(left.is_truthy() && right.is_truthy());
    } else if (operator_ == "||") {
        return Value(left.is_truthy() || right.is_truthy());
    } else {
        throw RuntimeError("Unknown binary operator: " + operator_);
    }
}

Value Interpreter::evaluate_unary_operation(const std::string& operator_, const Value& operand) {
    if (operator_ == "-") {
        if (operand.is_number()) {
            return Value(-operand.get_number());
        } else {
            throw RuntimeError("Invalid operand for unary -");
        }
    } else if (operator_ == "!") {
        return Value(!operand.is_truthy());
    } else {
        throw RuntimeError("Unknown unary operator: " + operator_);
    }
}

Value Interpreter::evaluate(Expression* expression) {
    if (auto literal = dynamic_cast<LiteralExpression*>(expression)) {
        return literal->value;
    } else if (auto variable = dynamic_cast<VariableExpression*>(expression)) {
        return environment->get(variable->name);
    } else if (auto binary = dynamic_cast<BinaryExpression*>(expression)) {
        Value left = evaluate(binary->left.get());
        Value right = evaluate(binary->right.get());
        return evaluate_binary_operation(binary->operator_, left, right);
    } else if (auto unary = dynamic_cast<UnaryExpression*>(expression)) {
        Value operand = evaluate(unary->operand.get());
        return evaluate_unary_operation(unary->operator_, operand);
    } else if (auto call = dynamic_cast<CallExpression*>(expression)) {
        std::vector<Value> arguments;
        for (const auto& arg : call->arguments) {
            arguments.push_back(evaluate(arg.get()));
        }
        
        auto native_it = native_functions.find(call->name);
        if (native_it != native_functions.end()) {
            return native_it->second->call(arguments);
        }
        
        auto func_it = functions.find(call->name);
        if (func_it != functions.end()) {
            return func_it->second->call(arguments, *this);
        }
        
        throw RuntimeError("Unknown function: " + call->name);
    } else if (auto array = dynamic_cast<ArrayExpression*>(expression)) {
        std::vector<Value> elements;
        for (const auto& element : array->elements) {
            elements.push_back(evaluate(element.get()));
        }
        return Value(elements);
    } else if (auto object = dynamic_cast<ObjectExpression*>(expression)) {
        std::map<std::string, Value> properties;
        for (const auto& prop : object->properties) {
            properties[prop.first] = evaluate(prop.second.get());
        }
        return Value(properties);
    } else if (auto access = dynamic_cast<AccessExpression*>(expression)) {
        Value obj = evaluate(access->object.get());
        
        if (obj.is_array()) {
            if (!access->property->is_number()) {
                throw RuntimeError("Array index must be number");
            }
            int index = static_cast<int>(access->property->get_number());
            const auto& arr = obj.get_array();
            if (index < 0 || index >= static_cast<int>(arr.size())) {
                throw RuntimeError("Array index out of bounds");
            }
            return arr[index];
        } else if (obj.is_object()) {
            if (!access->property->is_string()) {
                throw RuntimeError("Object property must be string");
            }
            const std::string& key = access->property->get_string();
            const auto& obj_map = obj.get_object();
            auto it = obj_map.find(key);
            if (it != obj_map.end()) {
                return it->second;
            } else {
                return Value();
            }
        } else {
            throw RuntimeError("Cannot access property of non-object/array");
        }
    } else {
        throw RuntimeError("Unknown expression type");
    }
}

void Interpreter::execute(Statement* statement) {
    if (should_return || should_break || should_continue) {
        return;
    }
    
    if (auto expr_stmt = dynamic_cast<ExpressionStatement*>(statement)) {
        evaluate(expr_stmt->expression.get());
    } else if (auto var_stmt = dynamic_cast<VariableStatement*>(statement)) {
        Value value;
        if (var_stmt->initializer) {
            value = evaluate(var_stmt->initializer.get());
        }
        environment->define(var_stmt->name, value);
    } else if (auto func_stmt = dynamic_cast<FunctionStatement*>(statement)) {
        auto function = std::make_unique<Function>(func_stmt->name, func_stmt->parameters, 
                                                   std::move(func_stmt->body), environment);
        functions[func_stmt->name] = std::move(function);
    } else if (auto if_stmt = dynamic_cast<IfStatement*>(statement)) {
        Value condition = evaluate(if_stmt->condition.get());
        if (condition.is_truthy()) {
            execute(if_stmt->then_branch.get());
        } else if (if_stmt->else_branch) {
            execute(if_stmt->else_branch.get());
        }
    } else if (auto while_stmt = dynamic_cast<WhileStatement*>(statement)) {
        while (true) {
            Value condition = evaluate(while_stmt->condition.get());
            if (!condition.is_truthy()) {
                break;
            }
            
            execute(while_stmt->body.get());
            
            if (should_return) {
                break;
            }
            
            if (should_break) {
                should_break = false;
                break;
            }
            
            if (should_continue) {
                should_continue = false;
                continue;
            }
        }
    } else if (auto for_stmt = dynamic_cast<ForStatement*>(statement)) {
        auto for_env = environment->create_child();
        auto previous_env = environment;
        environment = for_env;
        
        if (for_stmt->initializer) {
            execute(for_stmt->initializer.get());
        }
        
        while (true) {
            if (for_stmt->condition) {
                Value condition = evaluate(for_stmt->condition.get());
                if (!condition.is_truthy()) {
                    break;
                }
            }
            
            execute(for_stmt->body.get());
            
            if (should_return) {
                break;
            }
            
            if (should_break) {
                should_break = false;
                break;
            }
            
            if (should_continue) {
                should_continue = false;
            }
            
            if (for_stmt->increment) {
                evaluate(for_stmt->increment.get());
            }
        }
        
        environment = previous_env;
    } else if (auto block_stmt = dynamic_cast<BlockStatement*>(statement)) {
        execute_block(block_stmt->statements, environment->create_child());
    } else if (auto return_stmt = dynamic_cast<ReturnStatement*>(statement)) {
        if (return_stmt->value) {
            return_value = evaluate(return_stmt->value.get());
        } else {
            return_value = Value();
        }
        should_return = true;
    } else if (auto break_stmt = dynamic_cast<BreakStatement*>(statement)) {
        should_break = true;
    } else if (auto continue_stmt = dynamic_cast<ContinueStatement*>(statement)) {
        should_continue = true;
    } else {
        throw RuntimeError("Unknown statement type");
    }
}

void Interpreter::execute_block(const std::vector<std::unique_ptr<Statement>>& statements, 
                               std::shared_ptr<Environment> env) {
    auto previous_env = environment;
    environment = env;
    
    for (const auto& stmt : statements) {
        execute(stmt.get());
        if (should_return || should_break || should_continue) {
            break;
        }
    }
    
    environment = previous_env;
}

void Interpreter::interpret(const std::vector<std::unique_ptr<Statement>>& statements) {
    try {
        for (const auto& stmt : statements) {
            execute(stmt.get());
            if (should_return) {
                break;
            }
        }
    } catch (const RuntimeError& e) {
        std::cerr << "\033[31mRuntime Error: " << e.what() << "\033[0m" << std::endl;
        throw;
    }
}

void Interpreter::reset() {
    globals = std::make_shared<Environment>();
    environment = globals;
    functions.clear();
    should_return = false;
    should_break = false;
    should_continue = false;
    return_value = Value();
    define_native_functions();
}

Interpreter::MemoryStats Interpreter::get_memory_stats() const {
    MemoryStats stats;
    stats.total_allocated = 1024 * 1024; 
    stats.total_used = 512 * 1024;      
    stats.available = stats.total_allocated - stats.total_used;
    stats.block_count = 16;
    stats.fragmentation_percent = (stats.available * 100) / stats.total_allocated;
    return stats;
}

} 