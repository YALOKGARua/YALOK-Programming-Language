#pragma once

#include "ast.hpp"
#include "value.hpp"
#include <map>
#include <memory>
#include <stdexcept>

namespace yalok {

class RuntimeError : public std::runtime_error {
public:
    RuntimeError(const std::string& message) : std::runtime_error(message) {}
};

class Environment {
private:
    std::map<std::string, Value> variables;
    std::shared_ptr<Environment> parent;
    
public:
    Environment() : parent(nullptr) {}
    Environment(std::shared_ptr<Environment> parent) : parent(parent) {}
    
    void define(const std::string& name, const Value& value);
    Value get(const std::string& name);
    void assign(const std::string& name, const Value& value);
    bool exists(const std::string& name);
    
    std::shared_ptr<Environment> create_child();
    std::shared_ptr<Environment> get_parent() { return parent; }
};

class Function {
public:
    std::string name;
    std::vector<std::string> parameters;
    std::vector<std::unique_ptr<Statement>> body;
    std::shared_ptr<Environment> closure;
    
    Function(const std::string& name, const std::vector<std::string>& params, 
             std::vector<std::unique_ptr<Statement>> body, std::shared_ptr<Environment> closure);
    
    Value call(const std::vector<Value>& arguments, class Interpreter& interpreter);
};

class NativeFunction {
public:
    std::string name;
    std::function<Value(const std::vector<Value>&)> function;
    
    NativeFunction(const std::string& name, std::function<Value(const std::vector<Value>&)> func)
        : name(name), function(func) {}
    
    Value call(const std::vector<Value>& arguments);
};

class Interpreter {
private:
    std::shared_ptr<Environment> globals;
    std::shared_ptr<Environment> environment;
    std::map<std::string, std::unique_ptr<Function>> functions;
    std::map<std::string, std::unique_ptr<NativeFunction>> native_functions;
    
    bool should_return = false;
    bool should_break = false;
    bool should_continue = false;
    Value return_value;
    
    void define_native_functions();
    Value evaluate_binary_operation(const std::string& operator_, const Value& left, const Value& right);
    Value evaluate_unary_operation(const std::string& operator_, const Value& operand);
    
public:
    Interpreter();
    
    Value evaluate(Expression* expression);
    void execute(Statement* statement);
    void execute_block(const std::vector<std::unique_ptr<Statement>>& statements, 
                      std::shared_ptr<Environment> environment);
    
    void interpret(const std::vector<std::unique_ptr<Statement>>& statements);
    
    void reset();
    std::shared_ptr<Environment> get_global_environment() { return globals; }
    std::shared_ptr<Environment> get_current_environment() { return environment; }
    
    void set_return_flag(bool flag) { should_return = flag; }
    void set_break_flag(bool flag) { should_break = flag; }
    void set_continue_flag(bool flag) { should_continue = flag; }
    void set_return_value(const Value& value) { return_value = value; }
    
    bool get_return_flag() const { return should_return; }
    bool get_break_flag() const { return should_break; }
    bool get_continue_flag() const { return should_continue; }
    Value get_return_value() const { return return_value; }
};

} 