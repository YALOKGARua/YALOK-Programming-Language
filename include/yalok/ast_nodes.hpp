#pragma once

#include "ast.hpp"
#include "value.hpp"
#include <string>
#include <vector>
#include <memory>
#include <map>

namespace yalok {

class LiteralExpression : public Expression {
public:
    Value value;
    
    LiteralExpression(const Value& val) : value(val) {}
    
    void accept(ASTVisitor& visitor) override {}
    void accept(ConstASTVisitor& visitor) const override {}
    void accept(MutableASTVisitor& visitor) override {}
    
    std::unique_ptr<ASTNode> clone() const override {
        return std::make_unique<LiteralExpression>(value);
    }
    
    std::string to_string() const override {
        return value.to_string();
    }
    
    std::size_t hash() const override {
        return std::hash<std::string>{}(value.to_string());
    }
    
    bool equals(const ASTNode& other) const override {
        if (auto lit = dynamic_cast<const LiteralExpression*>(&other)) {
            return value.equals(lit->value);
        }
        return false;
    }
    
    std::string serialize() const override {
        return "literal:" + value.to_string();
    }
    
    void deserialize(const std::string& data) override {
    }
    
    std::vector<ASTNode*> get_children() override {
        return {};
    }
    
    std::vector<const ASTNode*> get_children() const override {
        return {};
    }
    
    Value evaluate() const override {
        return value;
    }
    
    bool is_constant() const override {
        return true;
    }
    
    bool is_pure() const override {
        return true;
    }
    
    std::vector<std::string> get_dependencies() const override {
        return {};
    }
    
    void replace_dependency(const std::string& old_name, const std::string& new_name) override {}
    
    std::unique_ptr<Expression> simplify() const override {
        return std::make_unique<LiteralExpression>(value);
    }
    
    std::unique_ptr<Expression> optimize_expression() const override {
        return std::make_unique<LiteralExpression>(value);
    }
    
    bool has_side_effects() const override {
        return false;
    }
    
    std::string get_expression_type() const override {
        return "literal";
    }
    
    int get_precedence() const override {
        return 0;
    }
    
    bool is_left_associative() const override {
        return true;
    }
    
    std::string to_code() const override {
        return value.to_string();
    }
    
    std::vector<Expression*> get_subexpressions() override {
        return {};
    }
    
    std::vector<const Expression*> get_subexpressions() const override {
        return {};
    }
    
    std::unique_ptr<Expression> clone_expression() const override {
        return std::make_unique<LiteralExpression>(value);
    }
    
    std::string get_return_type() const override {
        if (value.is_boolean()) return "bool";
        if (value.is_number()) return "number";
        if (value.is_string()) return "string";
        if (value.is_array()) return "array";
        if (value.is_object()) return "object";
        return "unknown";
    }
    
    bool is_type_compatible(const std::string& type) const override {
        return get_return_type() == type;
    }
    
    std::vector<std::string> get_possible_types() const override {
        return {get_return_type()};
    }
    
    std::string to_javascript() const override { return to_code(); }
    std::string to_python() const override { return to_code(); }
    std::string to_cpp() const override { return to_code(); }
    std::string to_json() const override { return to_code(); }
    
    std::vector<std::string> get_required_imports() const override { return {}; }
    std::vector<std::string> get_required_libraries() const override { return {}; }
    
    double complexity() const override { return 1.0; }
    size_t memory_usage() const override { return sizeof(LiteralExpression); }
    size_t instruction_count() const override { return 1; }
    
    bool is_tail_recursive() const override { return false; }
    bool is_recursive() const override { return false; }
    std::vector<std::string> get_recursive_calls() const override { return {}; }
    
    std::unique_ptr<Expression> inline_expression() const override { return clone_expression(); }
    std::unique_ptr<Expression> flatten_expression() const override { return clone_expression(); }
    std::unique_ptr<Expression> normalize_expression() const override { return clone_expression(); }
    
    std::unordered_map<std::string, int> get_variable_usage() const override { return {}; }
    std::vector<std::string> get_free_variables() const override { return {}; }
    std::vector<std::string> get_bound_variables() const override { return {}; }
    
    bool is_well_formed() const override { return true; }
    std::vector<std::string> get_semantic_errors() const override { return {}; }
    
    std::unique_ptr<Expression> substitute(const std::string& var, const Expression& expr) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> alpha_convert(const std::unordered_map<std::string, std::string>& mapping) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> beta_reduce() const override { return clone_expression(); }
    std::unique_ptr<Expression> eta_convert() const override { return clone_expression(); }
    
    bool is_reducible() const override { return false; }
    std::unique_ptr<Expression> reduce() const override { return clone_expression(); }
    std::unique_ptr<Expression> normalize() const override { return clone_expression(); }
    
    std::string get_canonical_form() const override { return to_string(); }
    std::string get_hash_string() const override { return to_string(); }
    bool structural_equals(const Expression& other) const override {
        if (auto lit = dynamic_cast<const LiteralExpression*>(&other)) {
            return value.equals(lit->value);
        }
        return false;
    }
    
    std::unique_ptr<Expression> differentiate(const std::string& var) const override {
        return std::make_unique<LiteralExpression>(Value(0.0));
    }
    
    std::unique_ptr<Expression> integrate(const std::string& var) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> partial_derivative(const std::string& var) const override {
        return std::make_unique<LiteralExpression>(Value(0.0));
    }
    
    std::unique_ptr<Expression> apply_rules(const std::vector<std::pair<std::string, std::string>>& rules) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> apply_transformations(const std::vector<std::function<std::unique_ptr<Expression>(const Expression&)>>& transforms) const override {
        return clone_expression();
    }
    
    void validate() const override {}
    std::vector<std::string> get_validation_errors() const override { return {}; }
    bool is_valid() const override { return true; }
    
    void optimize() override {}
    
    std::unordered_map<std::string, Value> get_attributes() const override {
        return metadata_.attributes;
    }
    
    void set_attribute(const std::string& name, const Value& value) override {
        metadata_.attributes[name] = value;
    }
    
    std::optional<Value> get_attribute(const std::string& name) const override {
        auto it = metadata_.attributes.find(name);
        return it != metadata_.attributes.end() ? std::optional<Value>(it->second) : std::nullopt;
    }
    
    bool has_attribute(const std::string& name) const override {
        return metadata_.attributes.find(name) != metadata_.attributes.end();
    }
    
    void remove_attribute(const std::string& name) override {
        metadata_.attributes.erase(name);
    }
    
    Position get_position() const override {
        return metadata_.position;
    }
    
    void set_position(const Position& pos) override {
        metadata_.position = pos;
    }
    
    Metadata& get_metadata() override {
        return metadata_;
    }
    
    const Metadata& get_metadata() const override {
        return metadata_;
    }
    
    std::string get_node_type() const override { return "LiteralExpression"; }
    std::string get_node_name() const override { return "literal"; }
    
private:
    mutable Metadata metadata_;
};

class VariableExpression : public Expression {
public:
    std::string name;
    
    VariableExpression(const std::string& n) : name(n) {}
    
    void accept(ASTVisitor& visitor) override {}
    void accept(ConstASTVisitor& visitor) const override {}
    void accept(MutableASTVisitor& visitor) override {}
    
    std::unique_ptr<ASTNode> clone() const override {
        return std::make_unique<VariableExpression>(name);
    }
    
    std::string to_string() const override {
        return name;
    }
    
    std::size_t hash() const override {
        return std::hash<std::string>{}(name);
    }
    
    bool equals(const ASTNode& other) const override {
        if (auto var = dynamic_cast<const VariableExpression*>(&other)) {
            return name == var->name;
        }
        return false;
    }
    
    std::string serialize() const override {
        return "variable:" + name;
    }
    
    void deserialize(const std::string& data) override {}
    
    std::vector<ASTNode*> get_children() override {
        return {};
    }
    
    std::vector<const ASTNode*> get_children() const override {
        return {};
    }
    
    Value evaluate() const override {
        return Value();
    }
    
    bool is_constant() const override {
        return false;
    }
    
    bool is_pure() const override {
        return true;
    }
    
    std::vector<std::string> get_dependencies() const override {
        return {name};
    }
    
    void replace_dependency(const std::string& old_name, const std::string& new_name) override {
        if (name == old_name) {
            name = new_name;
        }
    }
    
    std::unique_ptr<Expression> simplify() const override {
        return std::make_unique<VariableExpression>(name);
    }
    
    std::unique_ptr<Expression> optimize_expression() const override {
        return std::make_unique<VariableExpression>(name);
    }
    
    bool has_side_effects() const override {
        return false;
    }
    
    std::string get_expression_type() const override {
        return "variable";
    }
    
    int get_precedence() const override {
        return 0;
    }
    
    bool is_left_associative() const override {
        return true;
    }
    
    std::string to_code() const override {
        return name;
    }
    
    std::vector<Expression*> get_subexpressions() override {
        return {};
    }
    
    std::vector<const Expression*> get_subexpressions() const override {
        return {};
    }
    
    std::unique_ptr<Expression> clone_expression() const override {
        return std::make_unique<VariableExpression>(name);
    }
    
    std::string get_return_type() const override {
        return "unknown";
    }
    
    bool is_type_compatible(const std::string& type) const override {
        return true;
    }
    
    std::vector<std::string> get_possible_types() const override {
        return {"unknown"};
    }
    
    std::string to_javascript() const override { return name; }
    std::string to_python() const override { return name; }
    std::string to_cpp() const override { return name; }
    std::string to_json() const override { return "\"" + name + "\""; }
    
    std::vector<std::string> get_required_imports() const override { return {}; }
    std::vector<std::string> get_required_libraries() const override { return {}; }
    
    double complexity() const override { return 1.0; }
    size_t memory_usage() const override { return sizeof(VariableExpression); }
    size_t instruction_count() const override { return 1; }
    
    bool is_tail_recursive() const override { return false; }
    bool is_recursive() const override { return false; }
    std::vector<std::string> get_recursive_calls() const override { return {}; }
    
    std::unique_ptr<Expression> inline_expression() const override { return clone_expression(); }
    std::unique_ptr<Expression> flatten_expression() const override { return clone_expression(); }
    std::unique_ptr<Expression> normalize_expression() const override { return clone_expression(); }
    
    std::unordered_map<std::string, int> get_variable_usage() const override {
        return {{name, 1}};
    }
    
    std::vector<std::string> get_free_variables() const override {
        return {name};
    }
    
    std::vector<std::string> get_bound_variables() const override {
        return {};
    }
    
    bool is_well_formed() const override { return !name.empty(); }
    std::vector<std::string> get_semantic_errors() const override {
        return name.empty() ? std::vector<std::string>{"Empty variable name"} : std::vector<std::string>{};
    }
    
    std::unique_ptr<Expression> substitute(const std::string& var, const Expression& expr) const override {
        if (name == var) {
            return expr.clone_expression();
        }
        return clone_expression();
    }
    
    std::unique_ptr<Expression> alpha_convert(const std::unordered_map<std::string, std::string>& mapping) const override {
        auto it = mapping.find(name);
        if (it != mapping.end()) {
            return std::make_unique<VariableExpression>(it->second);
        }
        return clone_expression();
    }
    
    std::unique_ptr<Expression> beta_reduce() const override { return clone_expression(); }
    std::unique_ptr<Expression> eta_convert() const override { return clone_expression(); }
    
    bool is_reducible() const override { return false; }
    std::unique_ptr<Expression> reduce() const override { return clone_expression(); }
    std::unique_ptr<Expression> normalize() const override { return clone_expression(); }
    
    std::string get_canonical_form() const override { return name; }
    std::string get_hash_string() const override { return name; }
    bool structural_equals(const Expression& other) const override {
        if (auto var = dynamic_cast<const VariableExpression*>(&other)) {
            return name == var->name;
        }
        return false;
    }
    
    std::unique_ptr<Expression> differentiate(const std::string& var) const override {
        if (name == var) {
            return std::make_unique<LiteralExpression>(Value(1.0));
        }
        return std::make_unique<LiteralExpression>(Value(0.0));
    }
    
    std::unique_ptr<Expression> integrate(const std::string& var) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> partial_derivative(const std::string& var) const override {
        return differentiate(var);
    }
    
    std::unique_ptr<Expression> apply_rules(const std::vector<std::pair<std::string, std::string>>& rules) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> apply_transformations(const std::vector<std::function<std::unique_ptr<Expression>(const Expression&)>>& transforms) const override {
        return clone_expression();
    }
    
    void validate() const override {}
    std::vector<std::string> get_validation_errors() const override { return {}; }
    bool is_valid() const override { return !name.empty(); }
    
    void optimize() override {}
    
    std::unordered_map<std::string, Value> get_attributes() const override {
        return metadata_.attributes;
    }
    
    void set_attribute(const std::string& name, const Value& value) override {
        metadata_.attributes[name] = value;
    }
    
    std::optional<Value> get_attribute(const std::string& name) const override {
        auto it = metadata_.attributes.find(name);
        return it != metadata_.attributes.end() ? std::optional<Value>(it->second) : std::nullopt;
    }
    
    bool has_attribute(const std::string& name) const override {
        return metadata_.attributes.find(name) != metadata_.attributes.end();
    }
    
    void remove_attribute(const std::string& name) override {
        metadata_.attributes.erase(name);
    }
    
    Position get_position() const override {
        return metadata_.position;
    }
    
    void set_position(const Position& pos) override {
        metadata_.position = pos;
    }
    
    Metadata& get_metadata() override {
        return metadata_;
    }
    
    const Metadata& get_metadata() const override {
        return metadata_;
    }
    
    std::string get_node_type() const override { return "VariableExpression"; }
    std::string get_node_name() const override { return "variable"; }
    
private:
    mutable Metadata metadata_;
};

class BinaryExpression : public Expression {
public:
    std::unique_ptr<Expression> left;
    std::string operator_;
    std::unique_ptr<Expression> right;
    
    BinaryExpression(std::unique_ptr<Expression> l, const std::string& op, std::unique_ptr<Expression> r)
        : left(std::move(l)), operator_(op), right(std::move(r)) {}
    
    void accept(ASTVisitor& visitor) override {}
    void accept(ConstASTVisitor& visitor) const override {}
    void accept(MutableASTVisitor& visitor) override {}
    
    std::unique_ptr<ASTNode> clone() const override {
        return std::make_unique<BinaryExpression>(left->clone_expression(), operator_, right->clone_expression());
    }
    
    std::string to_string() const override {
        return "(" + left->to_string() + " " + operator_ + " " + right->to_string() + ")";
    }
    
    std::size_t hash() const override {
        return std::hash<std::string>{}(to_string());
    }
    
    bool equals(const ASTNode& other) const override {
        if (auto bin = dynamic_cast<const BinaryExpression*>(&other)) {
            return operator_ == bin->operator_ && 
                   left->equals(*bin->left) && 
                   right->equals(*bin->right);
        }
        return false;
    }
    
    std::string serialize() const override {
        return "binary:" + operator_ + ":" + left->serialize() + ":" + right->serialize();
    }
    
    void deserialize(const std::string& data) override {}
    
    std::vector<ASTNode*> get_children() override {
        return {left.get(), right.get()};
    }
    
    std::vector<const ASTNode*> get_children() const override {
        return {left.get(), right.get()};
    }
    
    Value evaluate() const override {
        return Value();
    }
    
    bool is_constant() const override {
        return left->is_constant() && right->is_constant();
    }
    
    bool is_pure() const override {
        return left->is_pure() && right->is_pure();
    }
    
    std::vector<std::string> get_dependencies() const override {
        auto left_deps = left->get_dependencies();
        auto right_deps = right->get_dependencies();
        left_deps.insert(left_deps.end(), right_deps.begin(), right_deps.end());
        return left_deps;
    }
    
    void replace_dependency(const std::string& old_name, const std::string& new_name) override {
        left->replace_dependency(old_name, new_name);
        right->replace_dependency(old_name, new_name);
    }
    
    std::unique_ptr<Expression> simplify() const override {
        return std::make_unique<BinaryExpression>(left->simplify(), operator_, right->simplify());
    }
    
    std::unique_ptr<Expression> optimize_expression() const override {
        return std::make_unique<BinaryExpression>(left->optimize_expression(), operator_, right->optimize_expression());
    }
    
    bool has_side_effects() const override {
        return left->has_side_effects() || right->has_side_effects();
    }
    
    std::string get_expression_type() const override {
        return "binary_op";
    }
    
    int get_precedence() const override {
        if (operator_ == "*" || operator_ == "/" || operator_ == "%") return 5;
        if (operator_ == "+" || operator_ == "-") return 4;
        if (operator_ == "<" || operator_ == ">" || operator_ == "<=" || operator_ == ">=") return 3;
        if (operator_ == "==" || operator_ == "!=") return 2;
        if (operator_ == "&&") return 1;
        if (operator_ == "||") return 0;
        return 0;
    }
    
    bool is_left_associative() const override {
        return true;
    }
    
    std::string to_code() const override {
        return "(" + left->to_code() + " " + operator_ + " " + right->to_code() + ")";
    }
    
    std::vector<Expression*> get_subexpressions() override {
        return {left.get(), right.get()};
    }
    
    std::vector<const Expression*> get_subexpressions() const override {
        return {left.get(), right.get()};
    }
    
    std::unique_ptr<Expression> clone_expression() const override {
        return std::make_unique<BinaryExpression>(left->clone_expression(), operator_, right->clone_expression());
    }
    
    std::string get_return_type() const override {
        if (operator_ == "==" || operator_ == "!=" || operator_ == "<" || operator_ == ">" || 
            operator_ == "<=" || operator_ == ">=" || operator_ == "&&" || operator_ == "||") {
            return "bool";
        }
        return "unknown";
    }
    
    bool is_type_compatible(const std::string& type) const override {
        return get_return_type() == type || type == "unknown";
    }
    
    std::vector<std::string> get_possible_types() const override {
        return {get_return_type()};
    }
    
    std::string to_javascript() const override { return to_code(); }
    std::string to_python() const override { return to_code(); }
    std::string to_cpp() const override { return to_code(); }
    std::string to_json() const override { return to_code(); }
    
    std::vector<std::string> get_required_imports() const override { return {}; }
    std::vector<std::string> get_required_libraries() const override { return {}; }
    
    double complexity() const override {
        return 1.0 + left->complexity() + right->complexity();
    }
    
    size_t memory_usage() const override {
        return sizeof(BinaryExpression) + left->memory_usage() + right->memory_usage();
    }
    
    size_t instruction_count() const override {
        return 1 + left->instruction_count() + right->instruction_count();
    }
    
    bool is_tail_recursive() const override { return false; }
    bool is_recursive() const override { return left->is_recursive() || right->is_recursive(); }
    std::vector<std::string> get_recursive_calls() const override {
        auto left_calls = left->get_recursive_calls();
        auto right_calls = right->get_recursive_calls();
        left_calls.insert(left_calls.end(), right_calls.begin(), right_calls.end());
        return left_calls;
    }
    
    std::unique_ptr<Expression> inline_expression() const override {
        return std::make_unique<BinaryExpression>(left->inline_expression(), operator_, right->inline_expression());
    }
    
    std::unique_ptr<Expression> flatten_expression() const override {
        return std::make_unique<BinaryExpression>(left->flatten_expression(), operator_, right->flatten_expression());
    }
    
    std::unique_ptr<Expression> normalize_expression() const override {
        return std::make_unique<BinaryExpression>(left->normalize_expression(), operator_, right->normalize_expression());
    }
    
    std::unordered_map<std::string, int> get_variable_usage() const override {
        auto left_usage = left->get_variable_usage();
        auto right_usage = right->get_variable_usage();
        for (const auto& [var, count] : right_usage) {
            left_usage[var] += count;
        }
        return left_usage;
    }
    
    std::vector<std::string> get_free_variables() const override {
        auto left_vars = left->get_free_variables();
        auto right_vars = right->get_free_variables();
        left_vars.insert(left_vars.end(), right_vars.begin(), right_vars.end());
        return left_vars;
    }
    
    std::vector<std::string> get_bound_variables() const override {
        auto left_vars = left->get_bound_variables();
        auto right_vars = right->get_bound_variables();
        left_vars.insert(left_vars.end(), right_vars.begin(), right_vars.end());
        return left_vars;
    }
    
    bool is_well_formed() const override {
        return left && right && left->is_well_formed() && right->is_well_formed();
    }
    
    std::vector<std::string> get_semantic_errors() const override {
        auto errors = left->get_semantic_errors();
        auto right_errors = right->get_semantic_errors();
        errors.insert(errors.end(), right_errors.begin(), right_errors.end());
        return errors;
    }
    
    std::unique_ptr<Expression> substitute(const std::string& var, const Expression& expr) const override {
        return std::make_unique<BinaryExpression>(left->substitute(var, expr), operator_, right->substitute(var, expr));
    }
    
    std::unique_ptr<Expression> alpha_convert(const std::unordered_map<std::string, std::string>& mapping) const override {
        return std::make_unique<BinaryExpression>(left->alpha_convert(mapping), operator_, right->alpha_convert(mapping));
    }
    
    std::unique_ptr<Expression> beta_reduce() const override {
        return std::make_unique<BinaryExpression>(left->beta_reduce(), operator_, right->beta_reduce());
    }
    
    std::unique_ptr<Expression> eta_convert() const override {
        return std::make_unique<BinaryExpression>(left->eta_convert(), operator_, right->eta_convert());
    }
    
    bool is_reducible() const override {
        return left->is_reducible() || right->is_reducible();
    }
    
    std::unique_ptr<Expression> reduce() const override {
        return std::make_unique<BinaryExpression>(left->reduce(), operator_, right->reduce());
    }
    
    std::unique_ptr<Expression> normalize() const override {
        return std::make_unique<BinaryExpression>(left->normalize(), operator_, right->normalize());
    }
    
    std::string get_canonical_form() const override {
        return left->get_canonical_form() + " " + operator_ + " " + right->get_canonical_form();
    }
    
    std::string get_hash_string() const override {
        return left->get_hash_string() + operator_ + right->get_hash_string();
    }
    
    bool structural_equals(const Expression& other) const override {
        if (auto bin = dynamic_cast<const BinaryExpression*>(&other)) {
            return operator_ == bin->operator_ && 
                   left->structural_equals(*bin->left) && 
                   right->structural_equals(*bin->right);
        }
        return false;
    }
    
    std::unique_ptr<Expression> differentiate(const std::string& var) const override {
        return std::make_unique<LiteralExpression>(Value(0.0));
    }
    
    std::unique_ptr<Expression> integrate(const std::string& var) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> partial_derivative(const std::string& var) const override {
        return differentiate(var);
    }
    
    std::unique_ptr<Expression> apply_rules(const std::vector<std::pair<std::string, std::string>>& rules) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> apply_transformations(const std::vector<std::function<std::unique_ptr<Expression>(const Expression&)>>& transforms) const override {
        return clone_expression();
    }
    
    void validate() const override {}
    std::vector<std::string> get_validation_errors() const override { return {}; }
    bool is_valid() const override { return left && right; }
    
    void optimize() override {}
    
    std::unordered_map<std::string, Value> get_attributes() const override {
        return metadata_.attributes;
    }
    
    void set_attribute(const std::string& name, const Value& value) override {
        metadata_.attributes[name] = value;
    }
    
    std::optional<Value> get_attribute(const std::string& name) const override {
        auto it = metadata_.attributes.find(name);
        return it != metadata_.attributes.end() ? std::optional<Value>(it->second) : std::nullopt;
    }
    
    bool has_attribute(const std::string& name) const override {
        return metadata_.attributes.find(name) != metadata_.attributes.end();
    }
    
    void remove_attribute(const std::string& name) override {
        metadata_.attributes.erase(name);
    }
    
    Position get_position() const override {
        return metadata_.position;
    }
    
    void set_position(const Position& pos) override {
        metadata_.position = pos;
    }
    
    Metadata& get_metadata() override {
        return metadata_;
    }
    
    const Metadata& get_metadata() const override {
        return metadata_;
    }
    
    std::string get_node_type() const override { return "BinaryExpression"; }
    std::string get_node_name() const override { return "binary"; }
    
private:
    mutable Metadata metadata_;
};

class UnaryExpression : public Expression {
public:
    std::string operator_;
    std::unique_ptr<Expression> operand;
    
    UnaryExpression(const std::string& op, std::unique_ptr<Expression> operand)
        : operator_(op), operand(std::move(operand)) {}
    
    void accept(ASTVisitor& visitor) override {}
    void accept(ConstASTVisitor& visitor) const override {}
    void accept(MutableASTVisitor& visitor) override {}
    
    std::unique_ptr<ASTNode> clone() const override {
        return std::make_unique<UnaryExpression>(operator_, operand->clone_expression());
    }
    
    std::string to_string() const override {
        return operator_ + operand->to_string();
    }
    
    std::size_t hash() const override {
        return std::hash<std::string>{}(to_string());
    }
    
    bool equals(const ASTNode& other) const override {
        if (auto unary = dynamic_cast<const UnaryExpression*>(&other)) {
            return operator_ == unary->operator_ && operand->equals(*unary->operand);
        }
        return false;
    }
    
    std::string serialize() const override {
        return "unary:" + operator_ + ":" + operand->serialize();
    }
    
    void deserialize(const std::string& data) override {}
    
    std::vector<ASTNode*> get_children() override {
        return {operand.get()};
    }
    
    std::vector<const ASTNode*> get_children() const override {
        return {operand.get()};
    }
    
    Value evaluate() const override { return Value(); }
    bool is_constant() const override { return operand->is_constant(); }
    bool is_pure() const override { return operand->is_pure(); }
    
    std::vector<std::string> get_dependencies() const override {
        return operand->get_dependencies();
    }
    
    void replace_dependency(const std::string& old_name, const std::string& new_name) override {
        operand->replace_dependency(old_name, new_name);
    }
    
    std::unique_ptr<Expression> simplify() const override {
        return std::make_unique<UnaryExpression>(operator_, operand->simplify());
    }
    
    std::unique_ptr<Expression> optimize_expression() const override {
        return std::make_unique<UnaryExpression>(operator_, operand->optimize_expression());
    }
    
    bool has_side_effects() const override { return operand->has_side_effects(); }
    std::string get_expression_type() const override { return "unary_op"; }
    
    int get_precedence() const override { return 10; }
    bool is_left_associative() const override { return false; }
    std::string to_code() const override { return operator_ + operand->to_code(); }
    
    std::vector<Expression*> get_subexpressions() override {
        return {operand.get()};
    }
    
    std::vector<const Expression*> get_subexpressions() const override {
        return {operand.get()};
    }
    
    std::unique_ptr<Expression> clone_expression() const override {
        return std::make_unique<UnaryExpression>(operator_, operand->clone_expression());
    }
    
    std::string get_return_type() const override {
        if (operator_ == "!") return "bool";
        return "unknown";
    }
    
    bool is_type_compatible(const std::string& type) const override {
        return get_return_type() == type || type == "unknown";
    }
    
    std::vector<std::string> get_possible_types() const override {
        return {get_return_type()};
    }
    
    std::string to_javascript() const override { return to_code(); }
    std::string to_python() const override { return to_code(); }
    std::string to_cpp() const override { return to_code(); }
    std::string to_json() const override { return to_code(); }
    
    std::vector<std::string> get_required_imports() const override { return {}; }
    std::vector<std::string> get_required_libraries() const override { return {}; }
    
    double complexity() const override { return 1.0 + operand->complexity(); }
    size_t memory_usage() const override { return sizeof(UnaryExpression) + operand->memory_usage(); }
    size_t instruction_count() const override { return 1 + operand->instruction_count(); }
    
    bool is_tail_recursive() const override { return false; }
    bool is_recursive() const override { return operand->is_recursive(); }
    std::vector<std::string> get_recursive_calls() const override { return operand->get_recursive_calls(); }
    
    std::unique_ptr<Expression> inline_expression() const override {
        return std::make_unique<UnaryExpression>(operator_, operand->inline_expression());
    }
    
    std::unique_ptr<Expression> flatten_expression() const override {
        return std::make_unique<UnaryExpression>(operator_, operand->flatten_expression());
    }
    
    std::unique_ptr<Expression> normalize_expression() const override {
        return std::make_unique<UnaryExpression>(operator_, operand->normalize_expression());
    }
    
    std::unordered_map<std::string, int> get_variable_usage() const override {
        return operand->get_variable_usage();
    }
    
    std::vector<std::string> get_free_variables() const override {
        return operand->get_free_variables();
    }
    
    std::vector<std::string> get_bound_variables() const override {
        return operand->get_bound_variables();
    }
    
    bool is_well_formed() const override { return operand && operand->is_well_formed(); }
    std::vector<std::string> get_semantic_errors() const override { return operand->get_semantic_errors(); }
    
    std::unique_ptr<Expression> substitute(const std::string& var, const Expression& expr) const override {
        return std::make_unique<UnaryExpression>(operator_, operand->substitute(var, expr));
    }
    
    std::unique_ptr<Expression> alpha_convert(const std::unordered_map<std::string, std::string>& mapping) const override {
        return std::make_unique<UnaryExpression>(operator_, operand->alpha_convert(mapping));
    }
    
    std::unique_ptr<Expression> beta_reduce() const override {
        return std::make_unique<UnaryExpression>(operator_, operand->beta_reduce());
    }
    
    std::unique_ptr<Expression> eta_convert() const override {
        return std::make_unique<UnaryExpression>(operator_, operand->eta_convert());
    }
    
    bool is_reducible() const override { return operand->is_reducible(); }
    
    std::unique_ptr<Expression> reduce() const override {
        return std::make_unique<UnaryExpression>(operator_, operand->reduce());
    }
    
    std::unique_ptr<Expression> normalize() const override {
        return std::make_unique<UnaryExpression>(operator_, operand->normalize());
    }
    
    std::string get_canonical_form() const override {
        return operator_ + operand->get_canonical_form();
    }
    
    std::string get_hash_string() const override {
        return operator_ + operand->get_hash_string();
    }
    
    bool structural_equals(const Expression& other) const override {
        if (auto unary = dynamic_cast<const UnaryExpression*>(&other)) {
            return operator_ == unary->operator_ && operand->structural_equals(*unary->operand);
        }
        return false;
    }
    
    std::unique_ptr<Expression> differentiate(const std::string& var) const override {
        return std::make_unique<LiteralExpression>(Value(0.0));
    }
    
    std::unique_ptr<Expression> integrate(const std::string& var) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> partial_derivative(const std::string& var) const override {
        return differentiate(var);
    }
    
    std::unique_ptr<Expression> apply_rules(const std::vector<std::pair<std::string, std::string>>& rules) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> apply_transformations(const std::vector<std::function<std::unique_ptr<Expression>(const Expression&)>>& transforms) const override {
        return clone_expression();
    }
    
    void validate() const override {}
    std::vector<std::string> get_validation_errors() const override { return {}; }
    bool is_valid() const override { return operand != nullptr; }
    
    void optimize() override {}
    
    std::unordered_map<std::string, Value> get_attributes() const override {
        return metadata_.attributes;
    }
    
    void set_attribute(const std::string& name, const Value& value) override {
        metadata_.attributes[name] = value;
    }
    
    std::optional<Value> get_attribute(const std::string& name) const override {
        auto it = metadata_.attributes.find(name);
        return it != metadata_.attributes.end() ? std::optional<Value>(it->second) : std::nullopt;
    }
    
    bool has_attribute(const std::string& name) const override {
        return metadata_.attributes.find(name) != metadata_.attributes.end();
    }
    
    void remove_attribute(const std::string& name) override {
        metadata_.attributes.erase(name);
    }
    
    Position get_position() const override {
        return metadata_.position;
    }
    
    void set_position(const Position& pos) override {
        metadata_.position = pos;
    }
    
    Metadata& get_metadata() override {
        return metadata_;
    }
    
    const Metadata& get_metadata() const override {
        return metadata_;
    }
    
    std::string get_node_type() const override { return "UnaryExpression"; }
    std::string get_node_name() const override { return "unary"; }
    
private:
    mutable Metadata metadata_;
};

class CallExpression : public Expression {
public:
    std::string name;
    std::vector<std::unique_ptr<Expression>> arguments;
    
    CallExpression(const std::string& name, std::vector<std::unique_ptr<Expression>> arguments)
        : name(name), arguments(std::move(arguments)) {}
    
    void accept(ASTVisitor& visitor) override {}
    void accept(ConstASTVisitor& visitor) const override {}
    void accept(MutableASTVisitor& visitor) override {}
    
    std::unique_ptr<ASTNode> clone() const override {
        std::vector<std::unique_ptr<Expression>> cloned_args;
        for (const auto& arg : arguments) {
            cloned_args.push_back(arg->clone_expression());
        }
        return std::make_unique<CallExpression>(name, std::move(cloned_args));
    }
    
    std::string to_string() const override {
        std::string result = name + "(";
        for (size_t i = 0; i < arguments.size(); ++i) {
            if (i > 0) result += ", ";
            result += arguments[i]->to_string();
        }
        result += ")";
        return result;
    }
    
    std::size_t hash() const override {
        return std::hash<std::string>{}(to_string());
    }
    
    bool equals(const ASTNode& other) const override {
        if (auto call = dynamic_cast<const CallExpression*>(&other)) {
            if (name != call->name || arguments.size() != call->arguments.size()) {
                return false;
            }
            for (size_t i = 0; i < arguments.size(); ++i) {
                if (!arguments[i]->equals(*call->arguments[i])) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
    
    std::string serialize() const override {
        return "call:" + name;
    }
    
    void deserialize(const std::string& data) override {}
    
    std::vector<ASTNode*> get_children() override {
        std::vector<ASTNode*> children;
        for (const auto& arg : arguments) {
            children.push_back(arg.get());
        }
        return children;
    }
    
    std::vector<const ASTNode*> get_children() const override {
        std::vector<const ASTNode*> children;
        for (const auto& arg : arguments) {
            children.push_back(arg.get());
        }
        return children;
    }
    
    Value evaluate() const override { return Value(); }
    bool is_constant() const override { return false; }
    bool is_pure() const override { return false; }
    
    std::vector<std::string> get_dependencies() const override {
        std::vector<std::string> deps;
        for (const auto& arg : arguments) {
            auto arg_deps = arg->get_dependencies();
            deps.insert(deps.end(), arg_deps.begin(), arg_deps.end());
        }
        return deps;
    }
    
    void replace_dependency(const std::string& old_name, const std::string& new_name) override {
        for (auto& arg : arguments) {
            arg->replace_dependency(old_name, new_name);
        }
    }
    
    std::unique_ptr<Expression> simplify() const override {
        std::vector<std::unique_ptr<Expression>> simplified_args;
        for (const auto& arg : arguments) {
            simplified_args.push_back(arg->simplify());
        }
        return std::make_unique<CallExpression>(name, std::move(simplified_args));
    }
    
    std::unique_ptr<Expression> optimize_expression() const override {
        std::vector<std::unique_ptr<Expression>> optimized_args;
        for (const auto& arg : arguments) {
            optimized_args.push_back(arg->optimize_expression());
        }
        return std::make_unique<CallExpression>(name, std::move(optimized_args));
    }
    
    bool has_side_effects() const override { return true; }
    std::string get_expression_type() const override { return "call"; }
    
    int get_precedence() const override { return 15; }
    bool is_left_associative() const override { return true; }
    std::string to_code() const override { return to_string(); }
    
    std::vector<Expression*> get_subexpressions() override {
        std::vector<Expression*> exprs;
        for (const auto& arg : arguments) {
            exprs.push_back(arg.get());
        }
        return exprs;
    }
    
    std::vector<const Expression*> get_subexpressions() const override {
        std::vector<const Expression*> exprs;
        for (const auto& arg : arguments) {
            exprs.push_back(arg.get());
        }
        return exprs;
    }
    
    std::unique_ptr<Expression> clone_expression() const override {
        std::vector<std::unique_ptr<Expression>> cloned_args;
        for (const auto& arg : arguments) {
            cloned_args.push_back(arg->clone_expression());
        }
        return std::make_unique<CallExpression>(name, std::move(cloned_args));
    }
    
    std::string get_return_type() const override { return "unknown"; }
    bool is_type_compatible(const std::string& type) const override { return true; }
    std::vector<std::string> get_possible_types() const override { return {"unknown"}; }
    
    std::string to_javascript() const override { return to_string(); }
    std::string to_python() const override { return to_string(); }
    std::string to_cpp() const override { return to_string(); }
    std::string to_json() const override { return to_string(); }
    
    std::vector<std::string> get_required_imports() const override { return {}; }
    std::vector<std::string> get_required_libraries() const override { return {}; }
    
    double complexity() const override {
        double total = 2.0;
        for (const auto& arg : arguments) {
            total += arg->complexity();
        }
        return total;
    }
    
    size_t memory_usage() const override {
        size_t total = sizeof(CallExpression);
        for (const auto& arg : arguments) {
            total += arg->memory_usage();
        }
        return total;
    }
    
    size_t instruction_count() const override {
        size_t total = 2;
        for (const auto& arg : arguments) {
            total += arg->instruction_count();
        }
        return total;
    }
    
    bool is_tail_recursive() const override { return false; }
    bool is_recursive() const override { return name == "recursive_call"; }
    std::vector<std::string> get_recursive_calls() const override { return {name}; }
    
    std::unique_ptr<Expression> inline_expression() const override {
        std::vector<std::unique_ptr<Expression>> inlined_args;
        for (const auto& arg : arguments) {
            inlined_args.push_back(arg->inline_expression());
        }
        return std::make_unique<CallExpression>(name, std::move(inlined_args));
    }
    
    std::unique_ptr<Expression> flatten_expression() const override {
        std::vector<std::unique_ptr<Expression>> flattened_args;
        for (const auto& arg : arguments) {
            flattened_args.push_back(arg->flatten_expression());
        }
        return std::make_unique<CallExpression>(name, std::move(flattened_args));
    }
    
    std::unique_ptr<Expression> normalize_expression() const override {
        std::vector<std::unique_ptr<Expression>> normalized_args;
        for (const auto& arg : arguments) {
            normalized_args.push_back(arg->normalize_expression());
        }
        return std::make_unique<CallExpression>(name, std::move(normalized_args));
    }
    
    std::unordered_map<std::string, int> get_variable_usage() const override {
        std::unordered_map<std::string, int> usage;
        for (const auto& arg : arguments) {
            auto arg_usage = arg->get_variable_usage();
            for (const auto& [var, count] : arg_usage) {
                usage[var] += count;
            }
        }
        return usage;
    }
    
    std::vector<std::string> get_free_variables() const override {
        std::vector<std::string> vars;
        for (const auto& arg : arguments) {
            auto arg_vars = arg->get_free_variables();
            vars.insert(vars.end(), arg_vars.begin(), arg_vars.end());
        }
        return vars;
    }
    
    std::vector<std::string> get_bound_variables() const override {
        std::vector<std::string> vars;
        for (const auto& arg : arguments) {
            auto arg_vars = arg->get_bound_variables();
            vars.insert(vars.end(), arg_vars.begin(), arg_vars.end());
        }
        return vars;
    }
    
    bool is_well_formed() const override { return !name.empty(); }
    std::vector<std::string> get_semantic_errors() const override {
        std::vector<std::string> errors;
        for (const auto& arg : arguments) {
            auto arg_errors = arg->get_semantic_errors();
            errors.insert(errors.end(), arg_errors.begin(), arg_errors.end());
        }
        return errors;
    }
    
    std::unique_ptr<Expression> substitute(const std::string& var, const Expression& expr) const override {
        std::vector<std::unique_ptr<Expression>> substituted_args;
        for (const auto& arg : arguments) {
            substituted_args.push_back(arg->substitute(var, expr));
        }
        return std::make_unique<CallExpression>(name, std::move(substituted_args));
    }
    
    std::unique_ptr<Expression> alpha_convert(const std::unordered_map<std::string, std::string>& mapping) const override {
        std::vector<std::unique_ptr<Expression>> converted_args;
        for (const auto& arg : arguments) {
            converted_args.push_back(arg->alpha_convert(mapping));
        }
        return std::make_unique<CallExpression>(name, std::move(converted_args));
    }
    
    std::unique_ptr<Expression> beta_reduce() const override {
        std::vector<std::unique_ptr<Expression>> reduced_args;
        for (const auto& arg : arguments) {
            reduced_args.push_back(arg->beta_reduce());
        }
        return std::make_unique<CallExpression>(name, std::move(reduced_args));
    }
    
    std::unique_ptr<Expression> eta_convert() const override {
        std::vector<std::unique_ptr<Expression>> converted_args;
        for (const auto& arg : arguments) {
            converted_args.push_back(arg->eta_convert());
        }
        return std::make_unique<CallExpression>(name, std::move(converted_args));
    }
    
    bool is_reducible() const override { return true; }
    
    std::unique_ptr<Expression> reduce() const override {
        std::vector<std::unique_ptr<Expression>> reduced_args;
        for (const auto& arg : arguments) {
            reduced_args.push_back(arg->reduce());
        }
        return std::make_unique<CallExpression>(name, std::move(reduced_args));
    }
    
    std::unique_ptr<Expression> normalize() const override {
        std::vector<std::unique_ptr<Expression>> normalized_args;
        for (const auto& arg : arguments) {
            normalized_args.push_back(arg->normalize());
        }
        return std::make_unique<CallExpression>(name, std::move(normalized_args));
    }
    
    std::string get_canonical_form() const override {
        std::string result = name + "(";
        for (size_t i = 0; i < arguments.size(); ++i) {
            if (i > 0) result += ", ";
            result += arguments[i]->get_canonical_form();
        }
        result += ")";
        return result;
    }
    
    std::string get_hash_string() const override {
        std::string result = name + "(";
        for (size_t i = 0; i < arguments.size(); ++i) {
            if (i > 0) result += ",";
            result += arguments[i]->get_hash_string();
        }
        result += ")";
        return result;
    }
    
    bool structural_equals(const Expression& other) const override {
        if (auto call = dynamic_cast<const CallExpression*>(&other)) {
            if (name != call->name || arguments.size() != call->arguments.size()) {
                return false;
            }
            for (size_t i = 0; i < arguments.size(); ++i) {
                if (!arguments[i]->structural_equals(*call->arguments[i])) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
    
    std::unique_ptr<Expression> differentiate(const std::string& var) const override {
        return std::make_unique<LiteralExpression>(Value(0.0));
    }
    
    std::unique_ptr<Expression> integrate(const std::string& var) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> partial_derivative(const std::string& var) const override {
        return differentiate(var);
    }
    
    std::unique_ptr<Expression> apply_rules(const std::vector<std::pair<std::string, std::string>>& rules) const override {
        return clone_expression();
    }
    
    std::unique_ptr<Expression> apply_transformations(const std::vector<std::function<std::unique_ptr<Expression>(const Expression&)>>& transforms) const override {
        return clone_expression();
    }
    
    void validate() const override {}
    std::vector<std::string> get_validation_errors() const override { return {}; }
    bool is_valid() const override { return !name.empty(); }
    
    void optimize() override {}
    
    std::unordered_map<std::string, Value> get_attributes() const override {
        return metadata_.attributes;
    }
    
    void set_attribute(const std::string& name, const Value& value) override {
        metadata_.attributes[name] = value;
    }
    
    std::optional<Value> get_attribute(const std::string& name) const override {
        auto it = metadata_.attributes.find(name);
        return it != metadata_.attributes.end() ? std::optional<Value>(it->second) : std::nullopt;
    }
    
    bool has_attribute(const std::string& name) const override {
        return metadata_.attributes.find(name) != metadata_.attributes.end();
    }
    
    void remove_attribute(const std::string& name) override {
        metadata_.attributes.erase(name);
    }
    
    Position get_position() const override {
        return metadata_.position;
    }
    
    void set_position(const Position& pos) override {
        metadata_.position = pos;
    }
    
    Metadata& get_metadata() override {
        return metadata_;
    }
    
    const Metadata& get_metadata() const override {
        return metadata_;
    }
    
    std::string get_node_type() const override { return "CallExpression"; }
    std::string get_node_name() const override { return "call"; }
    
private:
    mutable Metadata metadata_;
};

} 