#pragma once

#include "ast.hpp"
#include "ast_nodes.hpp"
#include <string>
#include <vector>
#include <memory>

namespace yalok {

class ExpressionStatement : public Statement {
public:
    std::unique_ptr<Expression> expression;
    
    ExpressionStatement(std::unique_ptr<Expression> expr) : expression(std::move(expr)) {}
    
    void accept(ASTVisitor& visitor) override {}
    void accept(ConstASTVisitor& visitor) const override {}
    void accept(MutableASTVisitor& visitor) override {}
    
    std::unique_ptr<ASTNode> clone() const override {
        return std::make_unique<ExpressionStatement>(expression->clone_expression());
    }
    
    std::string to_string() const override {
        return expression->to_string() + ";";
    }
    
    std::size_t hash() const override {
        return expression->hash();
    }
    
    bool equals(const ASTNode& other) const override {
        if (auto stmt = dynamic_cast<const ExpressionStatement*>(&other)) {
            return expression->equals(*stmt->expression);
        }
        return false;
    }
    
    std::string serialize() const override {
        return "expr_stmt:" + expression->serialize();
    }
    
    void deserialize(const std::string& data) override {}
    
    std::vector<ASTNode*> get_children() override {
        return {expression.get()};
    }
    
    std::vector<const ASTNode*> get_children() const override {
        return {expression.get()};
    }
    
    void execute() const override {}
    bool is_control_flow() const override { return false; }
    bool is_declaration() const override { return false; }
    bool is_expression_statement() const override { return true; }
    bool returns_value() const override { return false; }
    bool can_fallthrough() const override { return true; }
    
    std::vector<std::string> get_declared_variables() const override {
        return {};
    }
    
    std::vector<std::string> get_used_variables() const override {
        return expression->get_free_variables();
    }
    
    std::vector<std::string> get_modified_variables() const override {
        return {};
    }
    
    std::string get_statement_type() const override {
        return "expression_statement";
    }
    
    std::unique_ptr<Statement> clone_statement() const override {
        return std::make_unique<ExpressionStatement>(expression->clone_expression());
    }
    
    std::string to_code() const override {
        return expression->to_code() + ";";
    }
    
    std::vector<Statement*> get_substatements() override {
        return {};
    }
    
    std::vector<const Statement*> get_substatements() const override {
        return {};
    }
    
    std::string to_javascript() const override { return to_code(); }
    std::string to_python() const override { return to_code(); }
    std::string to_cpp() const override { return to_code(); }
    std::string to_json() const override { return to_code(); }
    
    std::vector<std::string> get_required_imports() const override { return {}; }
    std::vector<std::string> get_required_libraries() const override { return {}; }
    
    double complexity() const override { return expression->complexity(); }
    size_t memory_usage() const override { return sizeof(ExpressionStatement) + expression->memory_usage(); }
    size_t instruction_count() const override { return expression->instruction_count(); }
    
    bool is_unreachable() const override { return false; }
    bool is_dead_code() const override { return false; }
    std::vector<std::string> get_unreachable_statements() const override { return {}; }
    
    std::unique_ptr<Statement> optimize_statement() const override {
        return std::make_unique<ExpressionStatement>(expression->optimize_expression());
    }
    
    std::unique_ptr<Statement> inline_statement() const override {
        return std::make_unique<ExpressionStatement>(expression->inline_expression());
    }
    
    std::unique_ptr<Statement> flatten_statement() const override {
        return std::make_unique<ExpressionStatement>(expression->flatten_expression());
    }
    
    std::unordered_map<std::string, int> get_variable_usage() const override {
        return expression->get_variable_usage();
    }
    
    std::vector<std::string> get_free_variables() const override {
        return expression->get_free_variables();
    }
    
    std::vector<std::string> get_bound_variables() const override {
        return expression->get_bound_variables();
    }
    
    bool is_well_formed() const override { return expression && expression->is_well_formed(); }
    std::vector<std::string> get_semantic_errors() const override { return expression->get_semantic_errors(); }
    
    std::unique_ptr<Statement> substitute(const std::string& var, const Expression& expr) const override {
        return std::make_unique<ExpressionStatement>(expression->substitute(var, expr));
    }
    
    std::unique_ptr<Statement> alpha_convert(const std::unordered_map<std::string, std::string>& mapping) const override {
        return std::make_unique<ExpressionStatement>(expression->alpha_convert(mapping));
    }
    
    std::string get_canonical_form() const override {
        return expression->get_canonical_form() + ";";
    }
    
    std::string get_hash_string() const override {
        return expression->get_hash_string() + ";";
    }
    
    bool structural_equals(const Statement& other) const override {
        if (auto stmt = dynamic_cast<const ExpressionStatement*>(&other)) {
            return expression->structural_equals(*stmt->expression);
        }
        return false;
    }
    
    std::unique_ptr<Statement> apply_rules(const std::vector<std::pair<std::string, std::string>>& rules) const override {
        return clone_statement();
    }
    
    std::unique_ptr<Statement> apply_transformations(const std::vector<std::function<std::unique_ptr<Statement>(const Statement&)>>& transforms) const override {
        return clone_statement();
    }
    
    std::vector<std::string> get_control_flow_successors() const override { return {}; }
    std::vector<std::string> get_control_flow_predecessors() const override { return {}; }
    bool is_loop() const override { return false; }
    bool is_conditional() const override { return false; }
    bool is_jump() const override { return false; }
    
    bool has_side_effects() const override { return expression->has_side_effects(); }
    std::vector<std::string> get_side_effects() const override { return {}; }
    
    std::unique_ptr<Statement> hoist_declarations() const override { return clone_statement(); }
    std::unique_ptr<Statement> eliminate_dead_code() const override { return clone_statement(); }
    std::unique_ptr<Statement> constant_fold() const override { return clone_statement(); }
    std::unique_ptr<Statement> strength_reduce() const override { return clone_statement(); }
    
    std::vector<std::string> get_labels() const override { return {}; }
    bool has_label(const std::string& label) const override { return false; }
    void add_label(const std::string& label) override {}
    void remove_label(const std::string& label) override {}
    
    std::unique_ptr<Statement> unroll_loops(int factor) const override { return clone_statement(); }
    std::unique_ptr<Statement> parallelize() const override { return clone_statement(); }
    std::unique_ptr<Statement> vectorize() const override { return clone_statement(); }
    
    bool is_pure() const override { return expression->is_pure(); }
    bool is_deterministic() const override { return true; }
    bool is_idempotent() const override { return true; }
    bool is_commutative() const override { return false; }
    bool is_associative() const override { return false; }
    
    std::unique_ptr<Statement> refactor_extract_method(const std::string& method_name) const override {
        return clone_statement();
    }
    
    std::unique_ptr<Statement> refactor_inline_method(const std::string& method_name) const override {
        return clone_statement();
    }
    
    std::unique_ptr<Statement> refactor_rename_variable(const std::string& old_name, const std::string& new_name) const override {
        return clone_statement();
    }
    
    std::vector<std::string> get_code_smells() const override { return {}; }
    std::vector<std::string> get_refactoring_suggestions() const override { return {}; }
    double get_maintainability_score() const override { return 1.0; }
    
    std::unique_ptr<Statement> modernize() const override { return clone_statement(); }
    std::unique_ptr<Statement> apply_style_guide() const override { return clone_statement(); }
    std::unique_ptr<Statement> format_code() const override { return clone_statement(); }
    
    void validate() const override {}
    std::vector<std::string> get_validation_errors() const override { return {}; }
    bool is_valid() const override { return expression != nullptr; }
    
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
    
    std::string get_node_type() const override { return "ExpressionStatement"; }
    std::string get_node_name() const override { return "expression_statement"; }
    
private:
    mutable Metadata metadata_;
};

class VariableStatement : public Statement {
public:
    std::string name;
    std::unique_ptr<Expression> initializer;
    
    VariableStatement(const std::string& name, std::unique_ptr<Expression> init = nullptr)
        : name(name), initializer(std::move(init)) {}
    
    void accept(ASTVisitor& visitor) override {}
    void accept(ConstASTVisitor& visitor) const override {}
    void accept(MutableASTVisitor& visitor) override {}
    
    std::unique_ptr<ASTNode> clone() const override {
        auto init_clone = initializer ? initializer->clone_expression() : nullptr;
        return std::make_unique<VariableStatement>(name, std::move(init_clone));
    }
    
    std::string to_string() const override {
        std::string result = "var " + name;
        if (initializer) {
            result += " = " + initializer->to_string();
        }
        result += ";";
        return result;
    }
    
    std::size_t hash() const override {
        return std::hash<std::string>{}(name);
    }
    
    bool equals(const ASTNode& other) const override {
        if (auto stmt = dynamic_cast<const VariableStatement*>(&other)) {
            if (name != stmt->name) return false;
            if (initializer && stmt->initializer) {
                return initializer->equals(*stmt->initializer);
            }
            return !initializer && !stmt->initializer;
        }
        return false;
    }
    
    std::string serialize() const override {
        return "var_stmt:" + name;
    }
    
    void deserialize(const std::string& data) override {}
    
    std::vector<ASTNode*> get_children() override {
        if (initializer) {
            return {initializer.get()};
        }
        return {};
    }
    
    std::vector<const ASTNode*> get_children() const override {
        if (initializer) {
            return {initializer.get()};
        }
        return {};
    }
    
    void execute() const override {}
    bool is_control_flow() const override { return false; }
    bool is_declaration() const override { return true; }
    bool is_expression_statement() const override { return false; }
    bool returns_value() const override { return false; }
    bool can_fallthrough() const override { return true; }
    
    std::vector<std::string> get_declared_variables() const override {
        return {name};
    }
    
    std::vector<std::string> get_used_variables() const override {
        if (initializer) {
            return initializer->get_free_variables();
        }
        return {};
    }
    
    std::vector<std::string> get_modified_variables() const override {
        return {name};
    }
    
    std::string get_statement_type() const override {
        return "variable_declaration";
    }
    
    std::unique_ptr<Statement> clone_statement() const override {
        auto init_clone = initializer ? initializer->clone_expression() : nullptr;
        return std::make_unique<VariableStatement>(name, std::move(init_clone));
    }
    
    std::string to_code() const override {
        return to_string();
    }
    
    std::vector<Statement*> get_substatements() override {
        return {};
    }
    
    std::vector<const Statement*> get_substatements() const override {
        return {};
    }
    
    std::string to_javascript() const override { return to_code(); }
    std::string to_python() const override { return to_code(); }
    std::string to_cpp() const override { return to_code(); }
    std::string to_json() const override { return to_code(); }
    
    std::vector<std::string> get_required_imports() const override { return {}; }
    std::vector<std::string> get_required_libraries() const override { return {}; }
    
    double complexity() const override {
        return initializer ? 1.0 + initializer->complexity() : 1.0;
    }
    
    size_t memory_usage() const override {
        return sizeof(VariableStatement) + (initializer ? initializer->memory_usage() : 0);
    }
    
    size_t instruction_count() const override {
        return 1 + (initializer ? initializer->instruction_count() : 0);
    }
    
    bool is_unreachable() const override { return false; }
    bool is_dead_code() const override { return false; }
    std::vector<std::string> get_unreachable_statements() const override { return {}; }
    
    std::unique_ptr<Statement> optimize_statement() const override {
        auto init_opt = initializer ? initializer->optimize_expression() : nullptr;
        return std::make_unique<VariableStatement>(name, std::move(init_opt));
    }
    
    std::unique_ptr<Statement> inline_statement() const override {
        auto init_inline = initializer ? initializer->inline_expression() : nullptr;
        return std::make_unique<VariableStatement>(name, std::move(init_inline));
    }
    
    std::unique_ptr<Statement> flatten_statement() const override {
        auto init_flat = initializer ? initializer->flatten_expression() : nullptr;
        return std::make_unique<VariableStatement>(name, std::move(init_flat));
    }
    
    std::unordered_map<std::string, int> get_variable_usage() const override {
        auto usage = initializer ? initializer->get_variable_usage() : std::unordered_map<std::string, int>{};
        usage[name] = 1;
        return usage;
    }
    
    std::vector<std::string> get_free_variables() const override {
        return initializer ? initializer->get_free_variables() : std::vector<std::string>{};
    }
    
    std::vector<std::string> get_bound_variables() const override {
        return {name};
    }
    
    bool is_well_formed() const override { return !name.empty(); }
    std::vector<std::string> get_semantic_errors() const override {
        if (name.empty()) {
            return {"Empty variable name"};
        }
        return initializer ? initializer->get_semantic_errors() : std::vector<std::string>{};
    }
    
    std::unique_ptr<Statement> substitute(const std::string& var, const Expression& expr) const override {
        auto init_sub = initializer ? initializer->substitute(var, expr) : nullptr;
        return std::make_unique<VariableStatement>(name, std::move(init_sub));
    }
    
    std::unique_ptr<Statement> alpha_convert(const std::unordered_map<std::string, std::string>& mapping) const override {
        auto it = mapping.find(name);
        std::string new_name = it != mapping.end() ? it->second : name;
        auto init_conv = initializer ? initializer->alpha_convert(mapping) : nullptr;
        return std::make_unique<VariableStatement>(new_name, std::move(init_conv));
    }
    
    std::string get_canonical_form() const override {
        std::string result = "var " + name;
        if (initializer) {
            result += " = " + initializer->get_canonical_form();
        }
        return result;
    }
    
    std::string get_hash_string() const override {
        return name + (initializer ? initializer->get_hash_string() : "");
    }
    
    bool structural_equals(const Statement& other) const override {
        if (auto stmt = dynamic_cast<const VariableStatement*>(&other)) {
            if (name != stmt->name) return false;
            if (initializer && stmt->initializer) {
                return initializer->structural_equals(*stmt->initializer);
            }
            return !initializer && !stmt->initializer;
        }
        return false;
    }
    
    std::unique_ptr<Statement> apply_rules(const std::vector<std::pair<std::string, std::string>>& rules) const override {
        return clone_statement();
    }
    
    std::unique_ptr<Statement> apply_transformations(const std::vector<std::function<std::unique_ptr<Statement>(const Statement&)>>& transforms) const override {
        return clone_statement();
    }
    
    std::vector<std::string> get_control_flow_successors() const override { return {}; }
    std::vector<std::string> get_control_flow_predecessors() const override { return {}; }
    bool is_loop() const override { return false; }
    bool is_conditional() const override { return false; }
    bool is_jump() const override { return false; }
    
    bool has_side_effects() const override { return true; }
    std::vector<std::string> get_side_effects() const override { return {"variable_declaration"}; }
    
    std::unique_ptr<Statement> hoist_declarations() const override { return clone_statement(); }
    std::unique_ptr<Statement> eliminate_dead_code() const override { return clone_statement(); }
    std::unique_ptr<Statement> constant_fold() const override { return clone_statement(); }
    std::unique_ptr<Statement> strength_reduce() const override { return clone_statement(); }
    
    std::vector<std::string> get_labels() const override { return {}; }
    bool has_label(const std::string& label) const override { return false; }
    void add_label(const std::string& label) override {}
    void remove_label(const std::string& label) override {}
    
    std::unique_ptr<Statement> unroll_loops(int factor) const override { return clone_statement(); }
    std::unique_ptr<Statement> parallelize() const override { return clone_statement(); }
    std::unique_ptr<Statement> vectorize() const override { return clone_statement(); }
    
    bool is_pure() const override { return false; }
    bool is_deterministic() const override { return true; }
    bool is_idempotent() const override { return false; }
    bool is_commutative() const override { return false; }
    bool is_associative() const override { return false; }
    
    std::unique_ptr<Statement> refactor_extract_method(const std::string& method_name) const override {
        return clone_statement();
    }
    
    std::unique_ptr<Statement> refactor_inline_method(const std::string& method_name) const override {
        return clone_statement();
    }
    
    std::unique_ptr<Statement> refactor_rename_variable(const std::string& old_name, const std::string& new_name) const override {
        return clone_statement();
    }
    
    std::vector<std::string> get_code_smells() const override { return {}; }
    std::vector<std::string> get_refactoring_suggestions() const override { return {}; }
    double get_maintainability_score() const override { return 1.0; }
    
    std::unique_ptr<Statement> modernize() const override { return clone_statement(); }
    std::unique_ptr<Statement> apply_style_guide() const override { return clone_statement(); }
    std::unique_ptr<Statement> format_code() const override { return clone_statement(); }
    
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
    
    std::string get_node_type() const override { return "VariableStatement"; }
    std::string get_node_name() const override { return "variable_declaration"; }
    
private:
    mutable Metadata metadata_;
};

class FunctionStatement : public Statement {
public:
    std::string name;
    std::vector<std::string> parameters;
    std::vector<std::unique_ptr<Statement>> body;
    
    FunctionStatement(const std::string& name, const std::vector<std::string>& params, 
                     std::vector<std::unique_ptr<Statement>> body)
        : name(name), parameters(params), body(std::move(body)) {}
    
    void accept(ASTVisitor& visitor) override {}
    void accept(ConstASTVisitor& visitor) const override {}
    void accept(MutableASTVisitor& visitor) override {}
    
    std::unique_ptr<ASTNode> clone() const override {
        std::vector<std::unique_ptr<Statement>> cloned_body;
        for (const auto& stmt : body) {
            cloned_body.push_back(stmt->clone_statement());
        }
        return std::make_unique<FunctionStatement>(name, parameters, std::move(cloned_body));
    }
    
    std::string to_string() const override {
        std::string result = "func " + name + "(";
        for (size_t i = 0; i < parameters.size(); ++i) {
            if (i > 0) result += ", ";
            result += parameters[i];
        }
        result += ") {\n";
        for (const auto& stmt : body) {
            result += "  " + stmt->to_string() + "\n";
        }
        result += "}";
        return result;
    }
    
    std::size_t hash() const override {
        return std::hash<std::string>{}(name);
    }
    
    bool equals(const ASTNode& other) const override {
        if (auto stmt = dynamic_cast<const FunctionStatement*>(&other)) {
            if (name != stmt->name || parameters != stmt->parameters) return false;
            if (body.size() != stmt->body.size()) return false;
            for (size_t i = 0; i < body.size(); ++i) {
                if (!body[i]->equals(*stmt->body[i])) return false;
            }
            return true;
        }
        return false;
    }
    
    std::string serialize() const override {
        return "func_stmt:" + name;
    }
    
    void deserialize(const std::string& data) override {}
    
    std::vector<ASTNode*> get_children() override {
        std::vector<ASTNode*> children;
        for (const auto& stmt : body) {
            children.push_back(stmt.get());
        }
        return children;
    }
    
    std::vector<const ASTNode*> get_children() const override {
        std::vector<const ASTNode*> children;
        for (const auto& stmt : body) {
            children.push_back(stmt.get());
        }
        return children;
    }
    
    void execute() const override {}
    bool is_control_flow() const override { return false; }
    bool is_declaration() const override { return true; }
    bool is_expression_statement() const override { return false; }
    bool returns_value() const override { return false; }
    bool can_fallthrough() const override { return true; }
    
    std::vector<std::string> get_declared_variables() const override {
        std::vector<std::string> vars = {name};
        vars.insert(vars.end(), parameters.begin(), parameters.end());
        return vars;
    }
    
    std::vector<std::string> get_used_variables() const override {
        std::vector<std::string> vars;
        for (const auto& stmt : body) {
            auto stmt_vars = stmt->get_used_variables();
            vars.insert(vars.end(), stmt_vars.begin(), stmt_vars.end());
        }
        return vars;
    }
    
    std::vector<std::string> get_modified_variables() const override {
        std::vector<std::string> vars = {name};
        for (const auto& stmt : body) {
            auto stmt_vars = stmt->get_modified_variables();
            vars.insert(vars.end(), stmt_vars.begin(), stmt_vars.end());
        }
        return vars;
    }
    
    std::string get_statement_type() const override {
        return "function_declaration";
    }
    
    std::unique_ptr<Statement> clone_statement() const override {
        std::vector<std::unique_ptr<Statement>> cloned_body;
        for (const auto& stmt : body) {
            cloned_body.push_back(stmt->clone_statement());
        }
        return std::make_unique<FunctionStatement>(name, parameters, std::move(cloned_body));
    }
    
    std::string to_code() const override {
        return to_string();
    }
    
    std::vector<Statement*> get_substatements() override {
        std::vector<Statement*> stmts;
        for (const auto& stmt : body) {
            stmts.push_back(stmt.get());
        }
        return stmts;
    }
    
    std::vector<const Statement*> get_substatements() const override {
        std::vector<const Statement*> stmts;
        for (const auto& stmt : body) {
            stmts.push_back(stmt.get());
        }
        return stmts;
    }
    
    std::string to_javascript() const override { return to_code(); }
    std::string to_python() const override { return to_code(); }
    std::string to_cpp() const override { return to_code(); }
    std::string to_json() const override { return to_code(); }
    
    std::vector<std::string> get_required_imports() const override { return {}; }
    std::vector<std::string> get_required_libraries() const override { return {}; }
    
    double complexity() const override {
        double total = 2.0;
        for (const auto& stmt : body) {
            total += stmt->complexity();
        }
        return total;
    }
    
    size_t memory_usage() const override {
        size_t total = sizeof(FunctionStatement);
        for (const auto& stmt : body) {
            total += stmt->memory_usage();
        }
        return total;
    }
    
    size_t instruction_count() const override {
        size_t total = 2;
        for (const auto& stmt : body) {
            total += stmt->instruction_count();
        }
        return total;
    }
    
    bool is_unreachable() const override { return false; }
    bool is_dead_code() const override { return false; }
    std::vector<std::string> get_unreachable_statements() const override { return {}; }
    
    std::unique_ptr<Statement> optimize_statement() const override {
        std::vector<std::unique_ptr<Statement>> optimized_body;
        for (const auto& stmt : body) {
            optimized_body.push_back(stmt->optimize_statement());
        }
        return std::make_unique<FunctionStatement>(name, parameters, std::move(optimized_body));
    }
    
    std::unique_ptr<Statement> inline_statement() const override {
        std::vector<std::unique_ptr<Statement>> inlined_body;
        for (const auto& stmt : body) {
            inlined_body.push_back(stmt->inline_statement());
        }
        return std::make_unique<FunctionStatement>(name, parameters, std::move(inlined_body));
    }
    
    std::unique_ptr<Statement> flatten_statement() const override {
        std::vector<std::unique_ptr<Statement>> flattened_body;
        for (const auto& stmt : body) {
            flattened_body.push_back(stmt->flatten_statement());
        }
        return std::make_unique<FunctionStatement>(name, parameters, std::move(flattened_body));
    }
    
    std::unordered_map<std::string, int> get_variable_usage() const override {
        std::unordered_map<std::string, int> usage;
        usage[name] = 1;
        for (const auto& param : parameters) {
            usage[param] = 1;
        }
        for (const auto& stmt : body) {
            auto stmt_usage = stmt->get_variable_usage();
            for (const auto& [var, count] : stmt_usage) {
                usage[var] += count;
            }
        }
        return usage;
    }
    
    std::vector<std::string> get_free_variables() const override {
        std::vector<std::string> vars;
        for (const auto& stmt : body) {
            auto stmt_vars = stmt->get_free_variables();
            vars.insert(vars.end(), stmt_vars.begin(), stmt_vars.end());
        }
        return vars;
    }
    
    std::vector<std::string> get_bound_variables() const override {
        std::vector<std::string> vars = {name};
        vars.insert(vars.end(), parameters.begin(), parameters.end());
        return vars;
    }
    
    bool is_well_formed() const override { return !name.empty(); }
    std::vector<std::string> get_semantic_errors() const override {
        std::vector<std::string> errors;
        if (name.empty()) {
            errors.push_back("Empty function name");
        }
        for (const auto& stmt : body) {
            auto stmt_errors = stmt->get_semantic_errors();
            errors.insert(errors.end(), stmt_errors.begin(), stmt_errors.end());
        }
        return errors;
    }
    
    std::unique_ptr<Statement> substitute(const std::string& var, const Expression& expr) const override {
        std::vector<std::unique_ptr<Statement>> substituted_body;
        for (const auto& stmt : body) {
            substituted_body.push_back(stmt->substitute(var, expr));
        }
        return std::make_unique<FunctionStatement>(name, parameters, std::move(substituted_body));
    }
    
    std::unique_ptr<Statement> alpha_convert(const std::unordered_map<std::string, std::string>& mapping) const override {
        std::vector<std::unique_ptr<Statement>> converted_body;
        for (const auto& stmt : body) {
            converted_body.push_back(stmt->alpha_convert(mapping));
        }
        return std::make_unique<FunctionStatement>(name, parameters, std::move(converted_body));
    }
    
    std::string get_canonical_form() const override {
        return "func " + name + "(" + std::to_string(parameters.size()) + ")";
    }
    
    std::string get_hash_string() const override {
        return name + std::to_string(parameters.size());
    }
    
    bool structural_equals(const Statement& other) const override {
        if (auto stmt = dynamic_cast<const FunctionStatement*>(&other)) {
            if (name != stmt->name || parameters != stmt->parameters) return false;
            if (body.size() != stmt->body.size()) return false;
            for (size_t i = 0; i < body.size(); ++i) {
                if (!body[i]->structural_equals(*stmt->body[i])) return false;
            }
            return true;
        }
        return false;
    }
    
    std::unique_ptr<Statement> apply_rules(const std::vector<std::pair<std::string, std::string>>& rules) const override {
        return clone_statement();
    }
    
    std::unique_ptr<Statement> apply_transformations(const std::vector<std::function<std::unique_ptr<Statement>(const Statement&)>>& transforms) const override {
        return clone_statement();
    }
    
    std::vector<std::string> get_control_flow_successors() const override { return {}; }
    std::vector<std::string> get_control_flow_predecessors() const override { return {}; }
    bool is_loop() const override { return false; }
    bool is_conditional() const override { return false; }
    bool is_jump() const override { return false; }
    
    bool has_side_effects() const override { return true; }
    std::vector<std::string> get_side_effects() const override { return {"function_declaration"}; }
    
    std::unique_ptr<Statement> hoist_declarations() const override { return clone_statement(); }
    std::unique_ptr<Statement> eliminate_dead_code() const override { return clone_statement(); }
    std::unique_ptr<Statement> constant_fold() const override { return clone_statement(); }
    std::unique_ptr<Statement> strength_reduce() const override { return clone_statement(); }
    
    std::vector<std::string> get_labels() const override { return {}; }
    bool has_label(const std::string& label) const override { return false; }
    void add_label(const std::string& label) override {}
    void remove_label(const std::string& label) override {}
    
    std::unique_ptr<Statement> unroll_loops(int factor) const override { return clone_statement(); }
    std::unique_ptr<Statement> parallelize() const override { return clone_statement(); }
    std::unique_ptr<Statement> vectorize() const override { return clone_statement(); }
    
    bool is_pure() const override { return false; }
    bool is_deterministic() const override { return true; }
    bool is_idempotent() const override { return false; }
    bool is_commutative() const override { return false; }
    bool is_associative() const override { return false; }
    
    std::unique_ptr<Statement> refactor_extract_method(const std::string& method_name) const override {
        return clone_statement();
    }
    
    std::unique_ptr<Statement> refactor_inline_method(const std::string& method_name) const override {
        return clone_statement();
    }
    
    std::unique_ptr<Statement> refactor_rename_variable(const std::string& old_name, const std::string& new_name) const override {
        return clone_statement();
    }
    
    std::vector<std::string> get_code_smells() const override { return {}; }
    std::vector<std::string> get_refactoring_suggestions() const override { return {}; }
    double get_maintainability_score() const override { return 1.0; }
    
    std::unique_ptr<Statement> modernize() const override { return clone_statement(); }
    std::unique_ptr<Statement> apply_style_guide() const override { return clone_statement(); }
    std::unique_ptr<Statement> format_code() const override { return clone_statement(); }
    
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
    
    std::string get_node_type() const override { return "FunctionStatement"; }
    std::string get_node_name() const override { return "function_declaration"; }
    
private:
    mutable Metadata metadata_;
};

} 