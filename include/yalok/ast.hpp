#pragma once

#include "value.hpp"
#include <memory>
#include <vector>
#include <string>
#include <variant>
#include <concepts>
#include <type_traits>
#include <functional>
#include <optional>
#include <span>
#include <ranges>
#include <utility>
#include <typeindex>
#include <unordered_map>
#include <format>
#include <coroutine>
#include <generator>

namespace yalok {

template<typename T>
concept ASTNodeType = std::is_base_of_v<struct ASTNode, T>;

template<typename T>
concept Visitable = requires(T t) {
    t.accept(std::declval<auto&>());
};

template<typename T>
concept Visitor = requires(T visitor) {
    typename T::result_type;
};

template<typename T>
concept ExpressionType = std::is_base_of_v<struct Expression, T>;

template<typename T>
concept StatementType = std::is_base_of_v<struct Statement, T>;

template<typename T>
concept Cloneable = requires(T t) {
    { t.clone() } -> std::same_as<std::unique_ptr<T>>;
};

template<typename T>
concept Serializable = requires(T t) {
    { t.serialize() } -> std::convertible_to<std::string>;
};

template<typename T>
concept Hashable = requires(T t) {
    { t.hash() } -> std::convertible_to<std::size_t>;
};

class ASTVisitor;
class ConstASTVisitor;
class MutableASTVisitor;

struct ASTNode {
    virtual ~ASTNode() = default;
    virtual void accept(ASTVisitor& visitor) = 0;
    virtual void accept(ConstASTVisitor& visitor) const = 0;
    virtual void accept(MutableASTVisitor& visitor) = 0;
    virtual std::unique_ptr<ASTNode> clone() const = 0;
    virtual std::string to_string() const = 0;
    virtual std::size_t hash() const = 0;
    virtual bool equals(const ASTNode& other) const = 0;
    virtual std::string serialize() const = 0;
    virtual void deserialize(const std::string& data) = 0;
    
    template<typename T>
    T* as() {
        return dynamic_cast<T*>(this);
    }
    
    template<typename T>
    const T* as() const {
        return dynamic_cast<const T*>(this);
    }
    
    template<typename T>
    bool is() const {
        return dynamic_cast<const T*>(this) != nullptr;
    }
    
    std::type_index type_id() const {
        return std::type_index(typeid(*this));
    }
    
    virtual std::vector<ASTNode*> get_children() = 0;
    virtual std::vector<const ASTNode*> get_children() const = 0;
    
    template<typename F>
    void visit_children(F&& func) {
        for (auto child : get_children()) {
            if (child) func(*child);
        }
    }
    
    template<typename F>
    void visit_children(F&& func) const {
        for (auto child : get_children()) {
            if (child) func(*child);
        }
    }
    
    size_t depth() const {
        size_t max_depth = 0;
        for (auto child : get_children()) {
            if (child) {
                max_depth = std::max(max_depth, child->depth());
            }
        }
        return max_depth + 1;
    }
    
    size_t node_count() const {
        size_t count = 1;
        for (auto child : get_children()) {
            if (child) {
                count += child->node_count();
            }
        }
        return count;
    }
    
    std::generator<ASTNode*> nodes() {
        co_yield this;
        for (auto child : get_children()) {
            if (child) {
                for (auto node : child->nodes()) {
                    co_yield node;
                }
            }
        }
    }
    
    std::generator<const ASTNode*> nodes() const {
        co_yield this;
        for (auto child : get_children()) {
            if (child) {
                for (auto node : child->nodes()) {
                    co_yield node;
                }
            }
        }
    }
    
    template<typename T>
    std::generator<T*> nodes_of_type() {
        for (auto node : nodes()) {
            if (auto typed_node = node->as<T>()) {
                co_yield typed_node;
            }
        }
    }
    
    template<typename T>
    std::generator<const T*> nodes_of_type() const {
        for (auto node : nodes()) {
            if (auto typed_node = node->as<T>()) {
                co_yield typed_node;
            }
        }
    }
    
    template<typename Pred>
    std::generator<ASTNode*> nodes_matching(Pred&& predicate) {
        for (auto node : nodes()) {
            if (predicate(*node)) {
                co_yield node;
            }
        }
    }
    
    template<typename Pred>
    std::generator<const ASTNode*> nodes_matching(Pred&& predicate) const {
        for (auto node : nodes()) {
            if (predicate(*node)) {
                co_yield node;
            }
        }
    }
    
    template<typename T>
    std::optional<T*> find_first() {
        for (auto node : nodes_of_type<T>()) {
            return node;
        }
        return std::nullopt;
    }
    
    template<typename T>
    std::optional<const T*> find_first() const {
        for (auto node : nodes_of_type<T>()) {
            return node;
        }
        return std::nullopt;
    }
    
    template<typename T>
    std::vector<T*> find_all() {
        std::vector<T*> result;
        for (auto node : nodes_of_type<T>()) {
            result.push_back(node);
        }
        return result;
    }
    
    template<typename T>
    std::vector<const T*> find_all() const {
        std::vector<const T*> result;
        for (auto node : nodes_of_type<T>()) {
            result.push_back(node);
        }
        return result;
    }
    
    bool contains(const ASTNode& node) const {
        for (auto current : nodes()) {
            if (current == &node) {
                return true;
            }
        }
        return false;
    }
    
    template<typename T>
    bool contains_type() const {
        return find_first<T>().has_value();
    }
    
    std::string pretty_print(size_t indent = 0) const {
        std::string result;
        std::string indent_str(indent * 2, ' ');
        result += indent_str + to_string() + "\n";
        for (auto child : get_children()) {
            if (child) {
                result += child->pretty_print(indent + 1);
            }
        }
        return result;
    }
    
    virtual std::unordered_map<std::string, Value> get_attributes() const = 0;
    virtual void set_attribute(const std::string& name, const Value& value) = 0;
    virtual std::optional<Value> get_attribute(const std::string& name) const = 0;
    virtual bool has_attribute(const std::string& name) const = 0;
    virtual void remove_attribute(const std::string& name) = 0;
    
    struct Position {
        size_t line = 0;
        size_t column = 0;
        size_t position = 0;
        std::string filename;
        
        std::string to_string() const {
            return std::format("{}:{}:{}", filename.empty() ? "<unknown>" : filename, line, column);
        }
    };
    
    virtual Position get_position() const = 0;
    virtual void set_position(const Position& pos) = 0;
    
    struct Metadata {
        std::unordered_map<std::string, Value> attributes;
        Position position;
        std::string documentation;
        std::vector<std::string> annotations;
        
        template<typename T>
        void set(const std::string& key, T&& value) {
            attributes[key] = Value(std::forward<T>(value));
        }
        
        template<typename T>
        std::optional<T> get(const std::string& key) const {
            auto it = attributes.find(key);
            if (it != attributes.end()) {
                return it->second.try_cast<T>();
            }
            return std::nullopt;
        }
        
        bool has(const std::string& key) const {
            return attributes.find(key) != attributes.end();
        }
        
        void remove(const std::string& key) {
            attributes.erase(key);
        }
        
        void clear() {
            attributes.clear();
            documentation.clear();
            annotations.clear();
        }
        
        void add_annotation(const std::string& annotation) {
            annotations.push_back(annotation);
        }
        
        bool has_annotation(const std::string& annotation) const {
            return std::find(annotations.begin(), annotations.end(), annotation) != annotations.end();
        }
        
        void remove_annotation(const std::string& annotation) {
            annotations.erase(std::remove(annotations.begin(), annotations.end(), annotation), annotations.end());
        }
    };
    
    virtual Metadata& get_metadata() = 0;
    virtual const Metadata& get_metadata() const = 0;
    
    template<typename T>
    void set_metadata(const std::string& key, T&& value) {
        get_metadata().set(key, std::forward<T>(value));
    }
    
    template<typename T>
    std::optional<T> get_metadata(const std::string& key) const {
        return get_metadata().get<T>(key);
    }
    
    bool has_metadata(const std::string& key) const {
        return get_metadata().has(key);
    }
    
    void remove_metadata(const std::string& key) {
        get_metadata().remove(key);
    }
    
    void set_documentation(const std::string& doc) {
        get_metadata().documentation = doc;
    }
    
    const std::string& get_documentation() const {
        return get_metadata().documentation;
    }
    
    void add_annotation(const std::string& annotation) {
        get_metadata().add_annotation(annotation);
    }
    
    bool has_annotation(const std::string& annotation) const {
        return get_metadata().has_annotation(annotation);
    }
    
    void remove_annotation(const std::string& annotation) {
        get_metadata().remove_annotation(annotation);
    }
    
    virtual void validate() const = 0;
    virtual std::vector<std::string> get_validation_errors() const = 0;
    virtual bool is_valid() const = 0;
    
    template<typename T>
    std::unique_ptr<T> clone_as() const {
        auto cloned = clone();
        if (auto typed = dynamic_cast<T*>(cloned.get())) {
            cloned.release();
            return std::unique_ptr<T>(typed);
        }
        return nullptr;
    }
    
    virtual void optimize() = 0;
    virtual bool is_optimized() const = 0;
    virtual void mark_dirty() = 0;
    virtual bool is_dirty() const = 0;
    
    template<typename T>
    T* get_parent() const {
        return dynamic_cast<T*>(parent_);
    }
    
    ASTNode* get_parent() const { return parent_; }
    void set_parent(ASTNode* parent) { parent_ = parent; }
    
    std::vector<ASTNode*> get_siblings() const {
        if (!parent_) return {};
        auto siblings = parent_->get_children();
        siblings.erase(std::remove(siblings.begin(), siblings.end(), this), siblings.end());
        return siblings;
    }
    
    template<typename T>
    std::vector<T*> get_siblings_of_type() const {
        std::vector<T*> result;
        for (auto sibling : get_siblings()) {
            if (auto typed = sibling->as<T>()) {
                result.push_back(typed);
            }
        }
        return result;
    }
    
    size_t get_index() const {
        if (!parent_) return 0;
        auto children = parent_->get_children();
        auto it = std::find(children.begin(), children.end(), this);
        return it != children.end() ? std::distance(children.begin(), it) : 0;
    }
    
    bool is_first_child() const {
        return get_index() == 0;
    }
    
    bool is_last_child() const {
        if (!parent_) return true;
        return get_index() == parent_->get_children().size() - 1;
    }
    
    ASTNode* get_next_sibling() const {
        if (!parent_) return nullptr;
        auto children = parent_->get_children();
        auto index = get_index();
        return (index + 1 < children.size()) ? children[index + 1] : nullptr;
    }
    
    ASTNode* get_prev_sibling() const {
        if (!parent_) return nullptr;
        auto children = parent_->get_children();
        auto index = get_index();
        return (index > 0) ? children[index - 1] : nullptr;
    }
    
    std::vector<ASTNode*> get_ancestors() const {
        std::vector<ASTNode*> ancestors;
        ASTNode* current = parent_;
        while (current) {
            ancestors.push_back(current);
            current = current->parent_;
        }
        return ancestors;
    }
    
    template<typename T>
    T* find_ancestor() const {
        for (auto ancestor : get_ancestors()) {
            if (auto typed = ancestor->as<T>()) {
                return typed;
            }
        }
        return nullptr;
    }
    
    ASTNode* get_root() const {
        ASTNode* current = const_cast<ASTNode*>(this);
        while (current->parent_) {
            current = current->parent_;
        }
        return current;
    }
    
    bool is_root() const {
        return parent_ == nullptr;
    }
    
    bool is_leaf() const {
        return get_children().empty();
    }
    
    bool is_ancestor_of(const ASTNode& node) const {
        return node.find_ancestor<ASTNode>() == this;
    }
    
    bool is_descendant_of(const ASTNode& node) const {
        return find_ancestor<ASTNode>() == &node;
    }
    
    template<typename Func>
    void transform_children(Func&& func) {
        for (auto& child : get_children()) {
            if (child) {
                func(*child);
            }
        }
    }
    
    template<typename Func>
    void transform_descendants(Func&& func) {
        for (auto node : nodes()) {
            if (node != this) {
                func(*node);
            }
        }
    }
    
    template<typename Pred>
    bool any_child(Pred&& predicate) const {
        for (auto child : get_children()) {
            if (child && predicate(*child)) {
                return true;
            }
        }
        return false;
    }
    
    template<typename Pred>
    bool all_children(Pred&& predicate) const {
        for (auto child : get_children()) {
            if (child && !predicate(*child)) {
                return false;
            }
        }
        return true;
    }
    
    template<typename Pred>
    bool any_descendant(Pred&& predicate) const {
        for (auto node : nodes()) {
            if (node != this && predicate(*node)) {
                return true;
            }
        }
        return false;
    }
    
    template<typename Pred>
    bool all_descendants(Pred&& predicate) const {
        for (auto node : nodes()) {
            if (node != this && !predicate(*node)) {
                return false;
            }
        }
        return true;
    }
    
    virtual std::string get_node_type() const = 0;
    virtual std::string get_node_name() const = 0;
    
    template<typename T>
    static std::unique_ptr<T> create() {
        return std::make_unique<T>();
    }
    
    template<typename T, typename... Args>
    static std::unique_ptr<T> create(Args&&... args) {
        return std::make_unique<T>(std::forward<Args>(args)...);
    }
    
protected:
    ASTNode* parent_ = nullptr;
    mutable Metadata metadata_;
    mutable bool dirty_ = true;
    mutable bool optimized_ = false;
};

template<typename Derived>
class ASTNodeCRTP : public ASTNode {
public:
    std::unique_ptr<ASTNode> clone() const override {
        return std::make_unique<Derived>(static_cast<const Derived&>(*this));
    }
    
    std::string get_node_type() const override {
        return typeid(Derived).name();
    }
    
    std::string get_node_name() const override {
        return static_cast<const Derived*>(this)->node_name();
    }
    
    std::size_t hash() const override {
        return static_cast<const Derived*>(this)->compute_hash();
    }
    
    bool equals(const ASTNode& other) const override {
        if (auto typed_other = other.as<Derived>()) {
            return static_cast<const Derived*>(this)->equals_impl(*typed_other);
        }
        return false;
    }
    
    std::string serialize() const override {
        return static_cast<const Derived*>(this)->serialize_impl();
    }
    
    void deserialize(const std::string& data) override {
        static_cast<Derived*>(this)->deserialize_impl(data);
    }
    
    void validate() const override {
        static_cast<const Derived*>(this)->validate_impl();
    }
    
    std::vector<std::string> get_validation_errors() const override {
        return static_cast<const Derived*>(this)->get_validation_errors_impl();
    }
    
    bool is_valid() const override {
        return static_cast<const Derived*>(this)->is_valid_impl();
    }
    
    void optimize() override {
        static_cast<Derived*>(this)->optimize_impl();
        optimized_ = true;
        dirty_ = false;
    }
    
    bool is_optimized() const override {
        return optimized_;
    }
    
    void mark_dirty() override {
        dirty_ = true;
        optimized_ = false;
    }
    
    bool is_dirty() const override {
        return dirty_;
    }
    
    Metadata& get_metadata() override {
        return metadata_;
    }
    
    const Metadata& get_metadata() const override {
        return metadata_;
    }
    
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
};

struct Expression : ASTNode {
    virtual ~Expression() = default;
    virtual Value evaluate() const = 0;
    virtual bool is_constant() const = 0;
    virtual bool is_pure() const = 0;
    virtual std::vector<std::string> get_dependencies() const = 0;
    virtual void replace_dependency(const std::string& old_name, const std::string& new_name) = 0;
    virtual std::unique_ptr<Expression> simplify() const = 0;
    virtual std::unique_ptr<Expression> optimize_expression() const = 0;
    virtual bool has_side_effects() const = 0;
    virtual std::string get_expression_type() const = 0;
    virtual int get_precedence() const = 0;
    virtual bool is_left_associative() const = 0;
    virtual std::string to_code() const = 0;
    
    template<typename T>
    T* as_expression() {
        return dynamic_cast<T*>(this);
    }
    
    template<typename T>
    const T* as_expression() const {
        return dynamic_cast<const T*>(this);
    }
    
    template<typename T>
    bool is_expression() const {
        return dynamic_cast<const T*>(this) != nullptr;
    }
    
    bool is_literal() const {
        return is_constant() && !has_side_effects();
    }
    
    bool is_variable() const {
        return get_expression_type() == "variable";
    }
    
    bool is_call() const {
        return get_expression_type() == "call";
    }
    
    bool is_binary_op() const {
        return get_expression_type() == "binary_op";
    }
    
    bool is_unary_op() const {
        return get_expression_type() == "unary_op";
    }
    
    virtual std::vector<Expression*> get_subexpressions() = 0;
    virtual std::vector<const Expression*> get_subexpressions() const = 0;
    
    template<typename Func>
    void transform_subexpressions(Func&& func) {
        for (auto& subexpr : get_subexpressions()) {
            if (subexpr) {
                func(*subexpr);
            }
        }
    }
    
    template<typename Pred>
    bool any_subexpression(Pred&& predicate) const {
        for (auto subexpr : get_subexpressions()) {
            if (subexpr && predicate(*subexpr)) {
                return true;
            }
        }
        return false;
    }
    
    template<typename Pred>
    bool all_subexpressions(Pred&& predicate) const {
        for (auto subexpr : get_subexpressions()) {
            if (subexpr && !predicate(*subexpr)) {
                return false;
            }
        }
        return true;
    }
    
    std::generator<Expression*> expressions() {
        co_yield this;
        for (auto subexpr : get_subexpressions()) {
            if (subexpr) {
                for (auto expr : subexpr->expressions()) {
                    co_yield expr;
                }
            }
        }
    }
    
    std::generator<const Expression*> expressions() const {
        co_yield this;
        for (auto subexpr : get_subexpressions()) {
            if (subexpr) {
                for (auto expr : subexpr->expressions()) {
                    co_yield expr;
                }
            }
        }
    }
    
    template<typename T>
    std::vector<T*> find_expressions() {
        std::vector<T*> result;
        for (auto expr : expressions()) {
            if (auto typed = expr->as_expression<T>()) {
                result.push_back(typed);
            }
        }
        return result;
    }
    
    template<typename T>
    std::vector<const T*> find_expressions() const {
        std::vector<const T*> result;
        for (auto expr : expressions()) {
            if (auto typed = expr->as_expression<T>()) {
                result.push_back(typed);
            }
        }
        return result;
    }
    
    virtual bool contains_expression(const Expression& expr) const {
        for (auto current : expressions()) {
            if (current == &expr) {
                return true;
            }
        }
        return false;
    }
    
    virtual std::unique_ptr<Expression> clone_expression() const = 0;
    
    template<typename T>
    std::unique_ptr<T> clone_as_expression() const {
        auto cloned = clone_expression();
        if (auto typed = dynamic_cast<T*>(cloned.get())) {
            cloned.release();
            return std::unique_ptr<T>(typed);
        }
        return nullptr;
    }
    
    virtual std::string get_return_type() const = 0;
    virtual bool is_type_compatible(const std::string& type) const = 0;
    virtual std::vector<std::string> get_possible_types() const = 0;
    
    bool is_numeric() const {
        auto type = get_return_type();
        return type == "int" || type == "float" || type == "number";
    }
    
    bool is_string() const {
        return get_return_type() == "string";
    }
    
    bool is_boolean() const {
        return get_return_type() == "bool";
    }
    
    bool is_array() const {
        return get_return_type() == "array";
    }
    
    bool is_object() const {
        return get_return_type() == "object";
    }
    
    bool is_function() const {
        return get_return_type() == "function";
    }
    
    virtual std::optional<Value> try_evaluate() const {
        try {
            return evaluate();
        } catch (...) {
            return std::nullopt;
        }
    }
    
    virtual std::string to_javascript() const = 0;
    virtual std::string to_python() const = 0;
    virtual std::string to_cpp() const = 0;
    virtual std::string to_json() const = 0;
    
    virtual std::vector<std::string> get_required_imports() const = 0;
    virtual std::vector<std::string> get_required_libraries() const = 0;
    
    virtual double complexity() const = 0;
    virtual size_t memory_usage() const = 0;
    virtual size_t instruction_count() const = 0;
    
    virtual bool is_tail_recursive() const = 0;
    virtual bool is_recursive() const = 0;
    virtual std::vector<std::string> get_recursive_calls() const = 0;
    
    virtual std::unique_ptr<Expression> inline_expression() const = 0;
    virtual std::unique_ptr<Expression> flatten_expression() const = 0;
    virtual std::unique_ptr<Expression> normalize_expression() const = 0;
    
    virtual std::unordered_map<std::string, int> get_variable_usage() const = 0;
    virtual std::vector<std::string> get_free_variables() const = 0;
    virtual std::vector<std::string> get_bound_variables() const = 0;
    
    virtual bool is_well_formed() const = 0;
    virtual std::vector<std::string> get_semantic_errors() const = 0;
    
    virtual std::unique_ptr<Expression> substitute(const std::string& var, const Expression& expr) const = 0;
    virtual std::unique_ptr<Expression> alpha_convert(const std::unordered_map<std::string, std::string>& mapping) const = 0;
    virtual std::unique_ptr<Expression> beta_reduce() const = 0;
    virtual std::unique_ptr<Expression> eta_convert() const = 0;
    
    virtual bool is_reducible() const = 0;
    virtual std::unique_ptr<Expression> reduce() const = 0;
    virtual std::unique_ptr<Expression> normalize() const = 0;
    
    virtual std::string get_canonical_form() const = 0;
    virtual std::string get_hash_string() const = 0;
    virtual bool structural_equals(const Expression& other) const = 0;
    
    template<typename Visitor>
    auto accept_expression_visitor(Visitor&& visitor) const {
        return visitor(*this);
    }
    
    template<typename Visitor>
    auto accept_expression_visitor(Visitor&& visitor) {
        return visitor(*this);
    }
    
    virtual std::unique_ptr<Expression> differentiate(const std::string& var) const = 0;
    virtual std::unique_ptr<Expression> integrate(const std::string& var) const = 0;
    virtual std::unique_ptr<Expression> partial_derivative(const std::string& var) const = 0;
    
    virtual std::unique_ptr<Expression> apply_rules(const std::vector<std::pair<std::string, std::string>>& rules) const = 0;
    virtual std::unique_ptr<Expression> apply_transformations(const std::vector<std::function<std::unique_ptr<Expression>(const Expression&)>>& transforms) const = 0;
};

struct Statement : ASTNode {
    virtual ~Statement() = default;
    virtual void execute() const = 0;
    virtual bool is_control_flow() const = 0;
    virtual bool is_declaration() const = 0;
    virtual bool is_expression_statement() const = 0;
    virtual bool returns_value() const = 0;
    virtual bool can_fallthrough() const = 0;
    virtual std::vector<std::string> get_declared_variables() const = 0;
    virtual std::vector<std::string> get_used_variables() const = 0;
    virtual std::vector<std::string> get_modified_variables() const = 0;
    virtual std::string get_statement_type() const = 0;
    virtual std::unique_ptr<Statement> clone_statement() const = 0;
    virtual std::string to_code() const = 0;
    
    template<typename T>
    T* as_statement() {
        return dynamic_cast<T*>(this);
    }
    
    template<typename T>
    const T* as_statement() const {
        return dynamic_cast<const T*>(this);
    }
    
    template<typename T>
    bool is_statement() const {
        return dynamic_cast<const T*>(this) != nullptr;
    }
    
    bool is_block() const {
        return get_statement_type() == "block";
    }
    
    bool is_if() const {
        return get_statement_type() == "if";
    }
    
    bool is_while() const {
        return get_statement_type() == "while";
    }
    
    bool is_for() const {
        return get_statement_type() == "for";
    }
    
    bool is_return() const {
        return get_statement_type() == "return";
    }
    
    bool is_break() const {
        return get_statement_type() == "break";
    }
    
    bool is_continue() const {
        return get_statement_type() == "continue";
    }
    
    bool is_assignment() const {
        return get_statement_type() == "assignment";
    }
    
    bool is_function_declaration() const {
        return get_statement_type() == "function_declaration";
    }
    
    bool is_variable_declaration() const {
        return get_statement_type() == "variable_declaration";
    }
    
    virtual std::vector<Statement*> get_substatements() = 0;
    virtual std::vector<const Statement*> get_substatements() const = 0;
    
    template<typename Func>
    void transform_substatements(Func&& func) {
        for (auto& substmt : get_substatements()) {
            if (substmt) {
                func(*substmt);
            }
        }
    }
    
    template<typename Pred>
    bool any_substatement(Pred&& predicate) const {
        for (auto substmt : get_substatements()) {
            if (substmt && predicate(*substmt)) {
                return true;
            }
        }
        return false;
    }
    
    template<typename Pred>
    bool all_substatements(Pred&& predicate) const {
        for (auto substmt : get_substatements()) {
            if (substmt && !predicate(*substmt)) {
                return false;
            }
        }
        return true;
    }
    
    std::generator<Statement*> statements() {
        co_yield this;
        for (auto substmt : get_substatements()) {
            if (substmt) {
                for (auto stmt : substmt->statements()) {
                    co_yield stmt;
                }
            }
        }
    }
    
    std::generator<const Statement*> statements() const {
        co_yield this;
        for (auto substmt : get_substatements()) {
            if (substmt) {
                for (auto stmt : substmt->statements()) {
                    co_yield stmt;
                }
            }
        }
    }
    
    template<typename T>
    std::vector<T*> find_statements() {
        std::vector<T*> result;
        for (auto stmt : statements()) {
            if (auto typed = stmt->as_statement<T>()) {
                result.push_back(typed);
            }
        }
        return result;
    }
    
    template<typename T>
    std::vector<const T*> find_statements() const {
        std::vector<const T*> result;
        for (auto stmt : statements()) {
            if (auto typed = stmt->as_statement<T>()) {
                result.push_back(typed);
            }
        }
        return result;
    }
    
    virtual bool contains_statement(const Statement& stmt) const {
        for (auto current : statements()) {
            if (current == &stmt) {
                return true;
            }
        }
        return false;
    }
    
    template<typename T>
    std::unique_ptr<T> clone_as_statement() const {
        auto cloned = clone_statement();
        if (auto typed = dynamic_cast<T*>(cloned.get())) {
            cloned.release();
            return std::unique_ptr<T>(typed);
        }
        return nullptr;
    }
    
    virtual std::string to_javascript() const = 0;
    virtual std::string to_python() const = 0;
    virtual std::string to_cpp() const = 0;
    virtual std::string to_json() const = 0;
    
    virtual std::vector<std::string> get_required_imports() const = 0;
    virtual std::vector<std::string> get_required_libraries() const = 0;
    
    virtual double complexity() const = 0;
    virtual size_t memory_usage() const = 0;
    virtual size_t instruction_count() const = 0;
    
    virtual bool is_unreachable() const = 0;
    virtual bool is_dead_code() const = 0;
    virtual std::vector<std::string> get_unreachable_statements() const = 0;
    
    virtual std::unique_ptr<Statement> optimize_statement() const = 0;
    virtual std::unique_ptr<Statement> inline_statement() const = 0;
    virtual std::unique_ptr<Statement> flatten_statement() const = 0;
    
    virtual std::unordered_map<std::string, int> get_variable_usage() const = 0;
    virtual std::vector<std::string> get_free_variables() const = 0;
    virtual std::vector<std::string> get_bound_variables() const = 0;
    
    virtual bool is_well_formed() const = 0;
    virtual std::vector<std::string> get_semantic_errors() const = 0;
    
    virtual std::unique_ptr<Statement> substitute(const std::string& var, const Expression& expr) const = 0;
    virtual std::unique_ptr<Statement> alpha_convert(const std::unordered_map<std::string, std::string>& mapping) const = 0;
    
    virtual std::string get_canonical_form() const = 0;
    virtual std::string get_hash_string() const = 0;
    virtual bool structural_equals(const Statement& other) const = 0;
    
    template<typename Visitor>
    auto accept_statement_visitor(Visitor&& visitor) const {
        return visitor(*this);
    }
    
    template<typename Visitor>
    auto accept_statement_visitor(Visitor&& visitor) {
        return visitor(*this);
    }
    
    virtual std::unique_ptr<Statement> apply_rules(const std::vector<std::pair<std::string, std::string>>& rules) const = 0;
    virtual std::unique_ptr<Statement> apply_transformations(const std::vector<std::function<std::unique_ptr<Statement>(const Statement&)>>& transforms) const = 0;
    
    virtual std::vector<std::string> get_control_flow_successors() const = 0;
    virtual std::vector<std::string> get_control_flow_predecessors() const = 0;
    virtual bool is_loop() const = 0;
    virtual bool is_conditional() const = 0;
    virtual bool is_jump() const = 0;
    
    virtual std::optional<Value> try_execute() const {
        try {
            execute();
            return Value();
        } catch (...) {
            return std::nullopt;
        }
    }
    
    virtual bool has_side_effects() const = 0;
    virtual std::vector<std::string> get_side_effects() const = 0;
    
    virtual std::unique_ptr<Statement> hoist_declarations() const = 0;
    virtual std::unique_ptr<Statement> eliminate_dead_code() const = 0;
    virtual std::unique_ptr<Statement> constant_fold() const = 0;
    virtual std::unique_ptr<Statement> strength_reduce() const = 0;
    
    virtual std::vector<std::string> get_labels() const = 0;
    virtual bool has_label(const std::string& label) const = 0;
    virtual void add_label(const std::string& label) = 0;
    virtual void remove_label(const std::string& label) = 0;
    
    virtual std::unique_ptr<Statement> unroll_loops(int factor) const = 0;
    virtual std::unique_ptr<Statement> parallelize() const = 0;
    virtual std::unique_ptr<Statement> vectorize() const = 0;
    
    virtual bool is_pure() const = 0;
    virtual bool is_deterministic() const = 0;
    virtual bool is_idempotent() const = 0;
    virtual bool is_commutative() const = 0;
    virtual bool is_associative() const = 0;
    
    virtual std::unique_ptr<Statement> refactor_extract_method(const std::string& method_name) const = 0;
    virtual std::unique_ptr<Statement> refactor_inline_method(const std::string& method_name) const = 0;
    virtual std::unique_ptr<Statement> refactor_rename_variable(const std::string& old_name, const std::string& new_name) const = 0;
    
    virtual std::vector<std::string> get_code_smells() const = 0;
    virtual std::vector<std::string> get_refactoring_suggestions() const = 0;
    virtual double get_maintainability_score() const = 0;
    
    virtual std::unique_ptr<Statement> modernize() const = 0;
    virtual std::unique_ptr<Statement> apply_style_guide() const = 0;
    virtual std::unique_ptr<Statement> format_code() const = 0;
};

using ExpressionPtr = std::unique_ptr<Expression>;
using StatementPtr = std::unique_ptr<Statement>;
using ASTNodePtr = std::unique_ptr<ASTNode>;

template<typename T>
using ASTPtr = std::unique_ptr<T>;

template<typename T>
concept ASTPointer = std::is_same_v<T, std::unique_ptr<typename T::element_type>> && 
                     std::is_base_of_v<ASTNode, typename T::element_type>;

template<ASTPointer T>
class ASTContainer {
private:
    std::vector<T> nodes_;
    
public:
    void add(T node) {
        if (node) {
            nodes_.push_back(std::move(node));
        }
    }
    
    template<typename U, typename... Args>
    void emplace(Args&&... args) {
        nodes_.emplace_back(std::make_unique<U>(std::forward<Args>(args)...));
    }
    
    T& operator[](size_t index) {
        return nodes_[index];
    }
    
    const T& operator[](size_t index) const {
        return nodes_[index];
    }
    
    size_t size() const {
        return nodes_.size();
    }
    
    bool empty() const {
        return nodes_.empty();
    }
    
    void clear() {
        nodes_.clear();
    }
    
    auto begin() { return nodes_.begin(); }
    auto end() { return nodes_.end(); }
    auto begin() const { return nodes_.begin(); }
    auto end() const { return nodes_.end(); }
    
    template<typename Pred>
    auto filter(Pred&& predicate) const {
        ASTContainer<T> result;
        for (const auto& node : nodes_) {
            if (predicate(*node)) {
                result.add(node->clone());
            }
        }
        return result;
    }
    
    template<typename Func>
    void transform(Func&& func) {
        for (auto& node : nodes_) {
            func(*node);
        }
    }
    
    template<typename U>
    std::vector<U*> find_nodes() const {
        std::vector<U*> result;
        for (const auto& node : nodes_) {
            if (auto typed = node->template as<U>()) {
                result.push_back(typed);
            }
        }
        return result;
    }
    
    template<typename U>
    std::optional<U*> find_first() const {
        for (const auto& node : nodes_) {
            if (auto typed = node->template as<U>()) {
                return typed;
            }
        }
        return std::nullopt;
    }
    
    template<typename Pred>
    std::optional<T*> find_first_matching(Pred&& predicate) const {
        for (const auto& node : nodes_) {
            if (predicate(*node)) {
                return node.get();
            }
        }
        return std::nullopt;
    }
    
    std::vector<T> take() {
        return std::move(nodes_);
    }
    
    void reserve(size_t capacity) {
        nodes_.reserve(capacity);
    }
    
    void shrink_to_fit() {
        nodes_.shrink_to_fit();
    }
    
    template<typename Compare>
    void sort(Compare&& comp) {
        std::sort(nodes_.begin(), nodes_.end(), [&](const T& a, const T& b) {
            return comp(*a, *b);
        });
    }
    
    void remove_if(std::function<bool(const typename T::element_type&)> predicate) {
        nodes_.erase(std::remove_if(nodes_.begin(), nodes_.end(),
            [&](const T& node) { return predicate(*node); }), nodes_.end());
    }
    
    ASTContainer<T> clone() const {
        ASTContainer<T> result;
        for (const auto& node : nodes_) {
            result.add(node->clone());
        }
        return result;
    }
    
    std::string to_string() const {
        std::string result;
        for (const auto& node : nodes_) {
            result += node->to_string() + "\n";
        }
        return result;
    }
    
    void validate() const {
        for (const auto& node : nodes_) {
            node->validate();
        }
    }
    
    void optimize() {
        for (auto& node : nodes_) {
            node->optimize();
        }
    }
    
    void mark_dirty() {
        for (auto& node : nodes_) {
            node->mark_dirty();
        }
    }
    
    size_t total_node_count() const {
        size_t count = 0;
        for (const auto& node : nodes_) {
            count += node->node_count();
        }
        return count;
    }
    
    size_t max_depth() const {
        size_t max_d = 0;
        for (const auto& node : nodes_) {
            max_d = std::max(max_d, node->depth());
        }
        return max_d;
    }
    
    template<typename Visitor>
    void accept_all(Visitor&& visitor) {
        for (auto& node : nodes_) {
            node->accept(visitor);
        }
    }
    
    template<typename Visitor>
    void accept_all(Visitor&& visitor) const {
        for (const auto& node : nodes_) {
            node->accept(visitor);
        }
    }
    
    std::generator<typename T::element_type*> all_nodes() {
        for (auto& node : nodes_) {
            for (auto n : node->nodes()) {
                co_yield n;
            }
        }
    }
    
    std::generator<const typename T::element_type*> all_nodes() const {
        for (const auto& node : nodes_) {
            for (auto n : node->nodes()) {
                co_yield n;
            }
        }
    }
};

using ExpressionContainer = ASTContainer<ExpressionPtr>;
using StatementContainer = ASTContainer<StatementPtr>;
using ASTNodeContainer = ASTContainer<ASTNodePtr>;

template<typename T>
class ASTBuilder {
private:
    ASTContainer<std::unique_ptr<T>> container_;
    
public:
    template<typename U, typename... Args>
    ASTBuilder& add(Args&&... args) {
        container_.template emplace<U>(std::forward<Args>(args)...);
        return *this;
    }
    
    ASTBuilder& add_node(std::unique_ptr<T> node) {
        container_.add(std::move(node));
        return *this;
    }
    
    ASTContainer<std::unique_ptr<T>> build() {
        return std::move(container_);
    }
    
    size_t size() const {
        return container_.size();
    }
    
    bool empty() const {
        return container_.empty();
    }
    
    void clear() {
        container_.clear();
    }
    
    template<typename Pred>
    ASTBuilder& filter(Pred&& predicate) {
        container_.remove_if([&](const T& node) { return !predicate(node); });
        return *this;
    }
    
    template<typename Func>
    ASTBuilder& transform(Func&& func) {
        container_.transform(func);
        return *this;
    }
    
    ASTBuilder& validate() {
        container_.validate();
        return *this;
    }
    
    ASTBuilder& optimize() {
        container_.optimize();
        return *this;
    }
    
    template<typename Compare>
    ASTBuilder& sort(Compare&& comp) {
        container_.sort(comp);
        return *this;
    }
    
    ASTBuilder& reserve(size_t capacity) {
        container_.reserve(capacity);
        return *this;
    }
};

using ExpressionBuilder = ASTBuilder<Expression>;
using StatementBuilder = ASTBuilder<Statement>;
using ASTNodeBuilder = ASTBuilder<ASTNode>;

template<typename T>
class ASTFactory {
public:
    template<typename U, typename... Args>
    static std::unique_ptr<U> create(Args&&... args) {
        return std::make_unique<U>(std::forward<Args>(args)...);
    }
    
    template<typename U>
    static std::unique_ptr<U> clone(const U& node) {
        return node.clone_as<U>();
    }
    
    template<typename U>
    static std::unique_ptr<T> cast(std::unique_ptr<U> node) {
        if (auto casted = dynamic_cast<T*>(node.get())) {
            node.release();
            return std::unique_ptr<T>(casted);
        }
        return nullptr;
    }
    
    template<typename U>
    static std::vector<std::unique_ptr<U>> create_vector(size_t count) {
        std::vector<std::unique_ptr<U>> result;
        result.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            result.push_back(std::make_unique<U>());
        }
        return result;
    }
    
    template<typename U, typename... Args>
    static ASTContainer<std::unique_ptr<U>> create_container(Args&&... args) {
        ASTContainer<std::unique_ptr<U>> container;
        (container.template emplace<U>(std::forward<Args>(args)), ...);
        return container;
    }
    
    template<typename U>
    static ASTBuilder<U> create_builder() {
        return ASTBuilder<U>();
    }
};

using ExpressionFactory = ASTFactory<Expression>;
using StatementFactory = ASTFactory<Statement>;
using ASTNodeFactory = ASTFactory<ASTNode>;

template<typename T>
class ASTRegistry {
private:
    std::unordered_map<std::string, std::function<std::unique_ptr<T>()>> creators_;
    std::unordered_map<std::string, std::function<std::unique_ptr<T>(const std::string&)>> deserializers_;
    
public:
    template<typename U>
    void register_type(const std::string& name) {
        creators_[name] = []() { return std::make_unique<U>(); };
        deserializers_[name] = [](const std::string& data) {
            auto node = std::make_unique<U>();
            node->deserialize(data);
            return node;
        };
    }
    
    std::unique_ptr<T> create(const std::string& type_name) {
        auto it = creators_.find(type_name);
        if (it != creators_.end()) {
            return it->second();
        }
        return nullptr;
    }
    
    std::unique_ptr<T> deserialize(const std::string& type_name, const std::string& data) {
        auto it = deserializers_.find(type_name);
        if (it != deserializers_.end()) {
            return it->second(data);
        }
        return nullptr;
    }
    
    std::vector<std::string> get_registered_types() const {
        std::vector<std::string> types;
        for (const auto& [name, _] : creators_) {
            types.push_back(name);
        }
        return types;
    }
    
    bool is_registered(const std::string& type_name) const {
        return creators_.find(type_name) != creators_.end();
    }
    
    void clear() {
        creators_.clear();
        deserializers_.clear();
    }
};

using ExpressionRegistry = ASTRegistry<Expression>;
using StatementRegistry = ASTRegistry<Statement>;
using ASTNodeRegistry = ASTRegistry<ASTNode>;

}

#include "ast_nodes.hpp"
#include "ast_statements.hpp" 