#pragma once

#include "lexer.hpp"
#include "parser.hpp"
#include "interpreter.hpp"
#include "memory.hpp"
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <iostream>
#include <map>

namespace yalok {

struct CompilerOptions {
    bool debug_mode = false;
    bool optimize = true;
    bool show_tokens = false;
    bool show_ast = false;
    bool show_memory_stats = false;
    bool benchmark = false;
    std::string output_file = "";
    std::vector<std::string> include_paths;
};

class ErrorReporter {
private:
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    bool has_errors = false;
    
public:
    void report_error(const std::string& message, int line = -1, int column = -1);
    void report_warning(const std::string& message, int line = -1, int column = -1);
    
    void print_errors() const;
    void print_warnings() const;
    
    bool has_any_errors() const { return has_errors; }
    size_t get_error_count() const { return errors.size(); }
    size_t get_warning_count() const { return warnings.size(); }
    
    void clear();
};

class Compiler {
private:
    std::unique_ptr<Lexer> lexer;
    std::unique_ptr<Parser> parser;
    std::unique_ptr<Interpreter> interpreter;
    std::unique_ptr<ErrorReporter> error_reporter;
    CompilerOptions options;
    
    void print_tokens(const std::vector<Token>& tokens);
    void print_ast(const std::vector<std::unique_ptr<Statement>>& statements);
    void print_benchmark_results(const std::chrono::microseconds& execution_time);
    
public:
    Compiler(const CompilerOptions& opts = CompilerOptions{});
    ~Compiler();
    
    bool compile_file(const std::string& filename);
    bool compile_string(const std::string& source);
    
    bool run_file(const std::string& filename);
    bool run_string(const std::string& source);
    
    void interactive_mode();
    void repl();
    
    void set_options(const CompilerOptions& opts) { options = opts; }
    CompilerOptions get_options() const { return options; }
    
    ErrorReporter& get_error_reporter() { return *error_reporter; }
    
    void reset();
    void cleanup();
};

class YalokRuntime {
private:
    static std::unique_ptr<Compiler> compiler_instance;
    static std::unique_ptr<MemoryManager> memory_manager;
    
public:
    static void initialize(const CompilerOptions& options = CompilerOptions{});
    static void shutdown();
    
    static Compiler& get_compiler();
    static MemoryManager& get_memory_manager();
    
    static bool is_initialized();
    static void print_version();
    static void print_help();
};

class ModuleLoader {
private:
    std::map<std::string, std::vector<std::unique_ptr<Statement>>> loaded_modules;
    std::vector<std::string> search_paths;
    
public:
    ModuleLoader();
    
    void add_search_path(const std::string& path);
    bool load_module(const std::string& module_name);
    std::vector<std::unique_ptr<Statement>>* get_module(const std::string& module_name);
    
    void clear_cache();
    std::vector<std::string> get_loaded_modules() const;
};

} 