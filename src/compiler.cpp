#include "yalok/compiler.hpp"
#include "yalok/lexer.hpp"
#include "yalok/parser.hpp"
#include "yalok/interpreter.hpp"
#include "yalok/memory.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <filesystem>

namespace yalok {

void ErrorReporter::report_error(const std::string& message, int line, int column) {
    std::string error_msg = "Error";
    if (line != -1) {
        error_msg += " at line " + std::to_string(line);
        if (column != -1) {
            error_msg += ", column " + std::to_string(column);
        }
    }
    error_msg += ": " + message;
    
    errors.push_back(error_msg);
    has_errors = true;
    
    if (line != -1) {
        std::cerr << "\033[31m" << error_msg << "\033[0m" << std::endl;
    } else {
        std::cerr << "\033[31m" << error_msg << "\033[0m" << std::endl;
    }
}

void ErrorReporter::report_warning(const std::string& message, int line, int column) {
    std::string warning_msg = "Warning";
    if (line != -1) {
        warning_msg += " at line " + std::to_string(line);
        if (column != -1) {
            warning_msg += ", column " + std::to_string(column);
        }
    }
    warning_msg += ": " + message;
    
    warnings.push_back(warning_msg);
    std::cerr << "\033[33m" << warning_msg << "\033[0m" << std::endl;
}

void ErrorReporter::print_errors() const {
    if (errors.empty()) {
        return;
    }
    
    std::cerr << "\033[31m=== COMPILATION ERRORS ===\033[0m" << std::endl;
    for (const auto& error : errors) {
        std::cerr << "\033[31m" << error << "\033[0m" << std::endl;
    }
    std::cerr << "\033[31m=== END ERRORS ===\033[0m" << std::endl;
}

void ErrorReporter::print_warnings() const {
    if (warnings.empty()) {
        return;
    }
    
    std::cerr << "\033[33m=== COMPILATION WARNINGS ===\033[0m" << std::endl;
    for (const auto& warning : warnings) {
        std::cerr << "\033[33m" << warning << "\033[0m" << std::endl;
    }
    std::cerr << "\033[33m=== END WARNINGS ===\033[0m" << std::endl;
}

void ErrorReporter::clear() {
    errors.clear();
    warnings.clear();
    has_errors = false;
}

Compiler::Compiler(const CompilerOptions& opts) : options(opts) {
    lexer = std::make_unique<Lexer>();
    parser = std::make_unique<Parser>();
    interpreter = std::make_unique<Interpreter>();
    error_reporter = std::make_unique<ErrorReporter>();
}

Compiler::~Compiler() {
    cleanup();
}

void Compiler::print_tokens(const std::vector<Token>& tokens) {
    std::cout << "\033[36m=== TOKEN STREAM ===\033[0m" << std::endl;
    for (const auto& token : tokens) {
        std::cout << "\033[36m" << token.to_string() << "\033[0m" << std::endl;
    }
    std::cout << "\033[36m=== END TOKENS ===\033[0m" << std::endl;
}

void Compiler::print_ast(const std::vector<std::unique_ptr<Statement>>& statements) {
    std::cout << "\033[35m=== ABSTRACT SYNTAX TREE ===\033[0m" << std::endl;
    for (const auto& stmt : statements) {
        if (stmt) {
            std::cout << "\033[35m" << stmt->to_string() << "\033[0m" << std::endl;
        }
    }
    std::cout << "\033[35m=== END AST ===\033[0m" << std::endl;
}

void Compiler::print_benchmark_results(const std::chrono::microseconds& execution_time) {
    std::cout << "\033[32m=== BENCHMARK RESULTS ===\033[0m" << std::endl;
    std::cout << "\033[32mExecution time: " << execution_time.count() << " µs\033[0m" << std::endl;
    std::cout << "\033[32mExecution time: " << execution_time.count() / 1000.0 << " ms\033[0m" << std::endl;
    
    if (options.show_memory_stats) {
        auto memory_stats = interpreter->get_memory_stats();
        std::cout << "\033[32mMemory allocated: " << memory_stats.total_allocated << " bytes\033[0m" << std::endl;
        std::cout << "\033[32mMemory used: " << memory_stats.total_used << " bytes\033[0m" << std::endl;
        std::cout << "\033[32mMemory efficiency: " << std::fixed << std::setprecision(2) 
                  << (memory_stats.total_used * 100.0 / memory_stats.total_allocated) << "%\033[0m" << std::endl;
    }
    
    std::cout << "\033[32m=== END BENCHMARK ===\033[0m" << std::endl;
}

bool Compiler::compile_file(const std::string& filename) {
    try {
        std::ifstream file(filename);
        if (!file.is_open()) {
            error_reporter->report_error("Could not open file: " + filename);
            return false;
        }
        
        std::string source((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        
        return compile_string(source);
    } catch (const std::exception& e) {
        error_reporter->report_error("Exception while reading file: " + std::string(e.what()));
        return false;
    }
}

bool Compiler::compile_string(const std::string& source) {
    try {
        error_reporter->clear();
        
        auto tokens = lexer->tokenize(source);
        if (options.show_tokens) {
            print_tokens(tokens);
        }
        
        auto statements = parser->parse(tokens);
        if (options.show_ast) {
            print_ast(statements);
        }
        
        if (error_reporter->has_any_errors()) {
            error_reporter->print_errors();
            return false;
        }
        
        if (!options.output_file.empty()) {
            std::ofstream output(options.output_file);
            if (output.is_open()) {
                output << "// Compiled YALOK code" << std::endl;
                output << "// Source processed successfully" << std::endl;
                output.close();
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        error_reporter->report_error("Compilation error: " + std::string(e.what()));
        return false;
    }
}

bool Compiler::run_file(const std::string& filename) {
    try {
        std::ifstream file(filename);
        if (!file.is_open()) {
            error_reporter->report_error("Could not open file: " + filename);
            return false;
        }
        
        std::string source((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        
        return run_string(source);
    } catch (const std::exception& e) {
        error_reporter->report_error("Exception while reading file: " + std::string(e.what()));
        return false;
    }
}

bool Compiler::run_string(const std::string& source) {
    try {
        error_reporter->clear();
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        auto tokens = lexer->tokenize(source);
        if (options.show_tokens) {
            print_tokens(tokens);
        }
        
        auto statements = parser->parse(tokens);
        if (options.show_ast) {
            print_ast(statements);
        }
        
        if (error_reporter->has_any_errors()) {
            error_reporter->print_errors();
            return false;
        }
        
        interpreter->execute(statements);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto execution_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        if (options.benchmark) {
            print_benchmark_results(execution_time);
        }
        
        if (error_reporter->has_any_errors()) {
            error_reporter->print_errors();
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        error_reporter->report_error("Runtime error: " + std::string(e.what()));
        return false;
    }
}

void Compiler::interactive_mode() {
    std::cout << "\033[32mYALOK Interactive Mode - Demo Version\033[0m" << std::endl;
    std::cout << "\033[33mType 'exit' to quit, 'help' for commands\033[0m" << std::endl;
    
    repl();
}

void Compiler::repl() {
    std::string line;
    std::string buffer;
    int line_number = 1;
    
    while (true) {
        if (buffer.empty()) {
            std::cout << "\033[36myalok[" << line_number << "]>\033[0m ";
        } else {
            std::cout << "\033[36m       ...\033[0m ";
        }
        
        if (!std::getline(std::cin, line)) {
            break;
        }
        
        line = line.substr(0, line.find_last_not_of(" \t\n\r") + 1);
        
        if (line == "exit" || line == "quit") {
            break;
        } else if (line == "help") {
            std::cout << "\033[33mYALOK Demo Commands:\033[0m" << std::endl;
            std::cout << "\033[33m  help    - Show this help\033[0m" << std::endl;
            std::cout << "\033[33m  exit    - Exit REPL\033[0m" << std::endl;
            std::cout << "\033[33m  clear   - Clear screen\033[0m" << std::endl;
            std::cout << "\033[33m  reset   - Reset interpreter state\033[0m" << std::endl;
            continue;
        } else if (line == "clear") {
            system("clear");
            continue;
        } else if (line == "reset") {
            reset();
            std::cout << "\033[33mInterpreter state reset\033[0m" << std::endl;
            continue;
        } else if (line.empty()) {
            continue;
        }
        
        buffer += line + "\n";
        
        if (line.back() == ';' || line.back() == '}' || 
            line.find("print(") != std::string::npos ||
            line.find("var ") != std::string::npos ||
            line.find("func ") != std::string::npos) {
            
            try {
                run_string(buffer);
            } catch (const std::exception& e) {
                std::cerr << "\033[31mError: " << e.what() << "\033[0m" << std::endl;
            }
            
            buffer.clear();
        }
        
        line_number++;
    }
    
    std::cout << "\033[32mGoodbye from YALOK Demo!\033[0m" << std::endl;
}

void Compiler::reset() {
    interpreter->reset();
    error_reporter->clear();
}

void Compiler::cleanup() {
    if (interpreter) {
        interpreter->cleanup();
    }
}

std::unique_ptr<Compiler> YalokRuntime::compiler_instance = nullptr;
std::unique_ptr<MemoryManager> YalokRuntime::memory_manager = nullptr;

void YalokRuntime::initialize(const CompilerOptions& options) {
    if (!compiler_instance) {
        compiler_instance = std::make_unique<Compiler>(options);
        memory_manager = std::make_unique<MemoryManager>();
    }
}

void YalokRuntime::shutdown() {
    if (compiler_instance) {
        compiler_instance->cleanup();
        compiler_instance.reset();
    }
    
    if (memory_manager) {
        memory_manager->cleanup();
        memory_manager.reset();
    }
}

Compiler& YalokRuntime::get_compiler() {
    if (!compiler_instance) {
        throw std::runtime_error("YalokRuntime not initialized");
    }
    return *compiler_instance;
}

MemoryManager& YalokRuntime::get_memory_manager() {
    if (!memory_manager) {
        throw std::runtime_error("YalokRuntime not initialized");
    }
    return *memory_manager;
}

bool YalokRuntime::is_initialized() {
    return compiler_instance != nullptr && memory_manager != nullptr;
}

void YalokRuntime::print_version() {
    std::cout << "\033[32mYALOK Programming Language - Demo Version 1.0\033[0m" << std::endl;
    std::cout << "\033[33mAuthor: YALOKGAR (yalokgar@gmail.com)\033[0m" << std::endl;
    std::cout << "\033[33mBuilt with: C++20, Modern Architecture\033[0m" << std::endl;
    std::cout << "\033[31mWARNING: This is a DEMO VERSION with limited functionality\033[0m" << std::endl;
}

void YalokRuntime::print_help() {
    std::cout << "\033[32mYALOK Demo Usage:\033[0m" << std::endl;
    std::cout << "\033[33m  yalok [options] <file>  - Run YALOK file\033[0m" << std::endl;
    std::cout << "\033[33m  yalok -i                - Interactive mode\033[0m" << std::endl;
    std::cout << "\033[33m  yalok -h                - Show this help\033[0m" << std::endl;
    std::cout << "\033[33m  yalok -v                - Show version\033[0m" << std::endl;
    std::cout << "\033[33m\033[0m" << std::endl;
    std::cout << "\033[33mOptions:\033[0m" << std::endl;
    std::cout << "\033[33m  -d      - Debug mode\033[0m" << std::endl;
    std::cout << "\033[33m  -t      - Show tokens\033[0m" << std::endl;
    std::cout << "\033[33m  -a      - Show AST\033[0m" << std::endl;
    std::cout << "\033[33m  -b      - Benchmark\033[0m" << std::endl;
    std::cout << "\033[33m  -m      - Memory stats\033[0m" << std::endl;
}

ModuleLoader::ModuleLoader() {
    add_search_path(".");
    add_search_path("./modules");
    add_search_path("./lib");
}

void ModuleLoader::add_search_path(const std::string& path) {
    if (std::find(search_paths.begin(), search_paths.end(), path) == search_paths.end()) {
        search_paths.push_back(path);
    }
}

bool ModuleLoader::load_module(const std::string& module_name) {
    if (loaded_modules.find(module_name) != loaded_modules.end()) {
        return true;
    }
    
    for (const auto& search_path : search_paths) {
        std::string full_path = search_path + "/" + module_name + ".yal";
        
        if (std::filesystem::exists(full_path)) {
            try {
                std::ifstream file(full_path);
                if (!file.is_open()) {
                    continue;
                }
                
                std::string source((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();
                
                Lexer lexer;
                Parser parser;
                
                auto tokens = lexer.tokenize(source);
                auto statements = parser.parse(tokens);
                
                loaded_modules[module_name] = std::move(statements);
                return true;
            } catch (const std::exception& e) {
                continue;
            }
        }
    }
    
    return false;
}

std::vector<std::unique_ptr<Statement>>* ModuleLoader::get_module(const std::string& module_name) {
    auto it = loaded_modules.find(module_name);
    if (it != loaded_modules.end()) {
        return &it->second;
    }
    return nullptr;
}

void ModuleLoader::clear_cache() {
    loaded_modules.clear();
}

std::vector<std::string> ModuleLoader::get_loaded_modules() const {
    std::vector<std::string> modules;
    for (const auto& pair : loaded_modules) {
        modules.push_back(pair.first);
    }
    return modules;
}

} 