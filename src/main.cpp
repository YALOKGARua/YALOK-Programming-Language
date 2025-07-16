#include <yalok/compiler.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>

using namespace yalok;

void print_usage(const char* program_name) {
    std::cout << "YALOK Programming Language v1.0.0\n";
    std::cout << "Usage: " << program_name << " [options] [file]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help              Show this help message\n";
    std::cout << "  -v, --version           Show version information\n";
    std::cout << "  -i, --interactive       Start interactive mode (REPL)\n";
    std::cout << "  -d, --debug             Enable debug mode\n";
    std::cout << "  -O, --optimize          Enable optimizations (default)\n";
    std::cout << "  -t, --show-tokens       Show lexer tokens\n";
    std::cout << "  -a, --show-ast          Show AST structure\n";
    std::cout << "  -m, --show-memory       Show memory statistics\n";
    std::cout << "  -b, --benchmark         Show execution benchmarks\n";
    std::cout << "  -o FILE                 Output file (for compilation)\n";
    std::cout << "  -I DIR                  Add include directory\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " program.yal        Run program\n";
    std::cout << "  " << program_name << " -i                 Interactive mode\n";
    std::cout << "  " << program_name << " -b program.yal     Benchmark program\n";
    std::cout << "  " << program_name << " -d -m program.yal  Debug with memory stats\n";
}

void print_version() {
    std::cout << "YALOK Programming Language v1.0.0\n";
    std::cout << "Built with modern C++20 for maximum performance\n";
    std::cout << "Copyright (c) 2025 YALOKGAR\n";
}

CompilerOptions parse_arguments(int argc, char* argv[], std::string& input_file) {
    CompilerOptions options;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            exit(0);
        } else if (arg == "-v" || arg == "--version") {
            print_version();
            exit(0);
        } else if (arg == "-i" || arg == "--interactive") {
            input_file = "";
        } else if (arg == "-d" || arg == "--debug") {
            options.debug_mode = true;
        } else if (arg == "-O" || arg == "--optimize") {
            options.optimize = true;
        } else if (arg == "-t" || arg == "--show-tokens") {
            options.show_tokens = true;
        } else if (arg == "-a" || arg == "--show-ast") {
            options.show_ast = true;
        } else if (arg == "-m" || arg == "--show-memory") {
            options.show_memory_stats = true;
        } else if (arg == "-b" || arg == "--benchmark") {
            options.benchmark = true;
        } else if (arg == "-o") {
            if (i + 1 < argc) {
                options.output_file = argv[++i];
            } else {
                std::cerr << "Error: -o requires a filename\n";
                exit(1);
            }
        } else if (arg == "-I") {
            if (i + 1 < argc) {
                options.include_paths.push_back(argv[++i]);
            } else {
                std::cerr << "Error: -I requires a directory path\n";
                exit(1);
            }
        } else if (arg.starts_with("-")) {
            std::cerr << "Error: Unknown option " << arg << "\n";
            print_usage(argv[0]);
            exit(1);
        } else {
            if (input_file.empty()) {
                input_file = arg;
            } else {
                std::cerr << "Error: Multiple input files not supported\n";
                exit(1);
            }
        }
    }
    
    return options;
}

int main(int argc, char* argv[]) {
    try {
        std::string input_file;
        CompilerOptions options = parse_arguments(argc, argv, input_file);
        
        YalokRuntime::initialize(options);
        
        auto& compiler = YalokRuntime::get_compiler();
        
        if (input_file.empty()) {
            std::cout << "YALOK Interactive Mode v1.0.0\n";
            std::cout << "Type 'exit' or press Ctrl+C to quit\n";
            std::cout << "Type 'help' for available commands\n\n";
            compiler.interactive_mode();
        } else {
            if (!std::filesystem::exists(input_file)) {
                std::cerr << "Error: File '" << input_file << "' not found\n";
                return 1;
            }
            
            if (!compiler.run_file(input_file)) {
                return 1;
            }
        }
        
        YalokRuntime::shutdown();
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unknown fatal error occurred\n";
        return 1;
    }
} 