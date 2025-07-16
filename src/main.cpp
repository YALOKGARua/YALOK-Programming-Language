#include <yalok/compiler.hpp>
#include <yalok/lexer.hpp>
#include <yalok/parser.hpp>
#include <yalok/interpreter.hpp>
#include <yalok/memory.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <future>
#include <atomic>
#include <memory_resource>
#include <execution>
#include <immintrin.h>
#include <format>
#include <span>
#include <ranges>
#include <concepts>
#include <coroutine>
#include <generator>
#include <algorithm>
#include <numeric>
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <regex>
#include <cstring>
#include <csignal>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

using namespace yalok;

enum class ExecutionMode : uint8_t {
    INTERPRET = 0,
    JIT_COMPILE = 1,
    AOT_COMPILE = 2,
    TRANSPILE = 3,
    ANALYZE = 4,
    BENCHMARK = 5,
    PROFILE = 6,
    DEBUG = 7,
    REPL = 8,
    PARALLEL = 9
};

enum class OutputFormat : uint8_t {
    NATIVE = 0,
    JAVASCRIPT = 1,
    PYTHON = 2,
    CPP = 3,
    RUST = 4,
    LLVM_IR = 5,
    ASSEMBLY = 6,
    BYTECODE = 7,
    WASM = 8,
    JSON = 9
};

struct Config {
    ExecutionMode mode = ExecutionMode::INTERPRET;
    OutputFormat output_format = OutputFormat::NATIVE;
    std::string input_file;
    std::string output_file;
    std::vector<std::string> include_paths;
    std::vector<std::string> library_paths;
    std::vector<std::string> defines;
    std::vector<std::string> flags;
    bool verbose = false;
    bool debug = false;
    bool optimize = true;
    bool show_tokens = false;
    bool show_ast = false;
    bool show_memory = false;
    bool show_stats = false;
    bool enable_jit = false;
    bool enable_parallel = false;
    bool enable_simd = false;
    bool enable_gpu = false;
    bool enable_profiling = false;
    bool enable_coverage = false;
    bool enable_sanitizers = false;
    bool strict_mode = false;
    bool unsafe_mode = false;
    bool experimental = false;
    int optimization_level = 2;
    int thread_count = std::thread::hardware_concurrency();
    size_t memory_limit = 1024 * 1024 * 1024;
    size_t stack_size = 8 * 1024 * 1024;
    double timeout = 0.0;
    std::string target_arch = "x86_64";
    std::string target_os = "linux";
    std::string runtime_version = "1.0.0";
};

class PerformanceTimer {
    std::chrono::high_resolution_clock::time_point start_;
    std::string name_;
    
public:
    explicit PerformanceTimer(const std::string& name) : name_(name) {
        start_ = std::chrono::high_resolution_clock::now();
    }
    
    ~PerformanceTimer() {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start_);
        if (Config().verbose) {
            std::cout << std::format("[PERF] {}: {:.3f}ms\n", name_, duration.count() / 1000.0);
        }
    }
    
    double elapsed_ms() const {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start_);
        return duration.count() / 1000.0;
    }
};

class MemoryProfiler {
    std::atomic<size_t> allocated_bytes_{0};
    std::atomic<size_t> peak_memory_{0};
    std::atomic<size_t> allocation_count_{0};
    
public:
    void record_allocation(size_t bytes) {
        allocated_bytes_ += bytes;
        allocation_count_++;
        
        size_t current = allocated_bytes_.load();
        size_t peak = peak_memory_.load();
        while (current > peak && !peak_memory_.compare_exchange_weak(peak, current)) {
            peak = peak_memory_.load();
        }
    }
    
    void record_deallocation(size_t bytes) {
        allocated_bytes_ -= bytes;
    }
    
    size_t current_memory() const { return allocated_bytes_.load(); }
    size_t peak_memory() const { return peak_memory_.load(); }
    size_t allocation_count() const { return allocation_count_.load(); }
    
    void print_stats() const {
        std::cout << std::format("Memory Stats:\n");
        std::cout << std::format("  Current: {:.2f} MB\n", current_memory() / (1024.0 * 1024.0));
        std::cout << std::format("  Peak: {:.2f} MB\n", peak_memory() / (1024.0 * 1024.0));
        std::cout << std::format("  Allocations: {}\n", allocation_count());
    }
};

class JITCompiler {
    void* executable_memory_ = nullptr;
    size_t memory_size_ = 0;
    
public:
    ~JITCompiler() {
        if (executable_memory_) {
            munmap(executable_memory_, memory_size_);
        }
    }
    
    template<typename T>
    T* compile_function(const std::string& code) {
        std::vector<uint8_t> machine_code = generate_machine_code(code);
        
        memory_size_ = machine_code.size();
        executable_memory_ = mmap(nullptr, memory_size_, 
                                 PROT_READ | PROT_WRITE, 
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        
        if (executable_memory_ == MAP_FAILED) {
            throw std::runtime_error("Failed to allocate executable memory");
        }
        
        std::memcpy(executable_memory_, machine_code.data(), memory_size_);
        
        if (mprotect(executable_memory_, memory_size_, PROT_READ | PROT_EXEC) != 0) {
            throw std::runtime_error("Failed to make memory executable");
        }
        
        return reinterpret_cast<T*>(executable_memory_);
    }
    
private:
    std::vector<uint8_t> generate_machine_code(const std::string& code) {
        std::vector<uint8_t> machine_code;
        
        machine_code.insert(machine_code.end(), {
            0x48, 0x89, 0xF8,
            0x48, 0x83, 0xC0, 0x2A,
            0xC3
        });
        
        return machine_code;
    }
};

class ParallelExecutor {
    std::vector<std::thread> worker_threads_;
    std::atomic<bool> should_stop_{false};
    
public:
    explicit ParallelExecutor(size_t thread_count) {
        worker_threads_.reserve(thread_count);
        for (size_t i = 0; i < thread_count; ++i) {
            worker_threads_.emplace_back([this, i]() {
                worker_loop(i);
            });
        }
    }
    
    ~ParallelExecutor() {
        should_stop_ = true;
        for (auto& thread : worker_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
    }
    
    template<typename F>
    auto execute_parallel(F&& function) {
        return std::async(std::launch::async, std::forward<F>(function));
    }
    
private:
    void worker_loop(size_t worker_id) {
        while (!should_stop_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
};

class SIMDOptimizer {
public:
    static void vectorized_add(const float* a, const float* b, float* result, size_t size) {
        constexpr size_t simd_width = 8;
        size_t simd_end = (size / simd_width) * simd_width;
        
        for (size_t i = 0; i < simd_end; i += simd_width) {
            __m256 va = _mm256_load_ps(&a[i]);
            __m256 vb = _mm256_load_ps(&b[i]);
            __m256 vresult = _mm256_add_ps(va, vb);
            _mm256_store_ps(&result[i], vresult);
        }
        
        for (size_t i = simd_end; i < size; ++i) {
            result[i] = a[i] + b[i];
        }
    }
    
    static void vectorized_multiply(const float* a, const float* b, float* result, size_t size) {
        constexpr size_t simd_width = 8;
        size_t simd_end = (size / simd_width) * simd_width;
        
        for (size_t i = 0; i < simd_end; i += simd_width) {
            __m256 va = _mm256_load_ps(&a[i]);
            __m256 vb = _mm256_load_ps(&b[i]);
            __m256 vresult = _mm256_mul_ps(va, vb);
            _mm256_store_ps(&result[i], vresult);
        }
        
        for (size_t i = simd_end; i < size; ++i) {
            result[i] = a[i] * b[i];
        }
    }
};

class HackerConsole {
    std::unordered_map<std::string, std::function<void(const std::vector<std::string>&)>> commands_;
    
public:
    HackerConsole() {
        setup_commands();
    }
    
    void run_interactive() {
        std::cout << "YALOK Hacker Console v1.0.0\n";
        std::cout << "Type 'help' for commands or 'exit' to quit\n";
        
        std::string input;
        while (true) {
            std::cout << "yalok> ";
            std::getline(std::cin, input);
            
            if (input.empty()) continue;
            if (input == "exit" || input == "quit") break;
            
            auto tokens = tokenize_command(input);
            if (!tokens.empty()) {
                execute_command(tokens);
            }
        }
    }
    
private:
    void setup_commands() {
        commands_["help"] = [](const std::vector<std::string>& args) {
            std::cout << "Available commands:\n";
            std::cout << "  help        - Show this help\n";
            std::cout << "  run <file>  - Execute YALOK file\n";
            std::cout << "  tokenize    - Show tokens for input\n";
            std::cout << "  parse       - Show AST for input\n";
            std::cout << "  compile     - Compile to machine code\n";
            std::cout << "  benchmark   - Run performance tests\n";
            std::cout << "  memory      - Show memory statistics\n";
            std::cout << "  hack        - Enter hacker mode\n";
            std::cout << "  exploit     - Run exploit framework\n";
            std::cout << "  payload     - Generate payload\n";
            std::cout << "  scan        - Network scanner\n";
            std::cout << "  crack       - Password cracker\n";
            std::cout << "  inject      - Code injection\n";
            std::cout << "  shell       - System shell access\n";
            std::cout << "  exit        - Exit console\n";
        };
        
        commands_["run"] = [](const std::vector<std::string>& args) {
            if (args.size() < 2) {
                std::cout << "Usage: run <filename>\n";
                return;
            }
            
            std::ifstream file(args[1]);
            if (!file.is_open()) {
                std::cout << "Error: Cannot open file " << args[1] << "\n";
                return;
            }
            
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string code = buffer.str();
            
            try {
                Lexer lexer(code);
                auto tokens = lexer.tokenize();
                std::cout << "Tokens: " << tokens.size() << "\n";
                
                std::cout << "Execution complete\n";
            } catch (const std::exception& e) {
                std::cout << "Error: " << e.what() << "\n";
            }
        };
        
        commands_["hack"] = [](const std::vector<std::string>& args) {
            std::cout << "Entering hacker mode...\n";
            std::cout << "Enhanced security features enabled\n";
            std::cout << "Stealth mode: ACTIVE\n";
            std::cout << "Root access: GRANTED\n";
            std::cout << "Firewall: BYPASSED\n";
            std::cout << "Encryption: BROKEN\n";
            std::cout << "Welcome to the matrix, hacker.\n";
        };
        
        commands_["exploit"] = [](const std::vector<std::string>& args) {
            std::cout << "Exploit Framework v2.0\n";
            std::cout << "Scanning for vulnerabilities...\n";
            
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(1, 100);
            
            for (int i = 0; i < 5; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                int vuln_score = dis(gen);
                std::cout << std::format("Found vulnerability: CVE-2024-{:04d} (Score: {})\n", 
                                       1000 + i, vuln_score);
            }
            
            std::cout << "Exploit generation complete\n";
        };
        
        commands_["payload"] = [](const std::vector<std::string>& args) {
            std::cout << "Payload Generator v1.5\n";
            std::cout << "Generating advanced payload...\n";
            
            std::vector<uint8_t> payload = {
                0x48, 0x31, 0xc0, 0x48, 0x31, 0xdb, 0x48, 0x31, 0xc9,
                0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e,
                0x2f, 0x73, 0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x48,
                0x31, 0xc0, 0xb0, 0x3b, 0x0f, 0x05
            };
            
            std::cout << "Payload bytes: ";
            for (auto byte : payload) {
                std::cout << std::format("{:02x} ", byte);
            }
            std::cout << "\n";
            std::cout << "Payload size: " << payload.size() << " bytes\n";
            std::cout << "Payload type: Reverse shell\n";
            std::cout << "Target: x86_64 Linux\n";
        };
        
        commands_["scan"] = [](const std::vector<std::string>& args) {
            std::cout << "Network Scanner v3.0\n";
            std::cout << "Scanning network 192.168.1.0/24...\n";
            
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> ip_dis(1, 254);
            std::uniform_int_distribution<> port_dis(1, 65535);
            
            for (int i = 0; i < 10; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                int ip = ip_dis(gen);
                int port = port_dis(gen);
                std::cout << std::format("192.168.1.{:3d}:{:5d} - OPEN\n", ip, port);
            }
            
            std::cout << "Scan complete\n";
        };
        
        commands_["crack"] = [](const std::vector<std::string>& args) {
            std::cout << "Password Cracker v4.0\n";
            std::cout << "Cracking password hash...\n";
            
            std::vector<std::string> passwords = {
                "password123", "admin", "letmein", "welcome", "monkey",
                "password", "123456", "qwerty", "abc123", "password1"
            };
            
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, passwords.size() - 1);
            
            for (int i = 0; i < 5; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                std::cout << std::format("Trying: {}\n", passwords[dis(gen)]);
            }
            
            std::cout << "Password cracked: " << passwords[dis(gen)] << "\n";
        };
        
        commands_["inject"] = [](const std::vector<std::string>& args) {
            std::cout << "Code Injection Framework v2.5\n";
            std::cout << "Injecting payload into target process...\n";
            
            std::cout << "Process ID: " << getpid() << "\n";
            std::cout << "Injection method: DLL injection\n";
            std::cout << "Target: explorer.exe\n";
            std::cout << "Payload: keylogger.dll\n";
            std::cout << "Status: SUCCESS\n";
            std::cout << "Keylogger active\n";
        };
        
        commands_["shell"] = [](const std::vector<std::string>& args) {
            std::cout << "System Shell Access v1.0\n";
            std::cout << "Spawning reverse shell...\n";
            std::cout << "Connection established\n";
            std::cout << "Root shell active\n";
            std::cout << "# ";
        };
        
        commands_["memory"] = [](const std::vector<std::string>& args) {
            MemoryProfiler profiler;
            profiler.print_stats();
        };
        
        commands_["benchmark"] = [](const std::vector<std::string>& args) {
            std::cout << "Running performance benchmarks...\n";
            
            {
                PerformanceTimer timer("Fibonacci(40)");
                
                std::function<int(int)> fib = [&](int n) -> int {
                    if (n <= 1) return n;
                    return fib(n - 1) + fib(n - 2);
                };
                
                int result = fib(40);
                std::cout << "Fibonacci(40) = " << result << "\n";
            }
            
            {
                PerformanceTimer timer("SIMD Vector Add");
                
                constexpr size_t size = 1000000;
                std::vector<float> a(size, 1.0f);
                std::vector<float> b(size, 2.0f);
                std::vector<float> result(size);
                
                SIMDOptimizer::vectorized_add(a.data(), b.data(), result.data(), size);
                std::cout << "Processed " << size << " elements\n";
            }
        };
    }
    
    std::vector<std::string> tokenize_command(const std::string& input) {
        std::vector<std::string> tokens;
        std::istringstream iss(input);
        std::string token;
        
        while (iss >> token) {
            tokens.push_back(token);
        }
        
        return tokens;
    }
    
    void execute_command(const std::vector<std::string>& tokens) {
        const std::string& command = tokens[0];
        
        auto it = commands_.find(command);
        if (it != commands_.end()) {
            it->second(tokens);
        } else {
            std::cout << "Unknown command: " << command << "\n";
            std::cout << "Type 'help' for available commands\n";
        }
    }
};

void print_banner() {
    std::cout << R"(
██╗   ██╗ █████╗ ██╗      ██████╗ ██╗  ██╗
╚██╗ ██╔╝██╔══██╗██║     ██╔═══██╗██║ ██╔╝
 ╚████╔╝ ███████║██║     ██║   ██║█████╔╝ 
  ╚██╔╝  ██╔══██║██║     ██║   ██║██╔═██╗ 
   ██║   ██║  ██║███████╗╚██████╔╝██║  ██╗
   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
                                          
YALOK Programming Language v1.0.0
Underground Hacker Edition
Built with C++20 for Maximum Performance
)" << std::endl;
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options] [file]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help              Show this help message\n";
    std::cout << "  -v, --version           Show version information\n";
    std::cout << "  -i, --interactive       Start interactive mode (REPL)\n";
    std::cout << "  -d, --debug             Enable debug mode\n";
    std::cout << "  -O, --optimize          Enable optimizations\n";
    std::cout << "  -O0, -O1, -O2, -O3      Set optimization level\n";
    std::cout << "  -j, --jit               Enable JIT compilation\n";
    std::cout << "  -p, --parallel          Enable parallel execution\n";
    std::cout << "  --simd                  Enable SIMD optimizations\n";
    std::cout << "  --gpu                   Enable GPU acceleration\n";
    std::cout << "  -t, --show-tokens       Show lexer tokens\n";
    std::cout << "  -a, --show-ast          Show AST structure\n";
    std::cout << "  -m, --show-memory       Show memory statistics\n";
    std::cout << "  -s, --show-stats        Show execution statistics\n";
    std::cout << "  -b, --benchmark         Run performance benchmarks\n";
    std::cout << "  --profile               Enable profiling\n";
    std::cout << "  --coverage              Enable code coverage\n";
    std::cout << "  --sanitize              Enable sanitizers\n";
    std::cout << "  --strict                Enable strict mode\n";
    std::cout << "  --unsafe                Enable unsafe mode\n";
    std::cout << "  --experimental          Enable experimental features\n";
    std::cout << "  -o FILE                 Output file\n";
    std::cout << "  -I DIR                  Add include directory\n";
    std::cout << "  -L DIR                  Add library directory\n";
    std::cout << "  -D NAME=VALUE           Define macro\n";
    std::cout << "  --target ARCH           Target architecture\n";
    std::cout << "  --threads N             Number of threads\n";
    std::cout << "  --memory-limit N        Memory limit in MB\n";
    std::cout << "  --timeout N             Execution timeout in seconds\n";
    std::cout << "  --format FORMAT         Output format (native, js, py, cpp, rust, llvm, asm, bytecode, wasm, json)\n";
    std::cout << "  --mode MODE             Execution mode (interpret, jit, aot, transpile, analyze, benchmark, profile, debug, repl, parallel)\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " program.yal                Run program\n";
    std::cout << "  " << program_name << " -i                         Interactive mode\n";
    std::cout << "  " << program_name << " -j -O3 program.yal         JIT compile with optimizations\n";
    std::cout << "  " << program_name << " -p --threads 8 program.yal Parallel execution\n";
    std::cout << "  " << program_name << " --mode=transpile --format=js program.yal  Transpile to JavaScript\n";
    std::cout << "  " << program_name << " -b --simd program.yal      Benchmark with SIMD\n";
}

Config parse_arguments(int argc, char* argv[]) {
    Config config;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            std::exit(0);
        } else if (arg == "-v" || arg == "--version") {
            print_banner();
            std::exit(0);
        } else if (arg == "-i" || arg == "--interactive") {
            config.mode = ExecutionMode::REPL;
        } else if (arg == "-d" || arg == "--debug") {
            config.debug = true;
        } else if (arg == "-O" || arg == "--optimize") {
            config.optimize = true;
        } else if (arg == "-O0") {
            config.optimization_level = 0;
        } else if (arg == "-O1") {
            config.optimization_level = 1;
        } else if (arg == "-O2") {
            config.optimization_level = 2;
        } else if (arg == "-O3") {
            config.optimization_level = 3;
        } else if (arg == "-j" || arg == "--jit") {
            config.enable_jit = true;
            config.mode = ExecutionMode::JIT_COMPILE;
        } else if (arg == "-p" || arg == "--parallel") {
            config.enable_parallel = true;
            config.mode = ExecutionMode::PARALLEL;
        } else if (arg == "--simd") {
            config.enable_simd = true;
        } else if (arg == "--gpu") {
            config.enable_gpu = true;
        } else if (arg == "-t" || arg == "--show-tokens") {
            config.show_tokens = true;
        } else if (arg == "-a" || arg == "--show-ast") {
            config.show_ast = true;
        } else if (arg == "-m" || arg == "--show-memory") {
            config.show_memory = true;
        } else if (arg == "-s" || arg == "--show-stats") {
            config.show_stats = true;
        } else if (arg == "-b" || arg == "--benchmark") {
            config.mode = ExecutionMode::BENCHMARK;
        } else if (arg == "--profile") {
            config.enable_profiling = true;
            config.mode = ExecutionMode::PROFILE;
        } else if (arg == "--coverage") {
            config.enable_coverage = true;
        } else if (arg == "--sanitize") {
            config.enable_sanitizers = true;
        } else if (arg == "--strict") {
            config.strict_mode = true;
        } else if (arg == "--unsafe") {
            config.unsafe_mode = true;
        } else if (arg == "--experimental") {
            config.experimental = true;
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            config.output_file = argv[++i];
        } else if ((arg == "-I" || arg == "--include") && i + 1 < argc) {
            config.include_paths.push_back(argv[++i]);
        } else if ((arg == "-L" || arg == "--library") && i + 1 < argc) {
            config.library_paths.push_back(argv[++i]);
        } else if (arg.starts_with("-D")) {
            config.defines.push_back(arg.substr(2));
        } else if (arg.starts_with("--target=")) {
            config.target_arch = arg.substr(9);
        } else if (arg.starts_with("--threads=")) {
            config.thread_count = std::stoi(arg.substr(10));
        } else if (arg.starts_with("--memory-limit=")) {
            config.memory_limit = std::stoll(arg.substr(15)) * 1024 * 1024;
        } else if (arg.starts_with("--timeout=")) {
            config.timeout = std::stod(arg.substr(10));
        } else if (arg.starts_with("--format=")) {
            std::string format = arg.substr(9);
            if (format == "js") config.output_format = OutputFormat::JAVASCRIPT;
            else if (format == "py") config.output_format = OutputFormat::PYTHON;
            else if (format == "cpp") config.output_format = OutputFormat::CPP;
            else if (format == "rust") config.output_format = OutputFormat::RUST;
            else if (format == "llvm") config.output_format = OutputFormat::LLVM_IR;
            else if (format == "asm") config.output_format = OutputFormat::ASSEMBLY;
            else if (format == "bytecode") config.output_format = OutputFormat::BYTECODE;
            else if (format == "wasm") config.output_format = OutputFormat::WASM;
            else if (format == "json") config.output_format = OutputFormat::JSON;
        } else if (arg.starts_with("--mode=")) {
            std::string mode = arg.substr(7);
            if (mode == "interpret") config.mode = ExecutionMode::INTERPRET;
            else if (mode == "jit") config.mode = ExecutionMode::JIT_COMPILE;
            else if (mode == "aot") config.mode = ExecutionMode::AOT_COMPILE;
            else if (mode == "transpile") config.mode = ExecutionMode::TRANSPILE;
            else if (mode == "analyze") config.mode = ExecutionMode::ANALYZE;
            else if (mode == "benchmark") config.mode = ExecutionMode::BENCHMARK;
            else if (mode == "profile") config.mode = ExecutionMode::PROFILE;
            else if (mode == "debug") config.mode = ExecutionMode::DEBUG;
            else if (mode == "repl") config.mode = ExecutionMode::REPL;
            else if (mode == "parallel") config.mode = ExecutionMode::PARALLEL;
        } else if (!arg.starts_with("-") && config.input_file.empty()) {
            config.input_file = arg;
        } else {
            config.flags.push_back(arg);
        }
    }
    
    return config;
}

int main(int argc, char* argv[]) {
    try {
        Config config = parse_arguments(argc, argv);
        
        if (config.mode == ExecutionMode::REPL) {
            if (config.verbose) print_banner();
            HackerConsole console;
            console.run_interactive();
            return 0;
        }
        
        if (config.input_file.empty()) {
            std::cerr << "Error: No input file specified\n";
            print_usage(argv[0]);
            return 1;
        }
        
        std::ifstream file(config.input_file);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open file " << config.input_file << "\n";
            return 1;
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string source = buffer.str();
        
        if (config.verbose) {
            std::cout << std::format("Processing file: {}\n", config.input_file);
            std::cout << std::format("Source size: {} bytes\n", source.size());
        }
        
        PerformanceTimer total_timer("Total execution");
        MemoryProfiler memory_profiler;
        
        std::unique_ptr<ParallelExecutor> parallel_executor;
        if (config.enable_parallel) {
            parallel_executor = std::make_unique<ParallelExecutor>(config.thread_count);
        }
        
        std::unique_ptr<JITCompiler> jit_compiler;
        if (config.enable_jit) {
            jit_compiler = std::make_unique<JITCompiler>();
        }
        
        {
            PerformanceTimer lexer_timer("Lexical analysis");
            BasicLexer lexer(source);
            
            if (config.show_tokens) {
                auto tokens = lexer.tokenize();
                if (tokens) {
                    std::cout << "Tokens:\n";
                    for (const auto& token : *tokens) {
                        std::cout << std::format("  {}: '{}' at {}:{}\n", 
                                               static_cast<int>(token.type), 
                                               token.value, 
                                               token.line, 
                                               token.column);
                    }
                }
            }
        }
        
        if (config.show_memory) {
            memory_profiler.print_stats();
        }
        
        if (config.show_stats) {
            std::cout << std::format("Configuration:\n");
            std::cout << std::format("  Mode: {}\n", static_cast<int>(config.mode));
            std::cout << std::format("  Optimization level: {}\n", config.optimization_level);
            std::cout << std::format("  Thread count: {}\n", config.thread_count);
            std::cout << std::format("  SIMD enabled: {}\n", config.enable_simd);
            std::cout << std::format("  JIT enabled: {}\n", config.enable_jit);
            std::cout << std::format("  Parallel enabled: {}\n", config.enable_parallel);
        }
        
        if (config.mode == ExecutionMode::BENCHMARK) {
            std::cout << "Running benchmarks...\n";
            
            constexpr size_t iterations = 1000000;
            {
                PerformanceTimer timer("Simple arithmetic");
                volatile int result = 0;
                for (size_t i = 0; i < iterations; ++i) {
                    result += i * 2;
                }
            }
            
            if (config.enable_simd) {
                PerformanceTimer timer("SIMD operations");
                constexpr size_t size = 100000;
                std::vector<float> a(size, 1.0f);
                std::vector<float> b(size, 2.0f);
                std::vector<float> result(size);
                
                for (size_t i = 0; i < 100; ++i) {
                    SIMDOptimizer::vectorized_add(a.data(), b.data(), result.data(), size);
                }
            }
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occurred\n";
        return 1;
    }
} 