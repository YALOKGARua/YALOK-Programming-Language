#include "yalok/lexer.hpp"
#include "yalok/parser.hpp"
#include "yalok/interpreter.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

using namespace yalok;

static void banner() {
    std::cout << "\033[32m"
R"(
    ▄█    █▄     ▄████████  ▄█        ▄██████▄   ▄█   ▄█▄
   ███    ███   ███    ███ ███       ███    ███ ███ ▄███▀
   ███    ███   ███    ███ ███       ███    ███ ███▐██▀
    ███   ███   ███    ███ ███       ███    ███ █████▀
     ████████▀  ███    ███ ███       ███    ███ ▀█████▄
      ███  ███  ███    ███ ███       ███    ███ ███▐██▄
      ███  ███  ███    ███ ███▌    ▄ ███    ███ ███ ▀███▄
      ███  ███   ▀█████▀  █████▄▄██  ▀██████▀  ███   ▀█▀
)" << "\033[0m"
    << "\033[90m  [ YALOK v1.0 :: by YALOKGAR ]\033[0m\n"
    << "\033[90m  [ systems language for hackers ]\033[0m\n"
    << std::endl;
}

static std::string readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "\033[31m[ERR]\033[0m cannot open '" << path << "'\n";
        std::exit(1);
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

static void run(const std::string& source, Interpreter& interp) {
    try {
        Lexer lexer(source);
        auto tokens = lexer.tokenize();

        for (auto& t : tokens) {
            if (t.is(TokenType::Error)) {
                std::cerr << "\033[31m[LEXER]\033[0m " << t.line << ":" << t.col
                          << " unexpected '" << t.value << "'\n";
                return;
            }
        }

        Parser parser(std::move(tokens));
        auto program = parser.parse();
        interp.execute(program);

    } catch (const ParseError& e) {
        std::cerr << "\033[31m[PARSE]\033[0m " << e.line << ":" << e.col << " " << e.what() << "\n";
    } catch (const RuntimeError& e) {
        std::cerr << "\033[31m[RUNTIME]\033[0m " << e.what() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "\033[31m[FATAL]\033[0m " << e.what() << "\n";
    }
}

static void repl(Interpreter& interp) {
    banner();
    std::string line, buffer;

    while (true) {
        if (buffer.empty())
            std::cout << "\033[32mroot@yalok\033[0m\033[90m#\033[0m ";
        else
            std::cout << "\033[90m        ...\033[0m ";

        if (!std::getline(std::cin, line)) break;
        if (line == "kill" || line == "exit") break;

        if (line == "help") {
            std::cout << "\033[33m"
                      << "  YALOK REPL\n"
                      << "  ----------\n"
                      << "  help     show this\n"
                      << "  kill     exit session\n"
                      << "  clear    wipe screen\n"
                      << "  info     language info\n"
                      << "\033[0m";
            continue;
        }
        if (line == "clear") {
            std::cout << "\033[2J\033[H";
            continue;
        }
        if (line == "info") {
            std::cout << "\033[33m"
                      << "  YALOK v1.0 by YALOKGAR\n"
                      << "  keywords: load cell proc ret check alt\n"
                      << "            loop scan thru gate packet\n"
                      << "            probe breach halt skip on off\n"
                      << "  types:    i64 f64 str buf bool\n"
                      << "  builtins: echo emit size hex bits alloc\n"
                      << "            hexdump identify push pop slice\n"
                      << "            chr ord tick rand kill\n"
                      << "\033[0m";
            continue;
        }
        if (line.empty()) continue;

        buffer += line + "\n";

        int braces = 0;
        for (char c : buffer) {
            if (c == '{') braces++;
            if (c == '}') braces--;
        }
        if (braces > 0) continue;

        run(buffer, interp);
        buffer.clear();
    }

    std::cout << "\033[90m[session terminated]\033[0m\n";
}

int main(int argc, char* argv[]) {
    Interpreter interp;

    if (argc < 2) {
        repl(interp);
        return 0;
    }

    std::string arg = argv[1];
    if (arg == "-h" || arg == "--help") {
        std::cout << "usage: yalok [file.yal]\n"
                  << "       yalok           start REPL\n"
                  << "       yalok -h        help\n"
                  << "       yalok -v        version\n";
        return 0;
    }
    if (arg == "-v" || arg == "--version") {
        banner();
        return 0;
    }

    auto source = readFile(arg);
    run(source, interp);
    return 0;
}
