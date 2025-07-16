# 🚀 YALOK Programming Language

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/YALOKGARua/yalok)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/YALOKGARua/yalok/releases)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Language](https://img.shields.io/badge/language-C%2B%2B20-orange)](https://en.cppreference.com/w/cpp/20)

**YALOK** is a high-performance, memory-efficient programming language designed for speed and versatility. Built with modern C++20, it features advanced memory management, lightning-fast execution, and cross-platform compatibility.

## ✨ Features

- **🏃 Lightning Fast**: Optimized for maximum performance with native compilation
- **🧠 Smart Memory Management**: Advanced garbage collection and memory pooling
- **🎯 Simple Syntax**: Easy-to-learn C-style syntax with modern features
- **🌍 Cross-Platform**: Runs on Linux, Windows, and macOS
- **⚡ Instant Compilation**: Near-instantaneous compilation and execution
- **🔧 Developer-Friendly**: Rich debugging and profiling tools
- **📦 Modular Design**: Support for modules and imports
- **🎨 Modern Features**: Arrays, objects, functions, and more

## 🚀 Quick Start

### Prerequisites

- C++20 compatible compiler (GCC 10+, Clang 10+, MSVC 2022+)
- CMake 3.20+
- Git

### Installation

```bash
git clone https://github.com/YALOKGARua/yalok.git
cd yalok
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

### Your First Program

Create a file `hello.yal`:

```yalok
var greeting = "Hello, YALOK!";
print(greeting);

var numbers = [1, 2, 3, 4, 5];
for (var i = 0; i < len(numbers); i++) {
    print("Number:", numbers[i]);
}
```

Run it:

```bash
yalok hello.yal
```

## 📚 Language Guide

### 🔤 Variables and Types

```yalok
var name = "YALOK";           // String
var age = 25;                 // Integer
var height = 5.9;             // Float
var is_active = true;         // Boolean
var data = [1, 2, 3];         // Array
var user = {                  // Object
    name: "John",
    age: 30
};
```

### 🔢 Arithmetic Operations

```yalok
var a = 10;
var b = 3;

print(a + b);    // Addition: 13
print(a - b);    // Subtraction: 7
print(a * b);    // Multiplication: 30
print(a / b);    // Division: 3.333...
print(a % b);    // Modulo: 1
print(a ** b);   // Power: 1000
```

### 🎯 Control Flow

```yalok
// If statements
if (age >= 18) {
    print("Adult");
} else {
    print("Minor");
}

// While loops
var i = 0;
while (i < 5) {
    print("Count:", i);
    i++;
}

// For loops
for (var j = 0; j < 10; j++) {
    if (j == 5) break;
    if (j % 2 == 0) continue;
    print("Odd:", j);
}
```

### 🔧 Functions

```yalok
func add(a, b) {
    return a + b;
}

func factorial(n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

var result = add(5, 3);
print("Result:", result);
print("Factorial of 5:", factorial(5));
```

### 📊 Arrays and Objects

```yalok
// Arrays
var fruits = ["apple", "banana", "orange"];
fruits.push("grape");
print("Fruits:", fruits);

// Objects
var person = {
    name: "Alice",
    age: 28,
    greet: func() {
        print("Hello, I'm", this.name);
    }
};

person.greet();
```

### 📦 Modules

```yalok
// math.yal
export func square(x) {
    return x * x;
}

export var PI = 3.14159;

// main.yal
import { square, PI } from "math";

print("Square of 5:", square(5));
print("PI:", PI);
```

## 🛠️ Built-in Functions

| Function | Description | Example |
|----------|-------------|---------|
| `print(...)` | Output values to console | `print("Hello", 42)` |
| `len(array)` | Get array length | `len([1, 2, 3])` → 3 |
| `push(array, value)` | Add element to array | `push(arr, 42)` |
| `pop(array)` | Remove last element | `pop(arr)` |
| `type(value)` | Get value type | `type(42)` → "integer" |
| `str(value)` | Convert to string | `str(42)` → "42" |
| `int(value)` | Convert to integer | `int("42")` → 42 |
| `float(value)` | Convert to float | `float("3.14")` → 3.14 |

## 💻 Command Line Interface

```bash
# Run a program
yalok program.yal

# Interactive mode (REPL)
yalok -i

# Debug mode with memory stats
yalok -d -m program.yal

# Benchmark execution
yalok -b program.yal

# Show tokens and AST
yalok -t -a program.yal

# Optimize and compile
yalok -O -o output program.yal
```

## 🏗️ Building from Source

### Development Build

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

### Release Build

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### Build Options

- `CMAKE_BUILD_TYPE`: Debug, Release, RelWithDebInfo, MinSizeRel
- `ENABLE_COVERAGE`: Enable code coverage (Debug only)
- `ENABLE_TESTS`: Build test suite (requires Google Test)

## 🧪 Testing

```bash
# Run all tests
make test

# Run examples
make examples

# Run benchmarks
make benchmark

# Format code
make format

# Run linting
make lint
```

## 📊 Performance

YALOK is designed for maximum performance:

- **Native compilation** for optimal speed
- **Zero-copy string operations** where possible
- **Advanced memory pooling** reduces allocations
- **Optimized AST evaluation** minimizes overhead
- **JIT-friendly design** for future enhancements

### Benchmarks

| Operation | Time (μs) | Memory (KB) |
|-----------|-----------|-------------|
| Hello World | 45 | 12 |
| Fibonacci(30) | 892 | 24 |
| Prime Check(1000) | 156 | 16 |
| Array Sort(1000) | 234 | 89 |

## 🏛️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Lexer       │ -> │     Parser      │ -> │   Interpreter   │
│  (Tokenization) │    │  (AST Building) │    │  (Execution)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         v                       v                       v
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Memory Manager  │    │ Error Reporter  │    │ Standard Library│
│ (GC & Pooling)  │    │ (Diagnostics)   │    │ (Built-ins)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with modern C++20 features
- Inspired by the best practices from various language implementations
- Special thanks to the open-source community

## 📬 Contact

- **Author**: YALOKGAR
- **Email**: yalokgar@gmail.com
- **GitHub**: [@YALOKGARua](https://github.com/YALOKGARua)

---

<div align="center">
  <strong>🌟 Star us on GitHub if you find YALOK useful! 🌟</strong>
</div> 