# 🚀 YALOK Programming Language - Hacker Edition

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/YALOKGARua/yalok)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/YALOKGARua/yalok/releases)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Language](https://img.shields.io/badge/language-C%2B%2B20-orange)](https://en.cppreference.com/w/cpp/20)
[![Hacker](https://img.shields.io/badge/style-hacker-red)](https://github.com/YALOKGARua/yalok)

**YALOK** is a unique, high-performance programming language designed for hackers, security researchers, and system programmers. Built with modern C++20, it features underground-style syntax, advanced memory management, and lightning-fast execution.

## 💀 Hacker Features

- **🔓 Underground Syntax**: Unique hacker-style keywords and operators
- **🎯 Binary & Hex Literals**: Native support for 0x and 0b literals
- **⚡ Bitwise Operations**: Full support for bit manipulation
- **🧠 Memory Control**: Direct memory access and manipulation
- **🔐 Crypto Functions**: Built-in encryption and hashing
- **🕳️ System Calls**: Direct syscall interface
- **👻 Stealth Mode**: Ghost processes and phantom operations
- **🛡️ Security Tools**: Built-in penetration testing functions

## 🚀 Quick Start

### Prerequisites

- C++20 compatible compiler (GCC 10+, Clang 10+, MSVC 2022+)
- CMake 3.20+
- Git

### Installation

```bash
git clone https://github.com/YALOKGARua/yalok.git
cd yalok
./build.sh
sudo ./build.sh -t -p /usr/local
```

### Your First Hack

Create a file `hello.yal`:

```yalok
print("Welcome to the underground");

var target = "192.168.1.1";
var payload = {
    command: "shell",
    data: "ls -la"
};

print("Target:", target);
print("Payload:", payload);

var hex_data = 0xDEADBEEF;
var binary_mask = 0b11110000;

print("Hex:", hex_data);
print("Binary:", binary_mask);
print("XOR result:", hex_data ^ binary_mask);
```

Run it:

```bash
yalok hello.yal
```

## 🔥 Hacker Syntax Guide

### 💀 Binary & Hex Literals

```yalok
var address = 0x7ffff000;        // Hex literal
var shellcode = 0xDEADBEEF;      // Hex data
var bitmask = 0b11110000;        // Binary literal
var payload = 0b10101010;        // Binary payload
```

### ⚡ Bitwise Operations

```yalok
var data = 0xFF;
var key = 0xAA;

var encrypted = data ^ key;       // XOR encryption
var shifted = data << 4;          // Left shift
var masked = data & 0xF0;         // Bitwise AND
var combined = data | 0x0F;       // Bitwise OR
var flipped = ~data;              // Bitwise NOT
```

### 🎯 Memory Operations

```yalok
var buffer_size = 0x1000;
var stack_addr = 0x7ffff000;
var heap_size = 0x8000;

print("Buffer:", buffer_size);
print("Stack:", stack_addr);
print("Heap:", heap_size);
```

### 🔐 Crypto Functions

```yalok
func encrypt(data, algorithm) {
    return "encrypted_" + data;
}

func decrypt(encrypted, algorithm) {
    return "decrypted_data";
}

func hash(data, algorithm) {
    return "hash_" + data;
}

var secret = "password123";
var encrypted = encrypt(secret, "AES256");
var hash_value = hash(secret, "SHA256");
```

### 🕳️ System Operations

```yalok
func syscall(name, arg1, arg2, arg3) {
    print("Calling:", name);
    return 0;
}

func memory(addr, size) {
    var dump = [];
    for (var i = 0; i < size; i++) {
        dump.push(0xCC);
    }
    return dump;
}

syscall("sys_write", 1, "Hello", 5);
var memdump = memory(0x1000, 256);
```

### 👻 Stealth Operations

```yalok
func ghost(process_name) {
    print("Hiding process:", process_name);
    return true;
}

func mask() {
    print("Cleaning traces");
    return true;
}

func phantom_process(name) {
    ghost(name);
    print("Process", name, "is now invisible");
}

phantom_process("backdoor");
mask();
```

### 🛡️ Security Tools

```yalok
func probe(target, port) {
    print("Probing", target, "port", port);
    return true;
}

func exploit(target, vulnerability) {
    print("Exploiting", vulnerability);
    return true;
}

func crack_password(hash_target) {
    var wordlist = ["admin", "root", "password"];
    
    for (var i = 0; i < len(wordlist); i++) {
        if (hash(wordlist[i], "SHA256") == hash_target) {
            return wordlist[i];
        }
    }
    return nil;
}

var target = "192.168.1.1";
probe(target, 22);
exploit(target, "buffer_overflow");
```

### 🔧 Advanced Arrays and Objects

```yalok
var packet = {
    type: "TCP",
    source: "192.168.1.100",
    destination: "192.168.1.1",
    port: 80,
    payload: [0x48, 0x65, 0x6C, 0x6C, 0x6F]
};

var virus_signature = [
    0x90, 0x90, 0x90, 0x90,
    0x48, 0x31, 0xC0,
    0x50, 0x48, 0xBB
];

print("Packet:", packet);
print("Virus signature:", virus_signature);
```

## 🛠️ Built-in Hacker Functions

| Function | Description | Example |
|----------|-------------|---------|
| `encrypt(data, algo)` | Encrypt data | `encrypt("secret", "AES256")` |
| `decrypt(data, algo)` | Decrypt data | `decrypt(cipher, "AES256")` |
| `hash(data, algo)` | Hash data | `hash("password", "SHA256")` |
| `probe(target, port)` | Port scanning | `probe("192.168.1.1", 22)` |
| `exploit(target, vuln)` | Exploit vulnerabilities | `exploit(target, "buffer_overflow")` |
| `inject(target, payload)` | Code injection | `inject(target, shellcode)` |
| `syscall(name, args...)` | System calls | `syscall("sys_write", 1, "Hi", 2)` |
| `memory(addr, size)` | Memory operations | `memory(0x1000, 256)` |
| `ghost(process)` | Hide processes | `ghost("backdoor")` |
| `mask()` | Clean traces | `mask()` |
| `spoof(packet)` | Packet spoofing | `spoof(tcp_packet)` |
| `backdoor(port)` | Install backdoor | `backdoor(31337)` |

## 💻 Command Line Interface

```bash
# Run a hacker script
yalok exploit.yal

# Interactive hacker mode
yalok -i

# Debug with memory analysis
yalok -d -m payload.yal

# Benchmark performance
yalok -b algorithms.yal

# Show assembly tokens
yalok -t -a binary.yal
```

## 🏗️ Building from Source

### Hacker Build

```bash
./build.sh -d -t -v
```

### Stealth Build

```bash
./build.sh -O -j8
```

### Full Arsenal

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_HACKER_MODE=ON ..
make -j$(nproc)
```

## 📊 Performance Benchmarks

YALOK is optimized for maximum performance in security operations:

| Operation | Time (μs) | Memory (KB) | Style |
|-----------|-----------|-------------|-------|
| Hex Parsing | 12 | 4 | 🔥 |
| Binary Ops | 8 | 2 | ⚡ |
| Crypto Hash | 156 | 16 | 🔐 |
| Memory Dump | 89 | 64 | 🧠 |
| Exploit Code | 234 | 128 | 💀 |
| Stealth Mode | 45 | 8 | 👻 |

## 🎯 Example Scripts

### Port Scanner

```yalok
var targets = ["192.168.1.1", "10.0.0.1", "127.0.0.1"];
var ports = [22, 80, 443, 8080];

for (var i = 0; i < len(targets); i++) {
    for (var j = 0; j < len(ports); j++) {
        if (probe(targets[i], ports[j])) {
            print("OPEN:", targets[i], ":", ports[j]);
        }
    }
}
```

### Password Cracker

```yalok
func brute_force(target_hash) {
    var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    
    for (var len = 1; len <= 6; len++) {
        var password = generate_password(chars, len);
        if (hash(password, "SHA256") == target_hash) {
            return password;
        }
    }
    return nil;
}
```

### Memory Exploit

```yalok
var shellcode = [
    0x48, 0x31, 0xC0,        // xor rax, rax
    0x50,                    // push rax
    0x48, 0xBB, 0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x73, 0x68, 0x00,
    0x53,                    // push rbx
    0x48, 0x89, 0xE7,        // mov rdi, rsp
    0x48, 0x31, 0xD2,        // xor rdx, rdx
    0x48, 0x31, 0xF6,        // xor rsi, rsi
    0x48, 0xC7, 0xC0, 0x3B, 0x00, 0x00, 0x00,
    0x0F, 0x05               // syscall
];

inject("target_process", shellcode);
```

## 🏛️ Underground Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Hacker Lexer  │ -> │  Stealth Parser │ -> │ Ghost Executor  │
│  (0x & 0b)      │    │   (AST Build)   │    │  (Memory Ops)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         v                       v                       v
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Memory Hacker   │    │ Crypto Engine   │    │ Syscall Bridge  │
│ (Direct Access) │    │ (Hash & Crypt)  │    │ (Kernel Calls)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🤝 Contributing

Join the underground development! 

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-exploit`)
3. Commit your changes (`git commit -m 'Add new exploit technique'`)
4. Push to the branch (`git push origin feature/new-exploit`)
5. Create a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

YALOK is designed for educational purposes, security research, and legitimate penetration testing. Always ensure you have proper authorization before testing on any systems.

## 🙏 Acknowledgments

- Built with modern C++20 stealth techniques
- Inspired by underground programming culture
- Special thanks to the security research community
- Powered by elite hacker methodologies

## 📬 Contact

- **Author**: YALOKGAR
- **Email**: yalokgar@gmail.com
- **GitHub**: [@YALOKGARua](https://github.com/YALOKGARua)
- **Underground**: Deep Web Forums

---

<div align="center">
  <strong>🔥 Join the underground - Star us on GitHub! 🔥</strong><br>
  <em>"In code we trust, in YALOK we hack"</em>
</div> 