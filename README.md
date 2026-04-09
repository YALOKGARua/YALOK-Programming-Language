# YALOK

**Systems language by YALOKGAR.**

Designed for binary data, byte manipulation, and low-level operations.
Every keyword is unique -- YALOK doesn't look like any other language.

## Build

```bash
cmake -B build && cmake --build build
```

## Run

```bash
yalok examples/hello.yal
yalok                        # REPL
```

## Syntax

### Variables

```
load x: i64 = 42              # immutable
cell y: str = "hello"          # mutable
load mask: i64 = 0xFF00
load flag: i64 = 0b11001010
```

`load` -- immutable. `cell` -- mutable (memory cell).

### Procedures

```
proc add(a: i64, b: i64) -> i64 {
    ret a + b
}

proc greet(name: str) {
    echo("hello", name)
}
```

### Buffers

First-class byte arrays.

```
load data: buf = [0x48, 0x65, 0x6C, 0x6C, 0x6F]
cell raw: buf = alloc(1024)
raw[0] = 0xFF
hexdump(raw)
```

### Packet

Binary struct definitions.

```
packet Header {
    magic: i64,
    version: i64,
    size: i64,
}

load h = Header { magic: 0x59414C, version: 1, size: 64 }
echo(h.magic)
```

### Probe

Inspect any value -- hex dump, type, like a built-in debugger.

```
probe data       # [PROBE] <buf:5> 48 65 6C 6C 6F |Hello|
probe h          # [PROBE] <Header> magic=0x59414C version=1 size=64
probe x          # [PROBE] <i64> 42 (0x2A)
```

### Breach

Unsafe block -- signals raw memory intent.

```
breach {
    cell raw: buf = alloc(4096)
    raw[0] = 0xCC
}
```

### Pipe

```
load result = data |> encrypt |> compress
```

### Control Flow

```
check x > 10 {
    echo("big")
} alt {
    echo("small")
}

loop running {
    # ...
}

scan i thru 0..100 {
    echo(i)
}

gate status {
    0 => echo("ok"),
    1 => echo("error"),
    _ => echo("???"),
}
```

### Boolean Values

```
load active = on
load disabled = off
```

### Bitwise

```
load masked = value & 0xFF
load shifted = value << 4
cell flags: i64 = 0
flags |= 0x01
flags ^= 0xFF
```

### Flow Control

```
halt       # break out of loop
skip       # continue to next iteration
ret value  # return from proc
```

## Keywords

| Keyword | Purpose |
|---------|---------|
| `load` | Immutable binding |
| `cell` | Mutable binding |
| `proc` | Procedure definition |
| `ret` | Return value |
| `check` | Conditional |
| `alt` | Else branch |
| `loop` | While loop |
| `scan` | Range iteration |
| `thru` | Range separator |
| `gate` | Pattern matching |
| `packet` | Binary struct |
| `probe` | Value inspection |
| `breach` | Unsafe block |
| `halt` | Break |
| `skip` | Continue |
| `on` | True |
| `off` | False |
| `nil` | Null |

## Built-in Functions

| Function | Description |
|----------|-------------|
| `echo(...)` | Print with newline |
| `emit(...)` | Print without newline |
| `size(x)` | Length of str or buf |
| `hex(x)` | To hex string |
| `bits(x)` | To binary string |
| `alloc(n)` | Create zero buf |
| `hexdump(buf)` | Full hex dump |
| `identify(x)` | Type name |
| `str(x)` | To string |
| `i64(x)` | To integer |
| `f64(x)` | To float |
| `input()` | Read stdin |
| `tick()` | Time in ms |
| `rand(a, b)` | Random integer |
| `push(buf, byte)` | Append byte |
| `pop(buf)` | Remove last byte |
| `slice(buf, s, e)` | Sub-buffer |
| `chr(n)` | Int to char |
| `ord(s)` | Char to int |
| `kill(code)` | Exit process |

## Comments

```
# single line comment
// also works
/* block comment */
```

## File Extension

`.yal`

## License

See LICENSE.
