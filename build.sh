#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
BUILD_TYPE="Release"
INSTALL_PREFIX="/usr/local"
CLEAN_BUILD=false
RUN_TESTS=false
VERBOSE=false

print_usage() {
    cat << EOF
YALOK Build Script

Usage: $0 [OPTIONS]

Options:
    -h, --help          Show this help message
    -c, --clean         Clean build directory before building
    -d, --debug         Build in debug mode
    -t, --tests         Run tests after building
    -v, --verbose       Verbose output
    -p, --prefix PATH   Installation prefix (default: /usr/local)
    -j, --jobs N        Number of parallel jobs (default: auto)

Examples:
    $0                  # Release build
    $0 -d               # Debug build
    $0 -c -t            # Clean build and run tests
    $0 -d -v            # Debug build with verbose output
EOF
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    echo "[ERROR] $1" >&2
    exit 1
}

check_dependencies() {
    log "Checking dependencies..."
    
    command -v cmake >/dev/null 2>&1 || error "CMake is required but not installed"
    command -v make >/dev/null 2>&1 || error "Make is required but not installed"
    command -v g++ >/dev/null 2>&1 || error "G++ is required but not installed"
    
    CMAKE_VERSION=$(cmake --version | head -n1 | sed 's/cmake version //')
    log "Found CMake version: $CMAKE_VERSION"
    
    GCC_VERSION=$(g++ --version | head -n1)
    log "Found GCC: $GCC_VERSION"
}

configure_build() {
    log "Configuring build..."
    
    if [ "$CLEAN_BUILD" = true ]; then
        log "Cleaning build directory..."
        rm -rf "$BUILD_DIR"
    fi
    
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    CMAKE_ARGS=(
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    )
    
    if [ "$VERBOSE" = true ]; then
        CMAKE_ARGS+=(-DCMAKE_VERBOSE_MAKEFILE=ON)
    fi
    
    log "Running cmake with args: ${CMAKE_ARGS[*]}"
    cmake "${CMAKE_ARGS[@]}" "$SCRIPT_DIR" || error "CMake configuration failed"
}

build_project() {
    log "Building project..."
    
    cd "$BUILD_DIR"
    
    MAKE_ARGS=()
    if [ -n "$JOBS" ]; then
        MAKE_ARGS+=(-j "$JOBS")
    else
        MAKE_ARGS+=(-j "$(nproc)")
    fi
    
    if [ "$VERBOSE" = true ]; then
        MAKE_ARGS+=(VERBOSE=1)
    fi
    
    log "Running make with args: ${MAKE_ARGS[*]}"
    make "${MAKE_ARGS[@]}" || error "Build failed"
    
    log "Build completed successfully!"
}

run_tests() {
    log "Running tests..."
    
    cd "$BUILD_DIR"
    
    if [ -f "yalok" ]; then
        log "Running hello world example..."
        ./yalok "$SCRIPT_DIR/examples/hello.yal" || error "Hello world test failed"
        
        log "Running algorithms example..."
        ./yalok "$SCRIPT_DIR/examples/algorithms.yal" || error "Algorithms test failed"
        
        log "Running functions example..."
        ./yalok "$SCRIPT_DIR/examples/functions.yal" || error "Functions test failed"
        
        log "All tests passed!"
    else
        error "yalok binary not found"
    fi
}

install_project() {
    log "Installing YALOK..."
    
    cd "$BUILD_DIR"
    sudo make install || error "Installation failed"
    
    log "Installation completed!"
    log "You can now run 'yalok' from anywhere"
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                print_usage
                exit 0
                ;;
            -c|--clean)
                CLEAN_BUILD=true
                shift
                ;;
            -d|--debug)
                BUILD_TYPE="Debug"
                shift
                ;;
            -t|--tests)
                RUN_TESTS=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -p|--prefix)
                INSTALL_PREFIX="$2"
                shift 2
                ;;
            -j|--jobs)
                JOBS="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    log "Starting YALOK build process..."
    log "Build type: $BUILD_TYPE"
    log "Install prefix: $INSTALL_PREFIX"
    
    check_dependencies
    configure_build
    build_project
    
    if [ "$RUN_TESTS" = true ]; then
        run_tests
    fi
    
    echo
    log "Build completed successfully!"
    log "Binary location: $BUILD_DIR/yalok"
    echo
    echo "Next steps:"
    echo "  • Run examples: $BUILD_DIR/yalok examples/hello.yal"
    echo "  • Interactive mode: $BUILD_DIR/yalok -i"
    echo "  • Install system-wide: sudo make install -C $BUILD_DIR"
    echo "  • Run tests: $0 -t"
}

main "$@" 