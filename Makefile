CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -Iinclude
SRC = src/main.cpp src/lexer.cpp src/parser.cpp src/interpreter.cpp
OUT = yalok

ifeq ($(OS),Windows_NT)
	OUT = yalok.exe
endif

all: $(OUT)

$(OUT): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(OUT) $(SRC)

clean:
	rm -f $(OUT)

.PHONY: all clean
