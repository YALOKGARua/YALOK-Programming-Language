CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -O2 -march=native
INCLUDES = -Iinclude
SRCDIR = src
OBJDIR = obj
BINDIR = bin

SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
TARGET = $(BINDIR)/yalok

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CXX) $(OBJECTS) -o $@ -lpthread -lssl -lcrypto

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -rf $(OBJDIR) $(BINDIR)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

uninstall:
	sudo rm -f /usr/local/bin/yalok

run: $(TARGET)
	./$(TARGET)

debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

release: CXXFLAGS += -O3 -DNDEBUG
release: $(TARGET)

test: $(TARGET)
	./$(TARGET) examples/test.yal

repl: $(TARGET)
	./$(TARGET) --repl

help:
	@echo "YALOK Compiler Build System"
	@echo "Usage:"
	@echo "  make         - Build the project"
	@echo "  make clean   - Clean build files"
	@echo "  make install - Install to /usr/local/bin"
	@echo "  make run     - Run the compiled program"
	@echo "  make debug   - Build with debug flags"
	@echo "  make release - Build with release flags"
	@echo "  make test    - Run tests"
	@echo "  make repl    - Start REPL mode" 