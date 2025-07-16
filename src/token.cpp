#include <yalok/token.hpp>
#include <unordered_map>
#include <string>
#include <string_view>
#include <algorithm>
#include <ranges>
#include <format>
#include <bit>
#include <concepts>
#include <type_traits>
#include <array>
#include <span>
#include <immintrin.h>
#include <atomic>
#include <memory_resource>

namespace yalok {

constexpr std::array<std::pair<std::string_view, TokenType>, 512> KEYWORD_MAP = {{
    {"let", TokenType::LET},
    {"const", TokenType::CONST},
    {"var", TokenType::VAR},
    {"func", TokenType::FUNC},
    {"return", TokenType::RETURN},
    {"if", TokenType::IF},
    {"else", TokenType::ELSE},
    {"elif", TokenType::ELIF},
    {"while", TokenType::WHILE},
    {"for", TokenType::FOR},
    {"in", TokenType::IN},
    {"of", TokenType::OF},
    {"do", TokenType::DO},
    {"break", TokenType::BREAK},
    {"continue", TokenType::CONTINUE},
    {"switch", TokenType::SWITCH},
    {"case", TokenType::CASE},
    {"default", TokenType::DEFAULT},
    {"try", TokenType::TRY},
    {"catch", TokenType::CATCH},
    {"finally", TokenType::FINALLY},
    {"throw", TokenType::THROW},
    {"class", TokenType::CLASS},
    {"extends", TokenType::EXTENDS},
    {"super", TokenType::SUPER},
    {"this", TokenType::THIS},
    {"new", TokenType::NEW},
    {"delete", TokenType::DELETE},
    {"typeof", TokenType::TYPEOF},
    {"instanceof", TokenType::INSTANCEOF},
    {"true", TokenType::TRUE},
    {"false", TokenType::FALSE},
    {"nil", TokenType::NIL},
    {"null", TokenType::NULL_TOKEN},
    {"undefined", TokenType::UNDEFINED},
    {"import", TokenType::IMPORT},
    {"export", TokenType::EXPORT},
    {"from", TokenType::FROM},
    {"as", TokenType::AS},
    {"async", TokenType::ASYNC},
    {"await", TokenType::AWAIT},
    {"yield", TokenType::YIELD},
    {"static", TokenType::STATIC},
    {"public", TokenType::PUBLIC},
    {"private", TokenType::PRIVATE},
    {"protected", TokenType::PROTECTED},
    {"abstract", TokenType::ABSTRACT},
    {"final", TokenType::FINAL},
    {"override", TokenType::OVERRIDE},
    {"virtual", TokenType::VIRTUAL},
    {"interface", TokenType::INTERFACE},
    {"implements", TokenType::IMPLEMENTS},
    {"enum", TokenType::ENUM},
    {"struct", TokenType::STRUCT},
    {"union", TokenType::UNION},
    {"namespace", TokenType::NAMESPACE},
    {"using", TokenType::USING},
    {"typedef", TokenType::TYPEDEF},
    {"template", TokenType::TEMPLATE},
    {"typename", TokenType::TYPENAME},
    {"auto", TokenType::AUTO},
    {"decltype", TokenType::DECLTYPE},
    {"constexpr", TokenType::CONSTEXPR},
    {"consteval", TokenType::CONSTEVAL},
    {"constinit", TokenType::CONSTINIT},
    {"concept", TokenType::CONCEPT},
    {"requires", TokenType::REQUIRES},
    {"co_await", TokenType::CO_AWAIT},
    {"co_yield", TokenType::CO_YIELD},
    {"co_return", TokenType::CO_RETURN},
    {"module", TokenType::MODULE},
    {"and", TokenType::AND},
    {"or", TokenType::OR},
    {"not", TokenType::NOT},
    {"xor", TokenType::XOR},
    {"bitand", TokenType::BITAND},
    {"bitor", TokenType::BITOR},
    {"compl", TokenType::COMPL},
    {"match", TokenType::MATCH},
    {"when", TokenType::WHEN},
    {"with", TokenType::WITH},
    {"where", TokenType::WHERE},
    {"select", TokenType::SELECT},
    {"join", TokenType::JOIN},
    {"group", TokenType::GROUP},
    {"order", TokenType::ORDER},
    {"having", TokenType::HAVING},
    {"limit", TokenType::LIMIT},
    {"offset", TokenType::OFFSET},
    {"intersect", TokenType::INTERSECT},
    {"except", TokenType::EXCEPT},
    {"distinct", TokenType::DISTINCT},
    {"all", TokenType::ALL},
    {"any", TokenType::ANY},
    {"some", TokenType::SOME},
    {"exists", TokenType::EXISTS},
    {"between", TokenType::BETWEEN},
    {"like", TokenType::LIKE},
    {"glob", TokenType::GLOB},
    {"regexp", TokenType::REGEXP},
    {"is", TokenType::IS},
    {"isnull", TokenType::ISNULL},
    {"notnull", TokenType::NOTNULL},
    {"collate", TokenType::COLLATE},
    {"escape", TokenType::ESCAPE},
    {"cast", TokenType::CAST},
    {"then", TokenType::THEN},
    {"end", TokenType::END},
    {"hack", TokenType::HACK},
    {"crack", TokenType::CRACK},
    {"pwn", TokenType::PWN},
    {"exploit", TokenType::EXPLOIT},
    {"payload", TokenType::PAYLOAD},
    {"inject", TokenType::INJECT},
    {"shell", TokenType::SHELL},
    {"root", TokenType::ROOT},
    {"admin", TokenType::ADMIN},
    {"sudo", TokenType::SUDO},
    {"su", TokenType::SU},
    {"chmod", TokenType::CHMOD},
    {"chown", TokenType::CHOWN},
    {"setuid", TokenType::SETUID},
    {"setgid", TokenType::SETGID},
    {"sticky", TokenType::STICKY},
    {"umask", TokenType::UMASK},
    {"proc", TokenType::PROC},
    {"dev", TokenType::DEV},
    {"sys", TokenType::SYS},
    {"tmp", TokenType::TMP},
    {"etc", TokenType::ETC},
    {"bin", TokenType::BIN},
    {"sbin", TokenType::SBIN},
    {"usr", TokenType::USR},
    {"lib", TokenType::LIB},
    {"lib64", TokenType::LIB64},
    {"opt", TokenType::OPT},
    {"home", TokenType::HOME},
    {"boot", TokenType::BOOT},
    {"mnt", TokenType::MNT},
    {"media", TokenType::MEDIA},
    {"run", TokenType::RUN},
    {"srv", TokenType::SRV},
    {"encrypt", TokenType::ENCRYPT},
    {"decrypt", TokenType::DECRYPT},
    {"hash", TokenType::HASH},
    {"md5", TokenType::MD5},
    {"sha1", TokenType::SHA1},
    {"sha256", TokenType::SHA256},
    {"sha512", TokenType::SHA512},
    {"hmac", TokenType::HMAC},
    {"pbkdf2", TokenType::PBKDF2},
    {"scrypt", TokenType::SCRYPT},
    {"bcrypt", TokenType::BCRYPT},
    {"argon2", TokenType::ARGON2},
    {"aes", TokenType::AES},
    {"des", TokenType::DES},
    {"rsa", TokenType::RSA},
    {"dsa", TokenType::DSA},
    {"ecdsa", TokenType::ECDSA},
    {"ed25519", TokenType::ED25519},
    {"curve25519", TokenType::CURVE25519},
    {"secp256k1", TokenType::SECP256K1},
    {"p256", TokenType::P256},
    {"p384", TokenType::P384},
    {"p521", TokenType::P521},
    {"scan", TokenType::SCAN},
    {"probe", TokenType::PROBE},
    {"discover", TokenType::DISCOVER},
    {"fingerprint", TokenType::FINGERPRINT},
    {"banner", TokenType::BANNER},
    {"version", TokenType::VERSION},
    {"service", TokenType::SERVICE},
    {"port", TokenType::PORT},
    {"tcp", TokenType::TCP},
    {"udp", TokenType::UDP},
    {"icmp", TokenType::ICMP},
    {"ip", TokenType::IP},
    {"ipv4", TokenType::IPV4},
    {"ipv6", TokenType::IPV6},
    {"mac", TokenType::MAC},
    {"arp", TokenType::ARP},
    {"dns", TokenType::DNS},
    {"dhcp", TokenType::DHCP},
    {"http", TokenType::HTTP},
    {"https", TokenType::HTTPS},
    {"ftp", TokenType::FTP},
    {"sftp", TokenType::SFTP},
    {"ssh", TokenType::SSH},
    {"telnet", TokenType::TELNET},
    {"smtp", TokenType::SMTP},
    {"pop3", TokenType::POP3},
    {"imap", TokenType::IMAP},
    {"snmp", TokenType::SNMP},
    {"ldap", TokenType::LDAP},
    {"kerberos", TokenType::KERBEROS},
    {"ntlm", TokenType::NTLM},
    {"oauth", TokenType::OAUTH},
    {"jwt", TokenType::JWT},
    {"saml", TokenType::SAML},
    {"breach", TokenType::BREACH},
    {"backdoor", TokenType::BACKDOOR},
    {"trojan", TokenType::TROJAN},
    {"virus", TokenType::VIRUS},
    {"worm", TokenType::WORM},
    {"malware", TokenType::MALWARE},
    {"spyware", TokenType::SPYWARE},
    {"adware", TokenType::ADWARE},
    {"ransomware", TokenType::RANSOMWARE},
    {"rootkit", TokenType::ROOTKIT},
    {"bootkit", TokenType::BOOTKIT},
    {"firmware", TokenType::FIRMWARE},
    {"uefi", TokenType::UEFI},
    {"bios", TokenType::BIOS},
    {"mbr", TokenType::MBR},
    {"gpt", TokenType::GPT},
    {"partition", TokenType::PARTITION},
    {"sector", TokenType::SECTOR},
    {"cluster", TokenType::CLUSTER},
    {"inode", TokenType::INODE},
    {"filesystem", TokenType::FILESYSTEM},
    {"ext2", TokenType::EXT2},
    {"ext3", TokenType::EXT3},
    {"ext4", TokenType::EXT4},
    {"ntfs", TokenType::NTFS},
    {"fat32", TokenType::FAT32},
    {"exfat", TokenType::EXFAT},
    {"xfs", TokenType::XFS},
    {"btrfs", TokenType::BTRFS},
    {"zfs", TokenType::ZFS},
    {"keylog", TokenType::KEYLOG},
    {"keylogger", TokenType::KEYLOGGER},
    {"screenlog", TokenType::SCREENLOG},
    {"mic", TokenType::MIC},
    {"camera", TokenType::CAMERA},
    {"webcam", TokenType::WEBCAM},
    {"audio", TokenType::AUDIO},
    {"video", TokenType::VIDEO},
    {"screenshot", TokenType::SCREENSHOT},
    {"screencast", TokenType::SCREENCAST},
    {"record", TokenType::RECORD},
    {"capture", TokenType::CAPTURE},
    {"monitor", TokenType::MONITOR},
    {"surveillance", TokenType::SURVEILLANCE},
    {"spy", TokenType::SPY},
    {"watch", TokenType::WATCH},
    {"track", TokenType::TRACK},
    {"trace", TokenType::TRACE},
    {"log", TokenType::LOG},
    {"audit", TokenType::AUDIT},
    {"forensic", TokenType::FORENSIC},
    {"evidence", TokenType::EVIDENCE},
    {"artifact", TokenType::ARTIFACT},
    {"metadata", TokenType::METADATA},
    {"exif", TokenType::EXIF},
    {"steganography", TokenType::STEGANOGRAPHY},
    {"stego", TokenType::STEGO},
    {"hide", TokenType::HIDE},
    {"conceal", TokenType::CONCEAL},
    {"obfuscate", TokenType::OBFUSCATE},
    {"encode", TokenType::ENCODE},
    {"decode", TokenType::DECODE},
    {"base64", TokenType::BASE64},
    {"base32", TokenType::BASE32},
    {"base16", TokenType::BASE16},
    {"hex", TokenType::HEX},
    {"ascii", TokenType::ASCII},
    {"utf8", TokenType::UTF8},
    {"utf16", TokenType::UTF16},
    {"utf32", TokenType::UTF32},
    {"unicode", TokenType::UNICODE},
    {"sniff", TokenType::SNIFF},
    {"sniffer", TokenType::SNIFFER},
    {"packet", TokenType::PACKET},
    {"pcap", TokenType::PCAP},
    {"wireshark", TokenType::WIRESHARK},
    {"tcpdump", TokenType::TCPDUMP},
    {"netstat", TokenType::NETSTAT},
    {"ss", TokenType::SS},
    {"lsof", TokenType::LSOF},
    {"ps", TokenType::PS},
    {"top", TokenType::TOP},
    {"htop", TokenType::HTOP},
    {"iotop", TokenType::IOTOP},
    {"strace", TokenType::STRACE},
    {"ltrace", TokenType::LTRACE},
    {"ptrace", TokenType::PTRACE},
    {"gdb", TokenType::GDB},
    {"lldb", TokenType::LLDB},
    {"valgrind", TokenType::VALGRIND},
    {"perf", TokenType::PERF},
    {"objdump", TokenType::OBJDUMP},
    {"readelf", TokenType::READELF},
    {"nm", TokenType::NM},
    {"strings", TokenType::STRINGS},
    {"file", TokenType::FILE},
    {"hexdump", TokenType::HEXDUMP},
    {"xxd", TokenType::XXD},
    {"od", TokenType::OD},
    {"dd", TokenType::DD},
    {"spoof", TokenType::SPOOF},
    {"spoofing", TokenType::SPOOFING},
    {"mitm", TokenType::MITM},
    {"proxy", TokenType::PROXY},
    {"tunnel", TokenType::TUNNEL},
    {"vpn", TokenType::VPN},
    {"tor", TokenType::TOR},
    {"i2p", TokenType::I2P},
    {"onion", TokenType::ONION},
    {"darknet", TokenType::DARKNET},
    {"deepweb", TokenType::DEEPWEB},
    {"anonymous", TokenType::ANONYMOUS},
    {"anon", TokenType::ANON},
    {"privacy", TokenType::PRIVACY},
    {"security", TokenType::SECURITY},
    {"pentest", TokenType::PENTEST},
    {"redteam", TokenType::REDTEAM},
    {"blueteam", TokenType::BLUETEAM},
    {"ctf", TokenType::CTF},
    {"wargame", TokenType::WARGAME},
    {"challenge", TokenType::CHALLENGE},
    {"flag", TokenType::FLAG},
    {"score", TokenType::SCORE},
    {"points", TokenType::POINTS},
    {"rank", TokenType::RANK},
    {"leaderboard", TokenType::LEADERBOARD},
    {"mask", TokenType::MASK},
    {"masking", TokenType::MASKING},
    {"unmask", TokenType::UNMASK},
    {"reveal", TokenType::REVEAL},
    {"expose", TokenType::EXPOSE},
    {"leak", TokenType::LEAK},
    {"dump", TokenType::DUMP},
    {"extract", TokenType::EXTRACT},
    {"exfiltrate", TokenType::EXFILTRATE},
    {"infiltrate", TokenType::INFILTRATE},
    {"lateral", TokenType::LATERAL},
    {"pivot", TokenType::PIVOT},
    {"persist", TokenType::PERSIST},
    {"persistence", TokenType::PERSISTENCE},
    {"escalate", TokenType::ESCALATE},
    {"privilege", TokenType::PRIVILEGE},
    {"elevation", TokenType::ELEVATION},
    {"ghost", TokenType::GHOST},
    {"phantom", TokenType::PHANTOM},
    {"shadow", TokenType::SHADOW},
    {"stealth", TokenType::STEALTH},
    {"silent", TokenType::SILENT},
    {"quiet", TokenType::QUIET},
    {"covert", TokenType::COVERT},
    {"evasion", TokenType::EVASION},
    {"evade", TokenType::EVADE},
    {"avoid", TokenType::AVOID},
    {"bypass", TokenType::BYPASS},
    {"circumvent", TokenType::CIRCUMVENT},
    {"defeat", TokenType::DEFEAT},
    {"overcome", TokenType::OVERCOME},
    {"bruteforce", TokenType::BRUTEFORCE},
    {"dictionary", TokenType::DICTIONARY},
    {"wordlist", TokenType::WORDLIST},
    {"rainbow", TokenType::RAINBOW},
    {"table", TokenType::TABLE},
    {"salt", TokenType::SALT},
    {"pepper", TokenType::PEPPER},
    {"nonce", TokenType::NONCE},
    {"iv", TokenType::IV},
    {"key", TokenType::KEY},
    {"keyfile", TokenType::KEYFILE},
    {"keychain", TokenType::KEYCHAIN},
    {"keyring", TokenType::KEYRING},
    {"certificate", TokenType::CERTIFICATE},
    {"cert", TokenType::CERT},
    {"crl", TokenType::CRL},
    {"csr", TokenType::CSR},
    {"pem", TokenType::PEM},
    {"der", TokenType::DER},
    {"p12", TokenType::P12},
    {"pfx", TokenType::PFX},
    {"jks", TokenType::JKS},
    {"binary", TokenType::BINARY},
    {"exe", TokenType::EXE},
    {"dll", TokenType::DLL},
    {"so", TokenType::SO},
    {"dylib", TokenType::DYLIB},
    {"elf", TokenType::ELF},
    {"pe", TokenType::PE},
    {"macho", TokenType::MACHO},
    {"coff", TokenType::COFF},
    {"obj", TokenType::OBJ},
    {"ar", TokenType::AR},
    {"tar", TokenType::TAR},
    {"zip", TokenType::ZIP},
    {"rar", TokenType::RAR},
    {"7z", TokenType::SEVEN_Z},
    {"gz", TokenType::GZ},
    {"bz2", TokenType::BZ2},
    {"xz", TokenType::XZ},
    {"lzma", TokenType::LZMA},
    {"lz4", TokenType::LZ4},
    {"zstd", TokenType::ZSTD},
    {"compress", TokenType::COMPRESS},
    {"decompress", TokenType::DECOMPRESS},
    {"archive", TokenType::ARCHIVE},
    {"unarchive", TokenType::UNARCHIVE},
    {"pack", TokenType::PACK},
    {"unpack", TokenType::UNPACK},
    {"byte", TokenType::BYTE},
    {"word", TokenType::WORD},
    {"dword", TokenType::DWORD},
    {"qword", TokenType::QWORD},
    {"bit", TokenType::BIT},
    {"nibble", TokenType::NIBBLE},
    {"octet", TokenType::OCTET},
    {"buffer", TokenType::BUFFER},
    {"overflow", TokenType::OVERFLOW},
    {"underflow", TokenType::UNDERFLOW},
    {"stack", TokenType::STACK},
    {"heap", TokenType::HEAP},
    {"bss", TokenType::BSS},
    {"data", TokenType::DATA},
    {"text", TokenType::TEXT},
    {"rodata", TokenType::RODATA},
    {"got", TokenType::GOT},
    {"plt", TokenType::PLT},
    {"relocation", TokenType::RELOCATION},
    {"symbol", TokenType::SYMBOL},
    {"dynamic", TokenType::DYNAMIC},
    {"shared", TokenType::SHARED},
    {"library", TokenType::LIBRARY},
    {"loader", TokenType::LOADER},
    {"linker", TokenType::LINKER},
    {"assembler", TokenType::ASSEMBLER},
    {"compiler", TokenType::COMPILER},
    {"interpreter", TokenType::INTERPRETER},
    {"vm", TokenType::VM},
    {"jit", TokenType::JIT},
    {"aot", TokenType::AOT},
    {"bytecode", TokenType::BYTECODE},
    {"opcode", TokenType::OPCODE},
    {"instruction", TokenType::INSTRUCTION},
    {"mnemonic", TokenType::MNEMONIC},
    {"operand", TokenType::OPERAND},
    {"register", TokenType::REGISTER},
    {"eax", TokenType::EAX},
    {"ebx", TokenType::EBX},
    {"ecx", TokenType::ECX},
    {"edx", TokenType::EDX},
    {"esi", TokenType::ESI},
    {"edi", TokenType::EDI},
    {"esp", TokenType::ESP},
    {"ebp", TokenType::EBP},
    {"eip", TokenType::EIP},
    {"rax", TokenType::RAX},
    {"rbx", TokenType::RBX},
    {"rcx", TokenType::RCX},
    {"rdx", TokenType::RDX},
    {"rsi", TokenType::RSI},
    {"rdi", TokenType::RDI},
    {"rsp", TokenType::RSP},
    {"rbp", TokenType::RBP},
    {"rip", TokenType::RIP},
    {"r8", TokenType::R8},
    {"r9", TokenType::R9},
    {"r10", TokenType::R10},
    {"r11", TokenType::R11},
    {"r12", TokenType::R12},
    {"r13", TokenType::R13},
    {"r14", TokenType::R14},
    {"r15", TokenType::R15},
    {"cs", TokenType::CS},
    {"ds", TokenType::DS},
    {"es", TokenType::ES},
    {"fs", TokenType::FS},
    {"gs", TokenType::GS},
    {"flags", TokenType::FLAGS},
    {"eflags", TokenType::EFLAGS},
    {"rflags", TokenType::RFLAGS},
    {"cf", TokenType::CF},
    {"pf", TokenType::PF},
    {"af", TokenType::AF},
    {"zf", TokenType::ZF},
    {"sf", TokenType::SF},
    {"tf", TokenType::TF},
    {"df", TokenType::DF},
    {"of", TokenType::OF},
    {"iopl", TokenType::IOPL},
    {"nt", TokenType::NT},
    {"rf", TokenType::RF},
    {"ac", TokenType::AC},
    {"vif", TokenType::VIF},
    {"vip", TokenType::VIP},
    {"id", TokenType::ID},
    {"memory", TokenType::MEMORY},
    {"mem", TokenType::MEM},
    {"ram", TokenType::RAM},
    {"rom", TokenType::ROM},
    {"flash", TokenType::FLASH},
    {"eeprom", TokenType::EEPROM},
    {"cache", TokenType::CACHE},
    {"l1", TokenType::L1},
    {"l2", TokenType::L2},
    {"l3", TokenType::L3},
    {"tlb", TokenType::TLB},
    {"mmu", TokenType::MMU},
    {"page", TokenType::PAGE},
    {"frame", TokenType::FRAME},
    {"segment", TokenType::SEGMENT},
    {"physical", TokenType::PHYSICAL},
    {"linear", TokenType::LINEAR},
    {"logical", TokenType::LOGICAL},
    {"address", TokenType::ADDRESS},
    {"addr", TokenType::ADDR},
    {"pointer", TokenType::POINTER},
    {"ptr", TokenType::PTR},
    {"reference", TokenType::REFERENCE},
    {"ref", TokenType::REF},
    {"base", TokenType::BASE},
    {"size", TokenType::SIZE},
    {"length", TokenType::LENGTH},
    {"len", TokenType::LEN},
    {"count", TokenType::COUNT},
    {"index", TokenType::INDEX},
    {"idx", TokenType::IDX},
    {"position", TokenType::POSITION},
    {"pos", TokenType::POS},
    {"location", TokenType::LOCATION},
    {"loc", TokenType::LOC},
    {"syscall", TokenType::SYSCALL},
    {"sysenter", TokenType::SYSENTER},
    {"sysexit", TokenType::SYSEXIT},
    {"int", TokenType::INT},
    {"interrupt", TokenType::INTERRUPT},
    {"irq", TokenType::IRQ},
    {"nmi", TokenType::NMI},
    {"exception", TokenType::EXCEPTION},
    {"fault", TokenType::FAULT},
    {"trap", TokenType::TRAP},
    {"abort", TokenType::ABORT},
    {"signal", TokenType::SIGNAL},
    {"sigkill", TokenType::SIGKILL},
    {"sigterm", TokenType::SIGTERM},
    {"sigstop", TokenType::SIGSTOP},
    {"sigcont", TokenType::SIGCONT},
    {"sigint", TokenType::SIGINT},
    {"sigquit", TokenType::SIGQUIT},
    {"sigusr1", TokenType::SIGUSR1},
    {"sigusr2", TokenType::SIGUSR2},
    {"sigpipe", TokenType::SIGPIPE},
    {"sigalrm", TokenType::SIGALRM},
    {"sigchld", TokenType::SIGCHLD},
    {"sigwinch", TokenType::SIGWINCH},
    {"sigtstp", TokenType::SIGTSTP},
    {"sigttin", TokenType::SIGTTIN},
    {"sigttou", TokenType::SIGTTOU},
    {"sigurg", TokenType::SIGURG},
    {"sigxcpu", TokenType::SIGXCPU},
    {"sigxfsz", TokenType::SIGXFSZ},
    {"sigvtalrm", TokenType::SIGVTALRM},
    {"sigprof", TokenType::SIGPROF},
    {"sigbus", TokenType::SIGBUS},
    {"sigsegv", TokenType::SIGSEGV},
    {"sigfpe", TokenType::SIGFPE},
    {"sigill", TokenType::SIGILL},
    {"sigtrap", TokenType::SIGTRAP},
    {"sigabrt", TokenType::SIGABRT},
    {"sigiot", TokenType::SIGIOT},
    {"sigemt", TokenType::SIGEMT},
    {"sigsys", TokenType::SIGSYS},
    {"thread", TokenType::THREAD},
    {"process", TokenType::PROCESS},
    {"task", TokenType::TASK},
    {"job", TokenType::JOB},
    {"daemon", TokenType::DAEMON},
    {"worker", TokenType::WORKER},
    {"scheduler", TokenType::SCHEDULER},
    {"mutex", TokenType::MUTEX},
    {"semaphore", TokenType::SEMAPHORE},
    {"lock", TokenType::LOCK},
    {"unlock", TokenType::UNLOCK},
    {"atomic", TokenType::ATOMIC},
    {"volatile", TokenType::VOLATILE},
    {"barrier", TokenType::BARRIER},
    {"fence", TokenType::FENCE},
    {"synchronize", TokenType::SYNCHRONIZE},
    {"future", TokenType::FUTURE},
    {"promise", TokenType::PROMISE},
    {"coroutine", TokenType::COROUTINE},
    {"generator", TokenType::GENERATOR},
    {"iterator", TokenType::ITERATOR},
    {"stream", TokenType::STREAM},
    {"channel", TokenType::CHANNEL},
    {"queue", TokenType::QUEUE},
    {"deque", TokenType::DEQUE},
    {"list", TokenType::LIST},
    {"vector", TokenType::VECTOR},
    {"array", TokenType::ARRAY},
    {"map", TokenType::MAP},
    {"set", TokenType::SET},
    {"tree", TokenType::TREE},
    {"graph", TokenType::GRAPH},
    {"node", TokenType::NODE},
    {"edge", TokenType::EDGE},
    {"vertex", TokenType::VERTEX},
    {"path", TokenType::PATH},
    {"cycle", TokenType::CYCLE},
    {"loop", TokenType::LOOP},
    {"branch", TokenType::BRANCH},
    {"jump", TokenType::JUMP},
    {"call", TokenType::CALL},
    {"push", TokenType::PUSH},
    {"pop", TokenType::POP},
    {"peek", TokenType::PEEK},
    {"front", TokenType::FRONT},
    {"back", TokenType::BACK},
    {"begin", TokenType::BEGIN},
    {"first", TokenType::FIRST},
    {"last", TokenType::LAST},
    {"next", TokenType::NEXT},
    {"prev", TokenType::PREV},
    {"current", TokenType::CURRENT},
    {"head", TokenType::HEAD},
    {"tail", TokenType::TAIL},
    {"leaf", TokenType::LEAF},
    {"parent", TokenType::PARENT},
    {"child", TokenType::CHILD},
    {"sibling", TokenType::SIBLING},
    {"ancestor", TokenType::ANCESTOR},
    {"descendant", TokenType::DESCENDANT},
    {"depth", TokenType::DEPTH},
    {"height", TokenType::HEIGHT},
    {"level", TokenType::LEVEL},
    {"degree", TokenType::DEGREE},
    {"weight", TokenType::WEIGHT},
    {"distance", TokenType::DISTANCE},
    {"cost", TokenType::COST},
    {"value", TokenType::VALUE},
    {"info", TokenType::INFO},
    {"attribute", TokenType::ATTRIBUTE},
    {"property", TokenType::PROPERTY},
    {"field", TokenType::FIELD},
    {"member", TokenType::MEMBER},
    {"element", TokenType::ELEMENT},
    {"item", TokenType::ITEM},
    {"entry", TokenType::ENTRY},
    {"row", TokenType::ROW},
    {"column", TokenType::COLUMN},
    {"cell", TokenType::CELL},
    {"tuple", TokenType::TUPLE},
    {"pair", TokenType::PAIR},
    {"triple", TokenType::TRIPLE},
    {"quad", TokenType::QUAD},
    {"object", TokenType::OBJECT},
    {"instance", TokenType::INSTANCE},
    {"type", TokenType::TYPE},
    {"trait", TokenType::TRAIT},
    {"mixin", TokenType::MIXIN},
    {"package", TokenType::PACKAGE},
    {"scope", TokenType::SCOPE},
    {"context", TokenType::CONTEXT},
    {"environment", TokenType::ENVIRONMENT},
    {"closure", TokenType::CLOSURE},
    {"lambda", TokenType::LAMBDA},
    {"function", TokenType::FUNCTION},
    {"method", TokenType::METHOD},
    {"procedure", TokenType::PROCEDURE},
    {"routine", TokenType::ROUTINE},
    {"subroutine", TokenType::SUBROUTINE},
    {"macro", TokenType::MACRO},
    {"generic", TokenType::GENERIC},
    {"polymorphic", TokenType::POLYMORPHIC},
    {"monomorphic", TokenType::MONOMORPHIC},
    {"concrete", TokenType::CONCRETE},
    {"sealed", TokenType::SEALED},
    {"implement", TokenType::IMPLEMENT},
    {"extend", TokenType::EXTEND},
    {"inherit", TokenType::INHERIT},
    {"derive", TokenType::DERIVE},
    {"compose", TokenType::COMPOSE},
    {"delegate", TokenType::DELEGATE},
    {"wrapper", TokenType::WRAPPER},
    {"adapter", TokenType::ADAPTER},
    {"facade", TokenType::FACADE},
    {"decorator", TokenType::DECORATOR},
    {"observer", TokenType::OBSERVER},
    {"visitor", TokenType::VISITOR},
    {"strategy", TokenType::STRATEGY},
    {"factory", TokenType::FACTORY},
    {"builder", TokenType::BUILDER},
    {"singleton", TokenType::SINGLETON},
    {"prototype", TokenType::PROTOTYPE},
    {"flyweight", TokenType::FLYWEIGHT},
    {"command", TokenType::COMMAND},
    {"mediator", TokenType::MEDIATOR},
    {"memento", TokenType::MEMENTO},
    {"state", TokenType::STATE},
    {"chain", TokenType::CHAIN},
    {"composite", TokenType::COMPOSITE},
    {"bridge", TokenType::BRIDGE},
    {"mvc", TokenType::MVC},
    {"mvp", TokenType::MVP},
    {"mvvm", TokenType::MVVM},
    {"dao", TokenType::DAO},
    {"dto", TokenType::DTO},
    {"pojo", TokenType::POJO},
    {"bean", TokenType::BEAN},
    {"entity", TokenType::ENTITY},
    {"model", TokenType::MODEL},
    {"view", TokenType::VIEW},
    {"controller", TokenType::CONTROLLER},
    {"presenter", TokenType::PRESENTER},
    {"repository", TokenType::REPOSITORY},
    {"component", TokenType::COMPONENT},
    {"widget", TokenType::WIDGET},
    {"plugin", TokenType::PLUGIN},
    {"addon", TokenType::ADDON},
    {"extension", TokenType::EXTENSION},
    {"hook", TokenType::HOOK},
    {"filter", TokenType::FILTER},
    {"interceptor", TokenType::INTERCEPTOR},
    {"middleware", TokenType::MIDDLEWARE},
    {"pipeline", TokenType::PIPELINE},
    {"workflow", TokenType::WORKFLOW},
    {"batch", TokenType::BATCH},
    {"dispatcher", TokenType::DISPATCHER},
    {"executor", TokenType::EXECUTOR},
    {"runner", TokenType::RUNNER},
    {"handler", TokenType::HANDLER},
    {"listener", TokenType::LISTENER},
    {"callback", TokenType::CALLBACK},
    {"event", TokenType::EVENT},
    {"trigger", TokenType::TRIGGER},
    {"action", TokenType::ACTION},
    {"reaction", TokenType::REACTION},
    {"response", TokenType::RESPONSE},
    {"request", TokenType::REQUEST},
    {"message", TokenType::MESSAGE},
    {"notification", TokenType::NOTIFICATION},
    {"alert", TokenType::ALERT},
    {"warning", TokenType::WARNING},
    {"error", TokenType::ERROR},
    {"failure", TokenType::FAILURE},
    {"crash", TokenType::CRASH},
    {"panic", TokenType::PANIC},
    {"exit", TokenType::EXIT},
    {"quit", TokenType::QUIT},
    {"terminate", TokenType::TERMINATE},
    {"kill", TokenType::KILL},
    {"destroy", TokenType::DESTROY},
    {"remove", TokenType::REMOVE},
    {"clear", TokenType::CLEAR},
    {"reset", TokenType::RESET},
    {"restart", TokenType::RESTART},
    {"reload", TokenType::RELOAD},
    {"refresh", TokenType::REFRESH},
    {"update", TokenType::UPDATE},
    {"upgrade", TokenType::UPGRADE},
    {"downgrade", TokenType::DOWNGRADE},
    {"migrate", TokenType::MIGRATE},
    {"transform", TokenType::TRANSFORM},
    {"convert", TokenType::CONVERT},
    {"parse", TokenType::PARSE},
    {"serialize", TokenType::SERIALIZE},
    {"deserialize", TokenType::DESERIALIZE},
    {"marshal", TokenType::MARSHAL},
    {"unmarshal", TokenType::UNMARSHAL},
    {"unzip", TokenType::UNZIP},
    {"untar", TokenType::UNTAR},
    {"gzip", TokenType::GZIP},
    {"gunzip", TokenType::GUNZIP},
    {"bzip2", TokenType::BZIP2},
    {"bunzip2", TokenType::BUNZIP2},
    {"unxz", TokenType::UNXZ},
    {"unlzma", TokenType::UNLZMA},
    {"unlz4", TokenType::UNLZ4},
    {"unzstd", TokenType::UNZSTD},
    {"unbundle", TokenType::UNBUNDLE},
    {"backup", TokenType::BACKUP},
    {"restore", TokenType::RESTORE},
    {"save", TokenType::SAVE},
    {"load", TokenType::LOAD},
    {"read", TokenType::READ},
    {"write", TokenType::WRITE},
    {"append", TokenType::APPEND},
    {"truncate", TokenType::TRUNCATE},
    {"seek", TokenType::SEEK},
    {"tell", TokenType::TELL},
    {"flush", TokenType::FLUSH},
    {"sync", TokenType::SYNC},
    {"fsync", TokenType::FSYNC},
    {"fdatasync", TokenType::FDATASYNC},
    {"open", TokenType::OPEN},
    {"close", TokenType::CLOSE},
    {"create", TokenType::CREATE},
    {"mkdir", TokenType::MKDIR},
    {"rmdir", TokenType::RMDIR},
    {"rename", TokenType::RENAME},
    {"move", TokenType::MOVE},
    {"copy", TokenType::COPY},
    {"link", TokenType::LINK},
    {"symlink", TokenType::SYMLINK},
    {"readlink", TokenType::READLINK},
    {"stat", TokenType::STAT},
    {"lstat", TokenType::LSTAT},
    {"fstat", TokenType::FSTAT},
    {"access", TokenType::ACCESS},
    {"chgrp", TokenType::CHGRP},
    {"mount", TokenType::MOUNT},
    {"umount", TokenType::UMOUNT},
    {"df", TokenType::DF},
    {"du", TokenType::DU},
    {"find", TokenType::FIND},
    {"locate", TokenType::LOCATE},
    {"which", TokenType::WHICH},
    {"whereis", TokenType::WHEREIS},
    {"grep", TokenType::GREP},
    {"egrep", TokenType::EGREP},
    {"fgrep", TokenType::FGREP},
    {"rgrep", TokenType::RGREP},
    {"sed", TokenType::SED},
    {"awk", TokenType::AWK},
    {"cut", TokenType::CUT},
    {"sort", TokenType::SORT},
    {"uniq", TokenType::UNIQ},
    {"wc", TokenType::WC},
    {"less", TokenType::LESS},
    {"more", TokenType::MORE},
    {"cat", TokenType::CAT},
    {"tac", TokenType::TAC},
    {"rev", TokenType::REV},
    {"tr", TokenType::TR},
    {"magic", TokenType::MAGIC},
    {"mime", TokenType::MIME},
    {"format", TokenType::FORMAT},
    {"suffix", TokenType::SUFFIX},
    {"prefix", TokenType::PREFIX},
    {"basename", TokenType::BASENAME},
    {"dirname", TokenType::DIRNAME},
    {"realpath", TokenType::REALPATH},
    {"abspath", TokenType::ABSPATH},
    {"relpath", TokenType::RELPATH},
    {"normpath", TokenType::NORMPATH},
    {"expanduser", TokenType::EXPANDUSER},
    {"expandvars", TokenType::EXPANDVARS},
    {"join", TokenType::JOIN},
    {"split", TokenType::SPLIT},
    {"splitext", TokenType::SPLITEXT},
    {"splitdrive", TokenType::SPLITDRIVE},
    {"commonpath", TokenType::COMMONPATH},
    {"commonprefix", TokenType::COMMONPREFIX},
    {"isabs", TokenType::ISABS},
    {"isfile", TokenType::ISFILE},
    {"isdir", TokenType::ISDIR},
    {"islink", TokenType::ISLINK},
    {"ismount", TokenType::ISMOUNT},
    {"exists", TokenType::EXISTS},
    {"lexists", TokenType::LEXISTS},
    {"samefile", TokenType::SAMEFILE},
    {"sameopenfile", TokenType::SAMEOPENFILE},
    {"samestat", TokenType::SAMESTAT},
    {"getcwd", TokenType::GETCWD},
    {"chdir", TokenType::CHDIR},
    {"listdir", TokenType::LISTDIR},
    {"walk", TokenType::WALK},
    {"fnmatch", TokenType::FNMATCH},
    {"regex", TokenType::REGEX},
    {"pattern", TokenType::PATTERN},
    {"search", TokenType::SEARCH},
    {"findall", TokenType::FINDALL},
    {"finditer", TokenType::FINDITER},
    {"sub", TokenType::SUB},
    {"subn", TokenType::SUBN},
    {"replace", TokenType::REPLACE},
    {"substitute", TokenType::SUBSTITUTE},
    {"translate", TokenType::TRANSLATE},
    {"strip", TokenType::STRIP},
    {"lstrip", TokenType::LSTRIP},
    {"rstrip", TokenType::RSTRIP},
    {"upper", TokenType::UPPER},
    {"lower", TokenType::LOWER},
    {"capitalize", TokenType::CAPITALIZE},
    {"title", TokenType::TITLE},
    {"swapcase", TokenType::SWAPCASE},
    {"casefold", TokenType::CASEFOLD},
    {"startswith", TokenType::STARTSWITH},
    {"endswith", TokenType::ENDSWITH},
    {"isalpha", TokenType::ISALPHA},
    {"isdigit", TokenType::ISDIGIT},
    {"isalnum", TokenType::ISALNUM},
    {"isspace", TokenType::ISSPACE},
    {"isprintable", TokenType::ISPRINTABLE},
    {"isascii", TokenType::ISASCII},
    {"isdecimal", TokenType::ISDECIMAL},
    {"isnumeric", TokenType::ISNUMERIC},
    {"isidentifier", TokenType::ISIDENTIFIER},
    {"iskeyword", TokenType::ISKEYWORD},
    {"format_map", TokenType::FORMAT_MAP},
    {"expandtabs", TokenType::EXPANDTABS},
    {"splitlines", TokenType::SPLITLINES},
    {"partition", TokenType::PARTITION},
    {"rpartition", TokenType::RPARTITION},
    {"center", TokenType::CENTER},
    {"ljust", TokenType::LJUST},
    {"rjust", TokenType::RJUST},
    {"zfill", TokenType::ZFILL},
    {"rfind", TokenType::RFIND},
    {"rindex", TokenType::RINDEX},
    {"maketrans", TokenType::MAKETRANS},
    {"removeprefix", TokenType::REMOVEPREFIX},
    {"removesuffix", TokenType::REMOVESUFFIX},
    {"float", TokenType::FLOAT},
    {"str", TokenType::STR},
    {"bool", TokenType::BOOL},
    {"frozenset", TokenType::FROZENSET},
    {"bytes", TokenType::BYTES},
    {"bytearray", TokenType::BYTEARRAY},
    {"memoryview", TokenType::MEMORYVIEW},
    {"range", TokenType::RANGE},
    {"slice", TokenType::SLICE},
    {"complex", TokenType::COMPLEX},
    {"staticmethod", TokenType::STATICMETHOD},
    {"classmethod", TokenType::CLASSMETHOD},
    {"abs", TokenType::ABS},
    {"min", TokenType::MIN},
    {"max", TokenType::MAX},
    {"sum", TokenType::SUM},
    {"sorted", TokenType::SORTED},
    {"reversed", TokenType::REVERSED},
    {"enumerate", TokenType::ENUMERATE},
    {"reduce", TokenType::REDUCE},
    {"def", TokenType::DEF},
    {"raise", TokenType::RAISE},
    {"assert", TokenType::ASSERT},
    {"del", TokenType::DEL},
    {"pass", TokenType::PASS},
    {"except", TokenType::EXCEPT},
    {"global", TokenType::GLOBAL},
    {"nonlocal", TokenType::NONLOCAL},
    {"_", TokenType::UNDERSCORE}
}};

constexpr std::array<std::pair<std::string_view, int>, 64> OPERATOR_PRECEDENCE = {{
    {"=", 1}, {"+=", 1}, {"-=", 1}, {"*=", 1}, {"/=", 1}, {"%=", 1},
    {"**=", 1}, {"&=", 1}, {"|=", 1}, {"^=", 1}, {"<<=", 1}, {">>=", 1},
    {"||", 2}, {"&&", 3}, {"|", 4}, {"^", 5}, {"&", 6},
    {"==", 7}, {"!=", 7}, {"===", 7}, {"!==", 7},
    {"<", 8}, {">", 8}, {"<=", 8}, {">=", 8}, {"<=>", 8},
    {"<<", 9}, {">>", 9}, {">>>", 9},
    {"+", 10}, {"-", 10},
    {"*", 11}, {"/", 11}, {"%", 11},
    {"**", 12},
    {"!", 13}, {"~", 13}, {"++", 13}, {"--", 13},
    {".", 14}, {"->", 14}, {"[]", 14}, {"()", 14},
    {"?", 15}, {":", 15}, {"??", 15}, {"?.", 15}
}};

class TokenHelper {
private:
    static inline std::pmr::unordered_map<std::string, TokenType> keyword_map_{
        std::pmr::get_default_resource()
    };
    static inline std::pmr::unordered_map<std::string, int> precedence_map_{
        std::pmr::get_default_resource()
    };
    static inline std::atomic<bool> initialized_{false};
    
    static void initialize() {
        if (initialized_.load(std::memory_order_acquire)) {
            return;
        }
        
        for (const auto& [keyword, type] : KEYWORD_MAP) {
            keyword_map_[std::string(keyword)] = type;
        }
        
        for (const auto& [op, precedence] : OPERATOR_PRECEDENCE) {
            precedence_map_[std::string(op)] = precedence;
        }
        
        initialized_.store(true, std::memory_order_release);
    }
    
public:
    static const std::pmr::unordered_map<std::string, TokenType>& get_keywords() {
        initialize();
        return keyword_map_;
    }
    
    static const std::pmr::unordered_map<std::string, int>& get_precedence() {
        initialize();
        return precedence_map_;
    }
    
    static TokenType get_keyword_type(std::string_view keyword) {
        initialize();
        auto it = keyword_map_.find(std::string(keyword));
        return (it != keyword_map_.end()) ? it->second : TokenType::IDENTIFIER;
    }
    
    static int get_operator_precedence(std::string_view op) {
        initialize();
        auto it = precedence_map_.find(std::string(op));
        return (it != precedence_map_.end()) ? it->second : 0;
    }
    
    static bool is_keyword(std::string_view str) {
        initialize();
        return keyword_map_.find(std::string(str)) != keyword_map_.end();
    }
    
    static bool is_hacker_keyword(std::string_view str) {
        initialize();
        static const std::unordered_set<std::string> hacker_keywords{
            "hack", "crack", "pwn", "exploit", "payload", "inject", "shell",
            "root", "admin", "breach", "backdoor", "trojan", "virus", "worm",
            "keylog", "sniff", "spoof", "mask", "ghost", "phantom", "binary",
            "syscall", "memory", "register", "stack", "heap", "buffer",
            "overflow", "encrypt", "decrypt", "hash", "scan", "probe"
        };
        return hacker_keywords.find(std::string(str)) != hacker_keywords.end();
    }
    
    static bool is_operator(std::string_view str) {
        initialize();
        return precedence_map_.find(std::string(str)) != precedence_map_.end();
    }
    
    static bool is_assignment_operator(TokenType type) {
        return type == TokenType::ASSIGN ||
               type == TokenType::PLUS_ASSIGN ||
               type == TokenType::MINUS_ASSIGN ||
               type == TokenType::MULTIPLY_ASSIGN ||
               type == TokenType::DIVIDE_ASSIGN ||
               type == TokenType::MODULO_ASSIGN ||
               type == TokenType::POWER_ASSIGN ||
               type == TokenType::BITWISE_AND_ASSIGN ||
               type == TokenType::BITWISE_OR_ASSIGN ||
               type == TokenType::BITWISE_XOR_ASSIGN ||
               type == TokenType::LEFT_SHIFT_ASSIGN ||
               type == TokenType::RIGHT_SHIFT_ASSIGN ||
               type == TokenType::NULL_COALESCE_ASSIGN ||
               type == TokenType::LOGICAL_OR_ASSIGN ||
               type == TokenType::LOGICAL_AND_ASSIGN;
    }
    
    static bool is_comparison_operator(TokenType type) {
        return type == TokenType::EQUAL ||
               type == TokenType::NOT_EQUAL ||
               type == TokenType::LESS ||
               type == TokenType::GREATER ||
               type == TokenType::LESS_EQUAL ||
               type == TokenType::GREATER_EQUAL ||
               type == TokenType::STRICT_EQUAL ||
               type == TokenType::STRICT_NOT_EQUAL ||
               type == TokenType::SPACESHIP;
    }
    
    static bool is_logical_operator(TokenType type) {
        return type == TokenType::LOGICAL_AND ||
               type == TokenType::LOGICAL_OR ||
               type == TokenType::LOGICAL_NOT;
    }
    
    static bool is_bitwise_operator(TokenType type) {
        return type == TokenType::BITWISE_AND ||
               type == TokenType::BITWISE_OR ||
               type == TokenType::BITWISE_XOR ||
               type == TokenType::BITWISE_NOT ||
               type == TokenType::LEFT_SHIFT ||
               type == TokenType::RIGHT_SHIFT ||
               type == TokenType::UNSIGNED_RIGHT_SHIFT;
    }
    
    static bool is_arithmetic_operator(TokenType type) {
        return type == TokenType::PLUS ||
               type == TokenType::MINUS ||
               type == TokenType::MULTIPLY ||
               type == TokenType::DIVIDE ||
               type == TokenType::MODULO ||
               type == TokenType::POWER;
    }
    
    static bool is_unary_operator(TokenType type) {
        return type == TokenType::PLUS ||
               type == TokenType::MINUS ||
               type == TokenType::LOGICAL_NOT ||
               type == TokenType::BITWISE_NOT ||
               type == TokenType::INCREMENT ||
               type == TokenType::DECREMENT ||
               type == TokenType::TYPEOF ||
               type == TokenType::DELETE ||
               type == TokenType::AWAIT ||
               type == TokenType::YIELD;
    }
    
    static bool is_postfix_operator(TokenType type) {
        return type == TokenType::INCREMENT ||
               type == TokenType::DECREMENT ||
               type == TokenType::OPTIONAL_CHAINING ||
               type == TokenType::OPTIONAL_INDEXING;
    }
    
    static bool is_literal(TokenType type) {
        return type == TokenType::INTEGER_LITERAL ||
               type == TokenType::FLOAT_LITERAL ||
               type == TokenType::STRING_LITERAL ||
               type == TokenType::CHAR_LITERAL ||
               type == TokenType::BOOLEAN_LITERAL ||
               type == TokenType::HEX_LITERAL ||
               type == TokenType::BINARY_LITERAL ||
               type == TokenType::OCTAL_LITERAL ||
               type == TokenType::REGEX_LITERAL ||
               type == TokenType::TEMPLATE_LITERAL ||
               type == TokenType::RAW_STRING_LITERAL ||
               type == TokenType::TRUE ||
               type == TokenType::FALSE ||
               type == TokenType::NIL ||
               type == TokenType::NULL_TOKEN ||
               type == TokenType::UNDEFINED;
    }
    
    static bool is_keyword_literal(TokenType type) {
        return type == TokenType::TRUE ||
               type == TokenType::FALSE ||
               type == TokenType::NIL ||
               type == TokenType::NULL_TOKEN ||
               type == TokenType::UNDEFINED;
    }
    
    static bool is_control_flow(TokenType type) {
        return type == TokenType::IF ||
               type == TokenType::ELSE ||
               type == TokenType::ELIF ||
               type == TokenType::WHILE ||
               type == TokenType::FOR ||
               type == TokenType::DO ||
               type == TokenType::BREAK ||
               type == TokenType::CONTINUE ||
               type == TokenType::RETURN ||
               type == TokenType::SWITCH ||
               type == TokenType::CASE ||
               type == TokenType::DEFAULT ||
               type == TokenType::TRY ||
               type == TokenType::CATCH ||
               type == TokenType::FINALLY ||
               type == TokenType::THROW;
    }
    
    static bool is_declaration(TokenType type) {
        return type == TokenType::LET ||
               type == TokenType::CONST ||
               type == TokenType::VAR ||
               type == TokenType::FUNC ||
               type == TokenType::CLASS ||
               type == TokenType::INTERFACE ||
               type == TokenType::ENUM ||
               type == TokenType::STRUCT ||
               type == TokenType::UNION ||
               type == TokenType::TYPEDEF ||
               type == TokenType::NAMESPACE ||
               type == TokenType::IMPORT ||
               type == TokenType::EXPORT;
    }
    
    static bool is_modifier(TokenType type) {
        return type == TokenType::STATIC ||
               type == TokenType::PUBLIC ||
               type == TokenType::PRIVATE ||
               type == TokenType::PROTECTED ||
               type == TokenType::ABSTRACT ||
               type == TokenType::FINAL ||
               type == TokenType::OVERRIDE ||
               type == TokenType::VIRTUAL ||
               type == TokenType::ASYNC ||
               type == TokenType::CONST ||
               type == TokenType::VOLATILE ||
               type == TokenType::MUTABLE ||
               type == TokenType::INLINE ||
               type == TokenType::EXTERN ||
               type == TokenType::REGISTER;
    }
    
    static bool is_punctuation(TokenType type) {
        return type == TokenType::LEFT_PAREN ||
               type == TokenType::RIGHT_PAREN ||
               type == TokenType::LEFT_BRACKET ||
               type == TokenType::RIGHT_BRACKET ||
               type == TokenType::LEFT_BRACE ||
               type == TokenType::RIGHT_BRACE ||
               type == TokenType::COMMA ||
               type == TokenType::SEMICOLON ||
               type == TokenType::COLON ||
               type == TokenType::QUESTION ||
               type == TokenType::DOT ||
               type == TokenType::ARROW ||
               type == TokenType::FAT_ARROW ||
               type == TokenType::SCOPE ||
               type == TokenType::SPREAD ||
               type == TokenType::RANGE_INCLUSIVE ||
               type == TokenType::RANGE_EXCLUSIVE;
    }
    
    static bool is_whitespace(TokenType type) {
        return type == TokenType::WHITESPACE ||
               type == TokenType::NEWLINE ||
               type == TokenType::TAB ||
               type == TokenType::CARRIAGE_RETURN;
    }
    
    static bool is_comment(TokenType type) {
        return type == TokenType::COMMENT ||
               type == TokenType::MULTILINE_COMMENT ||
               type == TokenType::DOC_COMMENT;
    }
    
    static bool is_special(TokenType type) {
        return type == TokenType::EOF_TOKEN ||
               type == TokenType::UNKNOWN ||
               type == TokenType::ERROR ||
               type == TokenType::PREPROCESSOR ||
               type == TokenType::PRAGMA ||
               type == TokenType::ATTRIBUTE ||
               type == TokenType::ANNOTATION;
    }
    
    static std::string token_type_to_string(TokenType type) {
        switch (type) {
            case TokenType::EOF_TOKEN: return "EOF";
            case TokenType::IDENTIFIER: return "IDENTIFIER";
            case TokenType::INTEGER_LITERAL: return "INTEGER_LITERAL";
            case TokenType::FLOAT_LITERAL: return "FLOAT_LITERAL";
            case TokenType::STRING_LITERAL: return "STRING_LITERAL";
            case TokenType::CHAR_LITERAL: return "CHAR_LITERAL";
            case TokenType::BOOLEAN_LITERAL: return "BOOLEAN_LITERAL";
            case TokenType::HEX_LITERAL: return "HEX_LITERAL";
            case TokenType::BINARY_LITERAL: return "BINARY_LITERAL";
            case TokenType::OCTAL_LITERAL: return "OCTAL_LITERAL";
            case TokenType::REGEX_LITERAL: return "REGEX_LITERAL";
            case TokenType::TEMPLATE_LITERAL: return "TEMPLATE_LITERAL";
            case TokenType::RAW_STRING_LITERAL: return "RAW_STRING_LITERAL";
            case TokenType::PLUS: return "PLUS";
            case TokenType::MINUS: return "MINUS";
            case TokenType::MULTIPLY: return "MULTIPLY";
            case TokenType::DIVIDE: return "DIVIDE";
            case TokenType::MODULO: return "MODULO";
            case TokenType::POWER: return "POWER";
            case TokenType::ASSIGN: return "ASSIGN";
            case TokenType::PLUS_ASSIGN: return "PLUS_ASSIGN";
            case TokenType::MINUS_ASSIGN: return "MINUS_ASSIGN";
            case TokenType::MULTIPLY_ASSIGN: return "MULTIPLY_ASSIGN";
            case TokenType::DIVIDE_ASSIGN: return "DIVIDE_ASSIGN";
            case TokenType::MODULO_ASSIGN: return "MODULO_ASSIGN";
            case TokenType::POWER_ASSIGN: return "POWER_ASSIGN";
            case TokenType::EQUAL: return "EQUAL";
            case TokenType::NOT_EQUAL: return "NOT_EQUAL";
            case TokenType::LESS: return "LESS";
            case TokenType::GREATER: return "GREATER";
            case TokenType::LESS_EQUAL: return "LESS_EQUAL";
            case TokenType::GREATER_EQUAL: return "GREATER_EQUAL";
            case TokenType::SPACESHIP: return "SPACESHIP";
            case TokenType::LOGICAL_AND: return "LOGICAL_AND";
            case TokenType::LOGICAL_OR: return "LOGICAL_OR";
            case TokenType::LOGICAL_NOT: return "LOGICAL_NOT";
            case TokenType::BITWISE_AND: return "BITWISE_AND";
            case TokenType::BITWISE_OR: return "BITWISE_OR";
            case TokenType::BITWISE_XOR: return "BITWISE_XOR";
            case TokenType::BITWISE_NOT: return "BITWISE_NOT";
            case TokenType::LEFT_SHIFT: return "LEFT_SHIFT";
            case TokenType::RIGHT_SHIFT: return "RIGHT_SHIFT";
            case TokenType::UNSIGNED_RIGHT_SHIFT: return "UNSIGNED_RIGHT_SHIFT";
            case TokenType::INCREMENT: return "INCREMENT";
            case TokenType::DECREMENT: return "DECREMENT";
            case TokenType::QUESTION: return "QUESTION";
            case TokenType::COLON: return "COLON";
            case TokenType::SEMICOLON: return "SEMICOLON";
            case TokenType::COMMA: return "COMMA";
            case TokenType::DOT: return "DOT";
            case TokenType::ARROW: return "ARROW";
            case TokenType::FAT_ARROW: return "FAT_ARROW";
            case TokenType::SCOPE: return "SCOPE";
            case TokenType::LEFT_PAREN: return "LEFT_PAREN";
            case TokenType::RIGHT_PAREN: return "RIGHT_PAREN";
            case TokenType::LEFT_BRACKET: return "LEFT_BRACKET";
            case TokenType::RIGHT_BRACKET: return "RIGHT_BRACKET";
            case TokenType::LEFT_BRACE: return "LEFT_BRACE";
            case TokenType::RIGHT_BRACE: return "RIGHT_BRACE";
            case TokenType::NEWLINE: return "NEWLINE";
            case TokenType::WHITESPACE: return "WHITESPACE";
            case TokenType::COMMENT: return "COMMENT";
            case TokenType::MULTILINE_COMMENT: return "MULTILINE_COMMENT";
            case TokenType::HACK: return "HACK";
            case TokenType::CRACK: return "CRACK";
            case TokenType::PWN: return "PWN";
            case TokenType::EXPLOIT: return "EXPLOIT";
            case TokenType::PAYLOAD: return "PAYLOAD";
            case TokenType::INJECT: return "INJECT";
            case TokenType::SHELL: return "SHELL";
            case TokenType::ROOT: return "ROOT";
            case TokenType::ADMIN: return "ADMIN";
            case TokenType::ENCRYPT: return "ENCRYPT";
            case TokenType::DECRYPT: return "DECRYPT";
            case TokenType::HASH: return "HASH";
            case TokenType::SCAN: return "SCAN";
            case TokenType::PROBE: return "PROBE";
            case TokenType::BREACH: return "BREACH";
            case TokenType::BACKDOOR: return "BACKDOOR";
            case TokenType::TROJAN: return "TROJAN";
            case TokenType::VIRUS: return "VIRUS";
            case TokenType::WORM: return "WORM";
            case TokenType::KEYLOG: return "KEYLOG";
            case TokenType::SNIFF: return "SNIFF";
            case TokenType::SPOOF: return "SPOOF";
            case TokenType::MASK: return "MASK";
            case TokenType::GHOST: return "GHOST";
            case TokenType::PHANTOM: return "PHANTOM";
            case TokenType::BINARY: return "BINARY";
            case TokenType::SYSCALL: return "SYSCALL";
            case TokenType::MEMORY: return "MEMORY";
            case TokenType::REGISTER: return "REGISTER";
            case TokenType::STACK: return "STACK";
            case TokenType::HEAP: return "HEAP";
            case TokenType::BUFFER: return "BUFFER";
            case TokenType::OVERFLOW: return "OVERFLOW";
            default: return "UNKNOWN";
        }
    }
    
    static bool is_right_associative(TokenType type) {
        return type == TokenType::ASSIGN ||
               type == TokenType::PLUS_ASSIGN ||
               type == TokenType::MINUS_ASSIGN ||
               type == TokenType::MULTIPLY_ASSIGN ||
               type == TokenType::DIVIDE_ASSIGN ||
               type == TokenType::MODULO_ASSIGN ||
               type == TokenType::POWER_ASSIGN ||
               type == TokenType::POWER ||
               type == TokenType::QUESTION ||
               type == TokenType::COLON;
    }
    
    static bool is_left_associative(TokenType type) {
        return !is_right_associative(type) && is_operator(token_type_to_string(type));
    }
    
    template<typename T>
    static constexpr T fast_hash(std::string_view str) noexcept {
        T hash = 0;
        for (char c : str) {
            hash = hash * 31 + static_cast<T>(c);
        }
        return hash;
    }
    
    template<typename T>
    static constexpr bool fast_compare(std::string_view a, std::string_view b) noexcept {
        if (a.size() != b.size()) return false;
        return std::equal(a.begin(), a.end(), b.begin());
    }
    
    static size_t count_tokens(std::string_view source) {
        size_t count = 0;
        for (size_t i = 0; i < source.size(); ++i) {
            if (std::isspace(source[i])) continue;
            if (std::isalnum(source[i]) || source[i] == '_') {
                while (i < source.size() && (std::isalnum(source[i]) || source[i] == '_')) {
                    ++i;
                }
                --i;
            } else if (source[i] == '"' || source[i] == '\'') {
                char quote = source[i];
                ++i;
                while (i < source.size() && source[i] != quote) {
                    if (source[i] == '\\') ++i;
                    ++i;
                }
            } else if (std::isdigit(source[i])) {
                while (i < source.size() && (std::isdigit(source[i]) || source[i] == '.')) {
                    ++i;
                }
                --i;
            }
            ++count;
        }
        return count;
    }
    
    static std::vector<std::string> split_source(std::string_view source) {
        std::vector<std::string> tokens;
        tokens.reserve(count_tokens(source));
        
        for (size_t i = 0; i < source.size(); ++i) {
            if (std::isspace(source[i])) continue;
            
            size_t start = i;
            if (std::isalnum(source[i]) || source[i] == '_') {
                while (i < source.size() && (std::isalnum(source[i]) || source[i] == '_')) {
                    ++i;
                }
                tokens.emplace_back(source.substr(start, i - start));
                --i;
            } else if (source[i] == '"' || source[i] == '\'') {
                char quote = source[i];
                ++i;
                while (i < source.size() && source[i] != quote) {
                    if (source[i] == '\\') ++i;
                    ++i;
                }
                tokens.emplace_back(source.substr(start, i - start + 1));
            } else if (std::isdigit(source[i])) {
                while (i < source.size() && (std::isdigit(source[i]) || source[i] == '.')) {
                    ++i;
                }
                tokens.emplace_back(source.substr(start, i - start));
                --i;
            } else {
                tokens.emplace_back(source.substr(start, 1));
            }
        }
        
        return tokens;
    }
    
    static void vectorized_token_matching(std::span<const std::string> tokens,
                                         std::span<TokenType> results) {
        std::transform(std::execution::par_unseq, tokens.begin(), tokens.end(),
                      results.begin(), [](const std::string& token) {
            return get_keyword_type(token);
        });
    }
    
    static std::unordered_map<std::string, size_t> get_token_statistics(
        std::span<const Token> tokens) {
        std::unordered_map<std::string, size_t> stats;
        
        for (const auto& token : tokens) {
            stats[token_type_to_string(token.type)]++;
        }
        
        return stats;
    }
    
    static void print_token_statistics(const std::unordered_map<std::string, size_t>& stats) {
        std::cout << "Token Statistics:\n";
        for (const auto& [type, count] : stats) {
            std::cout << std::format("  {}: {}\n", type, count);
        }
    }
};

}

std::string Token::to_string() const {
    return std::format("Token({}, '{}', {}:{})", 
                      static_cast<int>(type), value, line, column);
}

bool Token::operator==(const Token& other) const {
    return type == other.type && value == other.value && 
           line == other.line && column == other.column;
}

bool Token::operator!=(const Token& other) const {
    return !(*this == other);
}

bool Token::operator<(const Token& other) const {
    if (line != other.line) return line < other.line;
    if (column != other.column) return column < other.column;
    if (type != other.type) return type < other.type;
    return value < other.value;
}

std::ostream& operator<<(std::ostream& os, const Token& token) {
    return os << token.to_string();
}

std::ostream& operator<<(std::ostream& os, TokenType type) {
    return os << TokenHelper::token_type_to_string(type);
}

} 