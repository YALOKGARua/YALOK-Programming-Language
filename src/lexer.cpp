#include <yalok/lexer.hpp>
#include <yalok/token.hpp>
#include <cctype>
#include <stdexcept>
#include <algorithm>
#include <execution>
#include <immintrin.h>
#include <bit>
#include <charconv>
#include <regex>
#include <unordered_set>
#include <array>
#include <chrono>
#include <random>
#include <thread>
#include <future>
#include <atomic>
#include <memory_resource>

namespace yalok {

template<typename Allocator>
bool BasicLexer<Allocator>::SIMDMatcher::match(std::string_view text, size_t pos) const noexcept {
    if (pos + SIMD_WIDTH > text.size()) {
        return false;
    }
    
    alignas(32) std::array<char, SIMD_WIDTH> input;
    std::copy_n(text.data() + pos, SIMD_WIDTH, input.begin());
    
    __m256i pattern_vec = _mm256_load_si256(reinterpret_cast<const __m256i*>(pattern_.data()));
    __m256i input_vec = _mm256_load_si256(reinterpret_cast<const __m256i*>(input.data()));
    __m256i mask_vec = _mm256_load_si256(reinterpret_cast<const __m256i*>(mask_.data()));
    
    __m256i masked_input = _mm256_and_si256(input_vec, mask_vec);
    __m256i masked_pattern = _mm256_and_si256(pattern_vec, mask_vec);
    
    __m256i cmp = _mm256_cmpeq_epi8(masked_input, masked_pattern);
    int mask = _mm256_movemask_epi8(cmp);
    
    return mask != 0;
}

template<typename Allocator>
void BasicLexer<Allocator>::initialize_keywords() {
    keywords_ = {
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
        {"from", TokenType::FROM},
        {"join", TokenType::JOIN},
        {"group", TokenType::GROUP},
        {"order", TokenType::ORDER},
        {"having", TokenType::HAVING},
        {"limit", TokenType::LIMIT},
        {"offset", TokenType::OFFSET},
        {"union", TokenType::UNION},
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
        {"match", TokenType::MATCH},
        {"is", TokenType::IS},
        {"isnull", TokenType::ISNULL},
        {"notnull", TokenType::NOTNULL},
        {"collate", TokenType::COLLATE},
        {"escape", TokenType::ESCAPE},
        {"cast", TokenType::CAST},
        {"when", TokenType::WHEN},
        {"then", TokenType::THEN},
        {"end", TokenType::END}
    };
}

template<typename Allocator>
void BasicLexer<Allocator>::initialize_operators() {
    operators_ = {
        {"+", TokenType::PLUS},
        {"-", TokenType::MINUS},
        {"*", TokenType::MULTIPLY},
        {"/", TokenType::DIVIDE},
        {"%", TokenType::MODULO},
        {"**", TokenType::POWER},
        {"=", TokenType::ASSIGN},
        {"+=", TokenType::PLUS_ASSIGN},
        {"-=", TokenType::MINUS_ASSIGN},
        {"*=", TokenType::MULTIPLY_ASSIGN},
        {"/=", TokenType::DIVIDE_ASSIGN},
        {"%=", TokenType::MODULO_ASSIGN},
        {"**=", TokenType::POWER_ASSIGN},
        {"==", TokenType::EQUAL},
        {"!=", TokenType::NOT_EQUAL},
        {"<", TokenType::LESS},
        {">", TokenType::GREATER},
        {"<=", TokenType::LESS_EQUAL},
        {">=", TokenType::GREATER_EQUAL},
        {"<=>", TokenType::SPACESHIP},
        {"&&", TokenType::LOGICAL_AND},
        {"||", TokenType::LOGICAL_OR},
        {"!", TokenType::LOGICAL_NOT},
        {"&", TokenType::BITWISE_AND},
        {"|", TokenType::BITWISE_OR},
        {"^", TokenType::BITWISE_XOR},
        {"~", TokenType::BITWISE_NOT},
        {"<<", TokenType::LEFT_SHIFT},
        {">>", TokenType::RIGHT_SHIFT},
        {"&=", TokenType::BITWISE_AND_ASSIGN},
        {"|=", TokenType::BITWISE_OR_ASSIGN},
        {"^=", TokenType::BITWISE_XOR_ASSIGN},
        {"<<=", TokenType::LEFT_SHIFT_ASSIGN},
        {">>=", TokenType::RIGHT_SHIFT_ASSIGN},
        {"++", TokenType::INCREMENT},
        {"--", TokenType::DECREMENT},
        {"?", TokenType::QUESTION},
        {":", TokenType::COLON},
        {"?:", TokenType::ELVIS},
        {"??", TokenType::NULL_COALESCE},
        {"?..", TokenType::RANGE_INCLUSIVE},
        {"..<", TokenType::RANGE_EXCLUSIVE},
        {"...", TokenType::SPREAD},
        {".", TokenType::DOT},
        {"->", TokenType::ARROW},
        {"=>", TokenType::FAT_ARROW},
        {"::", TokenType::SCOPE},
        {"@", TokenType::AT},
        {"#", TokenType::HASH},
        {"$", TokenType::DOLLAR},
        {"\\", TokenType::BACKSLASH},
        {"`", TokenType::BACKTICK},
        {"'", TokenType::SINGLE_QUOTE},
        {"\"", TokenType::DOUBLE_QUOTE},
        {"(", TokenType::LEFT_PAREN},
        {")", TokenType::RIGHT_PAREN},
        {"[", TokenType::LEFT_BRACKET},
        {"]", TokenType::RIGHT_BRACKET},
        {"{", TokenType::LEFT_BRACE},
        {"}", TokenType::RIGHT_BRACE},
        {",", TokenType::COMMA},
        {";", TokenType::SEMICOLON},
        {"_", TokenType::UNDERSCORE},
        {"|>", TokenType::PIPE},
        {"<|", TokenType::REVERSE_PIPE},
        {"<-", TokenType::LEFT_ARROW},
        {"<->", TokenType::BIDIRECTIONAL_ARROW},
        {"~>", TokenType::TILDE_ARROW},
        {"<~", TokenType::TILDE_LEFT_ARROW},
        {"=~", TokenType::MATCH_OPERATOR},
        {"!~", TokenType::NOT_MATCH_OPERATOR},
        {"===", TokenType::STRICT_EQUAL},
        {"!==", TokenType::STRICT_NOT_EQUAL},
        {"<>", TokenType::NOT_EQUAL_ALT},
        {"<<=", TokenType::LEFT_SHIFT_ASSIGN},
        {">>=", TokenType::RIGHT_SHIFT_ASSIGN},
        {">>>=", TokenType::UNSIGNED_RIGHT_SHIFT_ASSIGN},
        {">>>", TokenType::UNSIGNED_RIGHT_SHIFT},
        {"??=", TokenType::NULL_COALESCE_ASSIGN},
        {"||=", TokenType::LOGICAL_OR_ASSIGN},
        {"&&=", TokenType::LOGICAL_AND_ASSIGN},
        {"?.", TokenType::OPTIONAL_CHAINING},
        {"?[", TokenType::OPTIONAL_INDEXING},
        {"?=", TokenType::OPTIONAL_ASSIGN},
        {"!!", TokenType::DOUBLE_BANG},
        {"?!", TokenType::QUESTION_BANG},
        {"!?", TokenType::BANG_QUESTION},
        {"~=", TokenType::TILDE_ASSIGN},
        {"|=", TokenType::BITWISE_OR_ASSIGN},
        {"^=", TokenType::BITWISE_XOR_ASSIGN},
        {"&=", TokenType::BITWISE_AND_ASSIGN},
        {"++=", TokenType::INCREMENT_ASSIGN},
        {"--=", TokenType::DECREMENT_ASSIGN},
        {"<|>", TokenType::COMPOSITION},
        {"<*>", TokenType::APPLICATIVE},
        {"<$>", TokenType::FUNCTOR},
        {"</>", TokenType::ALTERNATIVE},
        {"<+>", TokenType::SEMIGROUP},
        {"<*", TokenType::LEFT_APPLY},
        {"*>", TokenType::RIGHT_APPLY},
        {">>", TokenType::BIND},
        {"=<<", TokenType::REVERSE_BIND},
        {"<=<", TokenType::LEFT_COMPOSE},
        {">=>", TokenType::RIGHT_COMPOSE},
        {"<==", TokenType::LEFT_BIND},
        {"==>", TokenType::RIGHT_BIND},
        {"<->", TokenType::BIDIRECTIONAL_ARROW},
        {"<~~", TokenType::TILDE_LEFT_ARROW},
        {"~~>", TokenType::TILDE_RIGHT_ARROW},
        {"<=>", TokenType::SPACESHIP},
        {"?<", TokenType::QUESTION_LEFT},
        {">?", TokenType::QUESTION_RIGHT},
        {"!<", TokenType::BANG_LEFT},
        {">!", TokenType::BANG_RIGHT},
        {"~<", TokenType::TILDE_LEFT},
        {">~", TokenType::TILDE_RIGHT},
        {"=#", TokenType::EQUAL_HASH},
        {"#=", TokenType::HASH_EQUAL},
        {"@=", TokenType::AT_EQUAL},
        {"=@", TokenType::EQUAL_AT},
        {"$=", TokenType::DOLLAR_EQUAL},
        {"=$", TokenType::EQUAL_DOLLAR},
        {"\\=", TokenType::BACKSLASH_EQUAL},
        {"=\\", TokenType::EQUAL_BACKSLASH},
        {"`=", TokenType::BACKTICK_EQUAL},
        {"=`", TokenType::EQUAL_BACKTICK}
    };
}

template<typename Allocator>
void BasicLexer<Allocator>::initialize_hacker_keywords() {
    hacker_keywords_ = {
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
        {"var", TokenType::VAR},
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
        {"enum", TokenType::ENUM},
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
        {"break", TokenType::BREAK},
        {"crack", TokenType::CRACK},
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
        {"bin", TokenType::BIN},
        {"exe", TokenType::EXE},
        {"dll", TokenType::DLL},
        {"so", TokenType::SO},
        {"dylib", TokenType::DYLIB},
        {"elf", TokenType::ELF},
        {"pe", TokenType::PE},
        {"macho", TokenType::MACHO},
        {"coff", TokenType::COFF},
        {"obj", TokenType::OBJ},
        {"lib", TokenType::LIB},
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
        {"export", TokenType::EXPORT},
        {"import", TokenType::IMPORT},
        {"dynamic", TokenType::DYNAMIC},
        {"static", TokenType::STATIC},
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
        {"ss", TokenType::SS},
        {"flags", TokenType::FLAGS},
        {"eflags", TokenType::EFLAGS},
        {"rflags", TokenType::RFLAGS},
        {"cf", TokenType::CF},
        {"pf", TokenType::PF},
        {"af", TokenType::AF},
        {"zf", TokenType::ZF},
        {"sf", TokenType::SF},
        {"tf", TokenType::TF},
        {"if", TokenType::IF},
        {"df", TokenType::DF},
        {"of", TokenType::OF},
        {"iopl", TokenType::IOPL},
        {"nt", TokenType::NT},
        {"rf", TokenType::RF},
        {"vm", TokenType::VM},
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
        {"virtual", TokenType::VIRTUAL},
        {"physical", TokenType::PHYSICAL},
        {"linear", TokenType::LINEAR},
        {"logical", TokenType::LOGICAL},
        {"address", TokenType::ADDRESS},
        {"addr", TokenType::ADDR},
        {"pointer", TokenType::POINTER},
        {"ptr", TokenType::PTR},
        {"reference", TokenType::REFERENCE},
        {"ref", TokenType::REF},
        {"offset", TokenType::OFFSET},
        {"base", TokenType::BASE},
        {"limit", TokenType::LIMIT},
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
        {"service", TokenType::SERVICE},
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
        {"async", TokenType::ASYNC},
        {"await", TokenType::AWAIT},
        {"yield", TokenType::YIELD},
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
        {"hash", TokenType::HASH},
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
        {"return", TokenType::RETURN},
        {"push", TokenType::PUSH},
        {"pop", TokenType::POP},
        {"peek", TokenType::PEEK},
        {"top", TokenType::TOP},
        {"bottom", TokenType::BOTTOM},
        {"front", TokenType::FRONT},
        {"back", TokenType::BACK},
        {"begin", TokenType::BEGIN},
        {"end", TokenType::END},
        {"first", TokenType::FIRST},
        {"last", TokenType::LAST},
        {"next", TokenType::NEXT},
        {"prev", TokenType::PREV},
        {"current", TokenType::CURRENT},
        {"head", TokenType::HEAD},
        {"tail", TokenType::TAIL},
        {"root", TokenType::ROOT},
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
        {"key", TokenType::KEY},
        {"data", TokenType::DATA},
        {"info", TokenType::INFO},
        {"metadata", TokenType::METADATA},
        {"attribute", TokenType::ATTRIBUTE},
        {"property", TokenType::PROPERTY},
        {"field", TokenType::FIELD},
        {"member", TokenType::MEMBER},
        {"element", TokenType::ELEMENT},
        {"item", TokenType::ITEM},
        {"entry", TokenType::ENTRY},
        {"record", TokenType::RECORD},
        {"row", TokenType::ROW},
        {"column", TokenType::COLUMN},
        {"cell", TokenType::CELL},
        {"tuple", TokenType::TUPLE},
        {"pair", TokenType::PAIR},
        {"triple", TokenType::TRIPLE},
        {"quad", TokenType::QUAD},
        {"struct", TokenType::STRUCT},
        {"union", TokenType::UNION},
        {"enum", TokenType::ENUM},
        {"class", TokenType::CLASS},
        {"object", TokenType::OBJECT},
        {"instance", TokenType::INSTANCE},
        {"type", TokenType::TYPE},
        {"interface", TokenType::INTERFACE},
        {"trait", TokenType::TRAIT},
        {"mixin", TokenType::MIXIN},
        {"module", TokenType::MODULE},
        {"package", TokenType::PACKAGE},
        {"namespace", TokenType::NAMESPACE},
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
        {"template", TokenType::TEMPLATE},
        {"generic", TokenType::GENERIC},
        {"polymorphic", TokenType::POLYMORPHIC},
        {"monomorphic", TokenType::MONOMORPHIC},
        {"virtual", TokenType::VIRTUAL},
        {"abstract", TokenType::ABSTRACT},
        {"concrete", TokenType::CONCRETE},
        {"final", TokenType::FINAL},
        {"sealed", TokenType::SEALED},
        {"override", TokenType::OVERRIDE},
        {"implement", TokenType::IMPLEMENT},
        {"extend", TokenType::EXTEND},
        {"inherit", TokenType::INHERIT},
        {"derive", TokenType::DERIVE},
        {"compose", TokenType::COMPOSE},
        {"delegate", TokenType::DELEGATE},
        {"proxy", TokenType::PROXY},
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
        {"iterator", TokenType::ITERATOR},
        {"composite", TokenType::COMPOSITE},
        {"bridge", TokenType::BRIDGE},
        {"proxy", TokenType::PROXY},
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
        {"service", TokenType::SERVICE},
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
        {"process", TokenType::PROCESS},
        {"task", TokenType::TASK},
        {"job", TokenType::JOB},
        {"batch", TokenType::BATCH},
        {"queue", TokenType::QUEUE},
        {"scheduler", TokenType::SCHEDULER},
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
        {"exception", TokenType::EXCEPTION},
        {"fault", TokenType::FAULT},
        {"failure", TokenType::FAILURE},
        {"crash", TokenType::CRASH},
        {"panic", TokenType::PANIC},
        {"abort", TokenType::ABORT},
        {"exit", TokenType::EXIT},
        {"quit", TokenType::QUIT},
        {"terminate", TokenType::TERMINATE},
        {"kill", TokenType::KILL},
        {"destroy", TokenType::DESTROY},
        {"delete", TokenType::DELETE},
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
        {"encode", TokenType::ENCODE},
        {"decode", TokenType::DECODE},
        {"compress", TokenType::COMPRESS},
        {"decompress", TokenType::DECOMPRESS},
        {"zip", TokenType::ZIP},
        {"unzip", TokenType::UNZIP},
        {"tar", TokenType::TAR},
        {"untar", TokenType::UNTAR},
        {"gzip", TokenType::GZIP},
        {"gunzip", TokenType::GUNZIP},
        {"bzip2", TokenType::BZIP2},
        {"bunzip2", TokenType::BUNZIP2},
        {"xz", TokenType::XZ},
        {"unxz", TokenType::UNXZ},
        {"lzma", TokenType::LZMA},
        {"unlzma", TokenType::UNLZMA},
        {"lz4", TokenType::LZ4},
        {"unlz4", TokenType::UNLZ4},
        {"zstd", TokenType::ZSTD},
        {"unzstd", TokenType::UNZSTD},
        {"pack", TokenType::PACK},
        {"unpack", TokenType::UNPACK},
        {"bundle", TokenType::BUNDLE},
        {"unbundle", TokenType::UNBUNDLE},
        {"archive", TokenType::ARCHIVE},
        {"unarchive", TokenType::UNARCHIVE},
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
        {"chmod", TokenType::CHMOD},
        {"chown", TokenType::CHOWN},
        {"chgrp", TokenType::CHGRP},
        {"umask", TokenType::UMASK},
        {"mount", TokenType::MOUNT},
        {"umount", TokenType::UMOUNT},
        {"sync", TokenType::SYNC},
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
        {"head", TokenType::HEAD},
        {"tail", TokenType::TAIL},
        {"less", TokenType::LESS},
        {"more", TokenType::MORE},
        {"cat", TokenType::CAT},
        {"tac", TokenType::TAC},
        {"rev", TokenType::REV},
        {"tr", TokenType::TR},
        {"od", TokenType::OD},
        {"xxd", TokenType::XXD},
        {"hexdump", TokenType::HEXDUMP},
        {"strings", TokenType::STRINGS},
        {"file", TokenType::FILE},
        {"magic", TokenType::MAGIC},
        {"mime", TokenType::MIME},
        {"type", TokenType::TYPE},
        {"format", TokenType::FORMAT},
        {"extension", TokenType::EXTENSION},
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
        {"glob", TokenType::GLOB},
        {"fnmatch", TokenType::FNMATCH},
        {"regex", TokenType::REGEX},
        {"regexp", TokenType::REGEXP},
        {"pattern", TokenType::PATTERN},
        {"match", TokenType::MATCH},
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
        {"encode", TokenType::ENCODE},
        {"decode", TokenType::DECODE},
        {"format", TokenType::FORMAT},
        {"format_map", TokenType::FORMAT_MAP},
        {"expandtabs", TokenType::EXPANDTABS},
        {"splitlines", TokenType::SPLITLINES},
        {"partition", TokenType::PARTITION},
        {"rpartition", TokenType::RPARTITION},
        {"center", TokenType::CENTER},
        {"ljust", TokenType::LJUST},
        {"rjust", TokenType::RJUST},
        {"zfill", TokenType::ZFILL},
        {"count", TokenType::COUNT},
        {"find", TokenType::FIND},
        {"rfind", TokenType::RFIND},
        {"index", TokenType::INDEX},
        {"rindex", TokenType::RINDEX},
        {"maketrans", TokenType::MAKETRANS},
        {"removeprefix", TokenType::REMOVEPREFIX},
        {"removesuffix", TokenType::REMOVESUFFIX},
        {"int", TokenType::INT},
        {"float", TokenType::FLOAT},
        {"str", TokenType::STR},
        {"bool", TokenType::BOOL},
        {"list", TokenType::LIST},
        {"tuple", TokenType::TUPLE},
        {"dict", TokenType::DICT},
        {"set", TokenType::SET},
        {"frozenset", TokenType::FROZENSET},
        {"bytes", TokenType::BYTES},
        {"bytearray", TokenType::BYTEARRAY},
        {"memoryview", TokenType::MEMORYVIEW},
        {"range", TokenType::RANGE},
        {"slice", TokenType::SLICE},
        {"complex", TokenType::COMPLEX},
        {"object", TokenType::OBJECT},
        {"type", TokenType::TYPE},
        {"super", TokenType::SUPER},
        {"property", TokenType::PROPERTY},
        {"staticmethod", TokenType::STATICMETHOD},
        {"classmethod", TokenType::CLASSMETHOD},
        {"len", TokenType::LEN},
        {"abs", TokenType::ABS},
        {"min", TokenType::MIN},
        {"max", TokenType::MAX},
        {"sum", TokenType::SUM},
        {"all", TokenType::ALL},
        {"any", TokenType::ANY},
        {"sorted", TokenType::SORTED},
        {"reversed", TokenType::REVERSED},
        {"enumerate", TokenType::ENUMERATE},
        {"zip", TokenType::ZIP},
        {"filter", TokenType::FILTER},
        {"map", TokenType::MAP},
        {"reduce", TokenType::REDUCE},
        {"lambda", TokenType::LAMBDA},
        {"def", TokenType::DEF},
        {"class", TokenType::CLASS},
        {"return", TokenType::RETURN},
        {"yield", TokenType::YIELD},
        {"raise", TokenType::RAISE},
        {"assert", TokenType::ASSERT},
        {"del", TokenType::DEL},
        {"pass", TokenType::PASS},
        {"break", TokenType::BREAK},
        {"continue", TokenType::CONTINUE},
        {"if", TokenType::IF},
        {"elif", TokenType::ELIF},
        {"else", TokenType::ELSE},
        {"while", TokenType::WHILE},
        {"for", TokenType::FOR},
        {"in", TokenType::IN},
        {"not", TokenType::NOT},
        {"and", TokenType::AND},
        {"or", TokenType::OR},
        {"is", TokenType::IS},
        {"with", TokenType::WITH},
        {"as", TokenType::AS},
        {"try", TokenType::TRY},
        {"except", TokenType::EXCEPT},
        {"finally", TokenType::FINALLY},
        {"import", TokenType::IMPORT},
        {"from", TokenType::FROM},
        {"global", TokenType::GLOBAL},
        {"nonlocal", TokenType::NONLOCAL},
        {"async", TokenType::ASYNC},
        {"await", TokenType::AWAIT},
        {"match", TokenType::MATCH},
        {"case", TokenType::CASE},
        {"_", TokenType::UNDERSCORE}
    };
}

template<typename Allocator>
void BasicLexer<Allocator>::skip_comment() {
    if (current_char() == '/' && peek_char() == '/') {
        while (current_char() != '\n' && !is_at_end()) {
            advance();
        }
    }
}

template<typename Allocator>
void BasicLexer<Allocator>::skip_multiline_comment() {
    if (current_char() == '/' && peek_char() == '*') {
        advance();
        advance();
        while (!is_at_end()) {
            if (current_char() == '*' && peek_char() == '/') {
                advance();
                advance();
                break;
            }
            advance();
        }
    }
}

template<typename Allocator>
std::expected<std::string, LexerError> BasicLexer<Allocator>::read_identifier() {
    std::string result;
    
    if (!is_alpha(current_char())) {
        return std::unexpected(LexerError{
            "Expected alphabetic character",
            line_,
            column_,
            position_,
            get_context()
        });
    }
    
    while (is_alnum(current_char()) || current_char() == '_') {
        result += current_char();
        advance();
    }
    
    return result;
}

template<typename Allocator>
std::expected<std::string, LexerError> BasicLexer<Allocator>::read_number() {
    std::string result;
    bool has_dot = false;
    bool has_exp = false;
    
    if (current_char() == '0') {
        result += current_char();
        advance();
        
        if (current_char() == 'x' || current_char() == 'X') {
            return read_hex_literal();
        } else if (current_char() == 'b' || current_char() == 'B') {
            return read_binary_literal();
        } else if (current_char() == 'o' || current_char() == 'O') {
            result += current_char();
            advance();
            while (is_octal_digit(current_char())) {
                result += current_char();
                advance();
            }
            return result;
        }
    }
    
    while (is_digit(current_char())) {
        result += current_char();
        advance();
    }
    
    if (current_char() == '.' && !has_dot) {
        has_dot = true;
        result += current_char();
        advance();
        
        while (is_digit(current_char())) {
            result += current_char();
            advance();
        }
    }
    
    if ((current_char() == 'e' || current_char() == 'E') && !has_exp) {
        has_exp = true;
        result += current_char();
        advance();
        
        if (current_char() == '+' || current_char() == '-') {
            result += current_char();
            advance();
        }
        
        while (is_digit(current_char())) {
            result += current_char();
            advance();
        }
    }
    
    if (result.empty()) {
        return std::unexpected(LexerError{
            "Invalid number format",
            line_,
            column_,
            position_,
            get_context()
        });
    }
    
    return result;
}

template<typename Allocator>
std::expected<std::string, LexerError> BasicLexer<Allocator>::read_hex_literal() {
    std::string result = "0x";
    advance();
    advance();
    
    if (!is_hex_digit(current_char())) {
        return std::unexpected(LexerError{
            "Expected hexadecimal digit",
            line_,
            column_,
            position_,
            get_context()
        });
    }
    
    while (is_hex_digit(current_char()) || current_char() == '_') {
        if (current_char() != '_') {
            result += current_char();
        }
        advance();
    }
    
    return result;
}

template<typename Allocator>
std::expected<std::string, LexerError> BasicLexer<Allocator>::read_binary_literal() {
    std::string result = "0b";
    advance();
    advance();
    
    if (!is_binary_digit(current_char())) {
        return std::unexpected(LexerError{
            "Expected binary digit",
            line_,
            column_,
            position_,
            get_context()
        });
    }
    
    while (is_binary_digit(current_char()) || current_char() == '_') {
        if (current_char() != '_') {
            result += current_char();
        }
        advance();
    }
    
    return result;
}

template<typename Allocator>
std::expected<std::string, LexerError> BasicLexer<Allocator>::read_string() {
    std::string result;
    char quote = current_char();
    advance();
    
    while (!is_at_end() && current_char() != quote) {
        if (current_char() == '\\') {
            advance();
            if (is_at_end()) {
                return std::unexpected(LexerError{
                    "Unterminated string literal",
                    line_,
                    column_,
                    position_,
                    get_context()
                });
            }
            
            char escaped = current_char();
            switch (escaped) {
                case 'n': result += '\n'; break;
                case 't': result += '\t'; break;
                case 'r': result += '\r'; break;
                case 'b': result += '\b'; break;
                case 'f': result += '\f'; break;
                case 'v': result += '\v'; break;
                case 'a': result += '\a'; break;
                case '0': result += '\0'; break;
                case '\\': result += '\\'; break;
                case '\'': result += '\''; break;
                case '\"': result += '\"'; break;
                case 'x': {
                    advance();
                    if (!is_hex_digit(current_char())) {
                        return std::unexpected(LexerError{
                            "Invalid hex escape sequence",
                            line_,
                            column_,
                            position_,
                            get_context()
                        });
                    }
                    std::string hex_str;
                    hex_str += current_char();
                    advance();
                    if (is_hex_digit(current_char())) {
                        hex_str += current_char();
                    } else {
                        position_--;
                        column_--;
                    }
                    result += static_cast<char>(std::stoi(hex_str, nullptr, 16));
                    break;
                }
                case 'u': {
                    advance();
                    std::string unicode_str;
                    for (int i = 0; i < 4; ++i) {
                        if (!is_hex_digit(current_char())) {
                            return std::unexpected(LexerError{
                                "Invalid unicode escape sequence",
                                line_,
                                column_,
                                position_,
                                get_context()
                            });
                        }
                        unicode_str += current_char();
                        advance();
                    }
                    position_--;
                    column_--;
                    int unicode_val = std::stoi(unicode_str, nullptr, 16);
                    if (unicode_val <= 0x7F) {
                        result += static_cast<char>(unicode_val);
                    } else if (unicode_val <= 0x7FF) {
                        result += static_cast<char>(0xC0 | (unicode_val >> 6));
                        result += static_cast<char>(0x80 | (unicode_val & 0x3F));
                    } else {
                        result += static_cast<char>(0xE0 | (unicode_val >> 12));
                        result += static_cast<char>(0x80 | ((unicode_val >> 6) & 0x3F));
                        result += static_cast<char>(0x80 | (unicode_val & 0x3F));
                    }
                    break;
                }
                default:
                    result += escaped;
                    break;
            }
        } else {
            result += current_char();
        }
        advance();
    }
    
    if (current_char() != quote) {
        return std::unexpected(LexerError{
            "Unterminated string literal",
            line_,
            column_,
            position_,
            get_context()
        });
    }
    
    advance();
    return result;
}

template<typename Allocator>
std::expected<std::string, LexerError> BasicLexer<Allocator>::read_raw_string() {
    std::string result;
    advance();
    advance();
    
    std::string delimiter;
    while (current_char() != '(' && !is_at_end()) {
        delimiter += current_char();
        advance();
    }
    
    if (current_char() != '(') {
        return std::unexpected(LexerError{
            "Expected '(' in raw string literal",
            line_,
            column_,
            position_,
            get_context()
        });
    }
    
    advance();
    
    while (!is_at_end()) {
        if (current_char() == ')') {
            size_t saved_pos = position_;
            size_t saved_line = line_;
            size_t saved_col = column_;
            advance();
            
            bool matches = true;
            for (char c : delimiter) {
                if (current_char() != c) {
                    matches = false;
                    break;
                }
                advance();
            }
            
            if (matches && current_char() == '"') {
                advance();
                return result;
            } else {
                position_ = saved_pos;
                line_ = saved_line;
                column_ = saved_col;
                result += current_char();
                advance();
            }
        } else {
            result += current_char();
            advance();
        }
    }
    
    return std::unexpected(LexerError{
        "Unterminated raw string literal",
        line_,
        column_,
        position_,
        get_context()
    });
}

template<typename Allocator>
std::expected<std::string, LexerError> BasicLexer<Allocator>::read_regex_literal() {
    std::string result;
    advance();
    
    while (!is_at_end() && current_char() != '/') {
        if (current_char() == '\\') {
            result += current_char();
            advance();
            if (!is_at_end()) {
                result += current_char();
                advance();
            }
        } else {
            result += current_char();
            advance();
        }
    }
    
    if (current_char() != '/') {
        return std::unexpected(LexerError{
            "Unterminated regex literal",
            line_,
            column_,
            position_,
            get_context()
        });
    }
    
    advance();
    
    while (is_alpha(current_char())) {
        result += current_char();
        advance();
    }
    
    return result;
}

template<typename Allocator>
std::expected<std::string, LexerError> BasicLexer<Allocator>::read_template_literal() {
    std::string result;
    advance();
    
    while (!is_at_end() && current_char() != '`') {
        if (current_char() == '\\') {
            advance();
            if (!is_at_end()) {
                result += current_char();
                advance();
            }
        } else if (current_char() == '$' && peek_char() == '{') {
            result += "${";
            advance();
            advance();
            
            int brace_count = 1;
            while (!is_at_end() && brace_count > 0) {
                if (current_char() == '{') {
                    brace_count++;
                } else if (current_char() == '}') {
                    brace_count--;
                }
                result += current_char();
                advance();
            }
        } else {
            result += current_char();
            advance();
        }
    }
    
    if (current_char() != '`') {
        return std::unexpected(LexerError{
            "Unterminated template literal",
            line_,
            column_,
            position_,
            get_context()
        });
    }
    
    advance();
    return result;
}

template<typename Allocator>
TokenType BasicLexer<Allocator>::get_keyword_type(std::string_view identifier) const {
    auto it = keywords_.find(std::string(identifier));
    return (it != keywords_.end()) ? it->second : TokenType::IDENTIFIER;
}

template<typename Allocator>
TokenType BasicLexer<Allocator>::get_operator_type(std::string_view op) const {
    auto it = operators_.find(std::string(op));
    return (it != operators_.end()) ? it->second : TokenType::UNKNOWN;
}

template<typename Allocator>
TokenType BasicLexer<Allocator>::get_hacker_keyword_type(std::string_view identifier) const {
    if (mode_ == LexerMode::HACKER || mode_ == LexerMode::EXPLOIT) {
        auto it = hacker_keywords_.find(std::string(identifier));
        return (it != hacker_keywords_.end()) ? it->second : TokenType::IDENTIFIER;
    }
    return TokenType::IDENTIFIER;
}

template<typename Allocator>
LexerResult BasicLexer<Allocator>::make_token(TokenType type, std::string_view value) {
    return Token{type, std::string(value), line_, column_};
}

template<typename Allocator>
LexerResult BasicLexer<Allocator>::make_error(std::string_view message) {
    return std::unexpected(LexerError{
        std::string(message),
        line_,
        column_,
        position_,
        get_context()
    });
}

template<typename Allocator>
std::string BasicLexer<Allocator>::get_context(size_t radius) const {
    size_t start = position_ > radius ? position_ - radius : 0;
    size_t end = std::min(position_ + radius, source_.size());
    return std::string(source_.substr(start, end - start));
}

template<typename Allocator>
LexerResult BasicLexer<Allocator>::scan_hacker_token() {
    if (mode_ == LexerMode::HACKER && HACK_PATTERN.match(source_, position_)) {
        std::string token = "hack";
        advance_by(4);
        return make_token(TokenType::HACK, token);
    }
    
    if (mode_ == LexerMode::EXPLOIT && EXPLOIT_PATTERN.match(source_, position_)) {
        std::string token = "exploit";
        advance_by(7);
        return make_token(TokenType::EXPLOIT, token);
    }
    
    return make_token(TokenType::UNKNOWN, "");
}

template<typename Allocator>
LexerResult BasicLexer<Allocator>::next_token() {
    skip_whitespace();
    
    if (is_at_end()) {
        return make_token(TokenType::EOF_TOKEN, "");
    }
    
    char c = current_char();
    
    if (c == '\n') {
        advance();
        return make_token(TokenType::NEWLINE, "\n");
    }
    
    if (c == '/' && peek_char() == '/') {
        skip_comment();
        return next_token();
    }
    
    if (c == '/' && peek_char() == '*') {
        skip_multiline_comment();
        return next_token();
    }
    
    if (is_alpha(c)) {
        auto result = read_identifier();
        if (!result) {
            return std::unexpected(result.error());
        }
        
        std::string identifier = *result;
        
        TokenType hacker_type = get_hacker_keyword_type(identifier);
        if (hacker_type != TokenType::IDENTIFIER) {
            return make_token(hacker_type, identifier);
        }
        
        TokenType keyword_type = get_keyword_type(identifier);
        if (keyword_type != TokenType::IDENTIFIER) {
            return make_token(keyword_type, identifier);
        }
        
        return make_token(TokenType::IDENTIFIER, identifier);
    }
    
    if (is_digit(c)) {
        auto result = read_number();
        if (!result) {
            return std::unexpected(result.error());
        }
        
        std::string number = *result;
        
        if (number.find('.') != std::string::npos || 
            number.find('e') != std::string::npos || 
            number.find('E') != std::string::npos) {
            return make_token(TokenType::FLOAT_LITERAL, number);
        } else if (number.find("0x") == 0 || number.find("0X") == 0) {
            return make_token(TokenType::HEX_LITERAL, number);
        } else if (number.find("0b") == 0 || number.find("0B") == 0) {
            return make_token(TokenType::BINARY_LITERAL, number);
        } else {
            return make_token(TokenType::INTEGER_LITERAL, number);
        }
    }
    
    if (c == '"' || c == '\'') {
        auto result = read_string();
        if (!result) {
            return std::unexpected(result.error());
        }
        return make_token(TokenType::STRING_LITERAL, *result);
    }
    
    if (c == '`') {
        auto result = read_template_literal();
        if (!result) {
            return std::unexpected(result.error());
        }
        return make_token(TokenType::TEMPLATE_LITERAL, *result);
    }
    
    if (c == 'R' && peek_char() == '"') {
        auto result = read_raw_string();
        if (!result) {
            return std::unexpected(result.error());
        }
        return make_token(TokenType::RAW_STRING_LITERAL, *result);
    }
    
    std::string op;
    size_t max_op_length = 4;
    
    for (size_t i = 1; i <= max_op_length && position_ + i <= source_.size(); ++i) {
        std::string candidate = std::string(source_.substr(position_, i));
        if (operators_.find(candidate) != operators_.end()) {
            op = candidate;
        }
    }
    
    if (!op.empty()) {
        TokenType op_type = get_operator_type(op);
        advance_by(op.length());
        return make_token(op_type, op);
    }
    
    if (mode_ == LexerMode::HACKER || mode_ == LexerMode::EXPLOIT) {
        auto hacker_result = scan_hacker_token();
        if (hacker_result->type != TokenType::UNKNOWN) {
            return hacker_result;
        }
    }
    
    advance();
    return make_token(TokenType::UNKNOWN, std::string(1, c));
}

template<typename Allocator>
TokenResult BasicLexer<Allocator>::tokenize() {
    std::vector<Token> tokens;
    
    while (!is_at_end()) {
        auto result = next_token();
        if (!result) {
            return std::unexpected(result.error());
        }
        
        if (result->type != TokenType::EOF_TOKEN) {
            tokens.push_back(*result);
        }
    }
    
    tokens.push_back(Token{TokenType::EOF_TOKEN, "", line_, column_});
    return tokens;
}

template<typename Allocator>
bool BasicLexer<Allocator>::match_keyword(std::string_view keyword) const {
    return keywords_.find(std::string(keyword)) != keywords_.end();
}

template<typename Allocator>
bool BasicLexer<Allocator>::match_operator(std::string_view op) const {
    return operators_.find(std::string(op)) != operators_.end();
}

template<typename Allocator>
bool BasicLexer<Allocator>::match_hacker_keyword(std::string_view keyword) const {
    return hacker_keywords_.find(std::string(keyword)) != hacker_keywords_.end();
}

template<typename Allocator>
std::vector<Token> BasicLexer<Allocator>::peek_tokens(size_t count) const {
    BasicLexer<Allocator> temp_lexer(*this);
    std::vector<Token> result;
    
    for (size_t i = 0; i < count && !temp_lexer.is_at_end(); ++i) {
        auto token_result = temp_lexer.next_token();
        if (token_result) {
            result.push_back(*token_result);
        } else {
            break;
        }
    }
    
    return result;
}

template<typename Allocator>
std::optional<Token> BasicLexer<Allocator>::peek_token(size_t offset) const {
    auto tokens = peek_tokens(offset);
    return tokens.size() >= offset ? std::optional<Token>(tokens[offset - 1]) : std::nullopt;
}

template<typename Allocator>
typename BasicLexer<Allocator>::Statistics BasicLexer<Allocator>::get_statistics() const {
    Statistics stats;
    stats.total_characters = source_.size();
    stats.total_lines = line_;
    
    BasicLexer<Allocator> temp_lexer(*this);
    temp_lexer.reset();
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    while (!temp_lexer.is_at_end()) {
        auto result = temp_lexer.next_token();
        if (result) {
            stats.add_token(result->type);
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    stats.tokenization_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
    
    return stats;
}

template<typename Allocator>
bool BasicLexer<Allocator>::validate_syntax() const {
    BasicLexer<Allocator> temp_lexer(*this);
    temp_lexer.reset();
    
    int paren_count = 0;
    int bracket_count = 0;
    int brace_count = 0;
    
    while (!temp_lexer.is_at_end()) {
        auto result = temp_lexer.next_token();
        if (!result) {
            return false;
        }
        
        switch (result->type) {
            case TokenType::LEFT_PAREN: paren_count++; break;
            case TokenType::RIGHT_PAREN: paren_count--; break;
            case TokenType::LEFT_BRACKET: bracket_count++; break;
            case TokenType::RIGHT_BRACKET: bracket_count--; break;
            case TokenType::LEFT_BRACE: brace_count++; break;
            case TokenType::RIGHT_BRACE: brace_count--; break;
            default: break;
        }
        
        if (paren_count < 0 || bracket_count < 0 || brace_count < 0) {
            return false;
        }
    }
    
    return paren_count == 0 && bracket_count == 0 && brace_count == 0;
}

template<typename Allocator>
std::vector<LexerError> BasicLexer<Allocator>::get_all_errors() const {
    std::vector<LexerError> errors;
    BasicLexer<Allocator> temp_lexer(*this);
    temp_lexer.reset();
    
    while (!temp_lexer.is_at_end()) {
        auto result = temp_lexer.next_token();
        if (!result) {
            errors.push_back(result.error());
        }
    }
    
    return errors;
}

template<typename Allocator>
void BasicLexer<Allocator>::enable_error_recovery(bool enable) {
    
}

template<typename Allocator>
void BasicLexer<Allocator>::set_error_limit(size_t limit) {
    
}

template class BasicLexer<std::allocator<Token>>;
template class BasicLexer<std::pmr::polymorphic_allocator<Token>>;

} 