#include <windows.h>
#include <array>
#include <string>
#include <random>

class CodeObfuscator 
{
public:
    // 1. Compile-time XOR with unique keys
    template<size_t N, uint8_t K>
    struct CryptString {
        std::array<uint8_t, N> data;
        
        // Forced to run at compile time
        consteval CryptString(const char* str) : data{} {
            for (size_t i = 0; i < N; ++i) {
                data[i] = static_cast<uint8_t>(str[i]) ^ K;
            }
        }

        // Decrypts onto the stack only when needed
        std::string decrypt() const {
            std::string result(N - 1, '\0');
            for (size_t i = 0; i < N - 1; ++i) {
                result[i] = data[i] ^ K;
            }
            return result;
        }
    };

    // 2. Opaque Predicates using Volatile to prevent Compiler Optimization
    static bool is_authentic() {
        volatile int a = 5;
        volatile int b = 10;
        // Even with full optimization, compilers find it hard to prune this
        return ((a * b) + 5) == 55;
    }

    // 3. Secure Execution (RAII for Virtual Memory)
    struct SecurePayload {
        void* mem;
        size_t size;

        SecurePayload(const uint8_t* encrypted, size_t n, uint8_t key) : size(n) {
            mem = VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!mem) return;

            for (size_t i = 0; i < n; ++i) {
                static_cast<uint8_t*>(mem)[i] = encrypted[i] ^ key;
            }

            // Change to Execute only AFTER writing (W^X Policy)
            DWORD oldProtect;
            VirtualProtect(mem, n, PAGE_EXECUTE_READ, &oldProtect);
        }

        void run() const {
            if (mem) reinterpret_cast<void(*)()>(mem)();
        }

        ~SecurePayload() {
            if (mem) {
                SecureZeroMemory(mem, size); // Wipe code from memory before freeing
                VirtualFree(mem, 0, MEM_RELEASE);
            }
        }
    };
};

// Macro uses __LINE__ as a seed for the XOR key to ensure every string has a different key
#define OBFUSCATE(str) []() { \
    static constexpr auto obf = CodeObfuscator::CryptString<sizeof(str), (__LINE__ % 254) + 1>(str); \
    return obf.decrypt(); \
}()