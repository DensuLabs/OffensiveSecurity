#ifdef _WIN32
#include <windows.h>

class PEParser {
private:
    std::vector<uint8_t> file_data;
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS nt_headers;
    
public:
    bool load_file(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) return false;
        
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        file_data.resize(file_size);
        file.read(reinterpret_cast<char*>(file_data.data()), file_size);
        file.close();
        
        if (file_data.size() < sizeof(IMAGE_DOS_HEADER)) return false;
        
        dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(file_data.data());
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        if (dos_header->e_lfanew >= file_data.size()) return false;
        
        nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(file_data.data() + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return false;
        
        return true;
    }
    
    std::vector<std::string> get_imported_dlls() {
        std::vector<std::string> dlls;
        
        DWORD import_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (import_rva == 0) return dlls;
        
        DWORD import_offset = rva_to_offset(import_rva);
        if (import_offset == 0) return dlls;
        
        PIMAGE_IMPORT_DESCRIPTOR import_desc = 
            reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(file_data.data() + import_offset);
        
        while (import_desc->Name != 0) {
            DWORD name_offset = rva_to_offset(import_desc->Name);
            if (name_offset != 0) {
                char* dll_name = reinterpret_cast<char*>(file_data.data() + name_offset);
                dlls.push_back(std::string(dll_name));
            }
            import_desc++;
        }
        
        return dlls;
    }
    
    std::vector<std::string> get_imported_functions(const std::string& dll_name) {
        std::vector<std::string> functions;
        
        DWORD import_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (import_rva == 0) return functions;
        
        DWORD import_offset = rva_to_offset(import_rva);
        if (import_offset == 0) return functions;
        
        PIMAGE_IMPORT_DESCRIPTOR import_desc = 
            reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(file_data.data() + import_offset);
        
        while (import_desc->Name != 0) {
            DWORD name_offset = rva_to_offset(import_desc->Name);
            if (name_offset != 0) {
                char* current_dll = reinterpret_cast<char*>(file_data.data() + name_offset);
                
                if (_stricmp(current_dll, dll_name.c_str()) == 0) {
                    // Found the DLL, now get functions
                    DWORD thunk_rva = import_desc->OriginalFirstThunk;
                    if (thunk_rva == 0) thunk_rva = import_desc->FirstThunk;
                    
                    DWORD thunk_offset = rva_to_offset(thunk_rva);
                    if (thunk_offset != 0) {
                        PIMAGE_THUNK_DATA thunk = 
                            reinterpret_cast<PIMAGE_THUNK_DATA>(file_data.data() + thunk_offset);
                        
                        while (thunk->u1.AddressOfData != 0) {
                            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                                DWORD func_offset = rva_to_offset(thunk->u1.AddressOfData);
                                if (func_offset != 0) {
                                    PIMAGE_IMPORT_BY_NAME import_name = 
                                        reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(file_data.data() + func_offset);
                                    functions.push_back(std::string(import_name->Name));
                                }
                            }
                            thunk++;
                        }
                    }
                    break;
                }
            }
            import_desc++;
        }
        
        return functions;
    }
    
private:
    DWORD rva_to_offset(DWORD rva) {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
        
        for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
            if (rva >= section->VirtualAddress && 
                rva < section->VirtualAddress + section->Misc.VirtualSize) {
                return rva - section->VirtualAddress + section->PointerToRawData;
            }
            section++;
        }
        return 0;
    }
};
#endif