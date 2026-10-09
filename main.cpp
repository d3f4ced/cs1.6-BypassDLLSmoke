#define NOMINMAX

#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <algorithm>

namespace fs = std::filesystem;

constexpr std::size_t PATCH_RVA = 0x6AFDE;
constexpr std::uint8_t ORIGINAL = 0x75;
constexpr std::uint8_t PATCHED = 0x74;

namespace Console
{
    constexpr WORD WHITE = 7;
    constexpr WORD RED = 12;
    constexpr WORD GREEN = 10;
    constexpr WORD GRAY = 8;
    constexpr WORD CYAN = 11;

    void color(WORD value)
    {
        SetConsoleTextAttribute(
            GetStdHandle(STD_OUTPUT_HANDLE), value
        );
    }

    void print(const std::string& prefix,
        const std::string& message,
        WORD shade = WHITE)
    {
        color(shade);
        std::cout << "  " << prefix << " ";
        color(WHITE);
        std::cout << message << '\n';
    }

    void header()
    {
        system("cls");
        color(RED);
        std::cout << "\n";
        std::cout << "  =====================================\n";
        std::cout << "             DEFACED PATCHER\n";
        std::cout << "  =====================================\n";
        color(GRAY);
        std::cout << "         developed by defaced\n\n";
        color(WHITE);
    }

    void pause()
    {
        color(GRAY);
        std::cout << "\n  Press ENTER to exit...";
        color(WHITE);
        std::string line;
        std::getline(std::cin, line);
    }
}

std::uint32_t read32(
    const std::vector<std::uint8_t>& data,
    std::size_t pos)
{
    if (pos > data.size() || data.size() - pos < 4)
        throw std::runtime_error("Invalid PE structure.");

    return static_cast<std::uint32_t>(data[pos])
        | (static_cast<std::uint32_t>(data[pos + 1]) << 8)
        | (static_cast<std::uint32_t>(data[pos + 2]) << 16)
        | (static_cast<std::uint32_t>(data[pos + 3]) << 24);
}

std::size_t rvaToOffset(
    const std::vector<std::uint8_t>& data,
    std::size_t rva)
{
    if (data.size() < 0x40 ||
        data[0] != 'M' || data[1] != 'Z')
        throw std::runtime_error("Invalid DLL format.");

    const std::size_t pe = read32(data, 0x3C);

    if (pe > data.size() ||
        data.size() - pe < 24 ||
        read32(data, pe) != 0x00004550)
        throw std::runtime_error("Invalid PE signature.");

    const std::size_t count =
        static_cast<std::size_t>(data[pe + 6])
        | (static_cast<std::size_t>(data[pe + 7]) << 8);

    const std::size_t optionalSize =
        static_cast<std::size_t>(data[pe + 20])
        | (static_cast<std::size_t>(data[pe + 21]) << 8);

    const std::size_t sections = pe + 24 + optionalSize;

    if (sections > data.size() ||
        count > (data.size() - sections) / 40)
        throw std::runtime_error("Invalid section table.");

    for (std::size_t i = 0; i < count; ++i)
    {
        const std::size_t s = sections + i * 40;

        const auto virtualSize = read32(data, s + 8);
        const auto virtualAddress = read32(data, s + 12);
        const auto rawSize = read32(data, s + 16);
        const auto rawPointer = read32(data, s + 20);

        const auto sectionSize = std::max(virtualSize, rawSize);

        if (rva >= virtualAddress &&
            rva - virtualAddress < sectionSize &&
            rva - virtualAddress < rawSize)
        {
            const std::size_t offset =
                rawPointer + rva - virtualAddress;

            if (offset < data.size())
                return offset;
        }
    }

    throw std::runtime_error("Patch RVA not found.");
}

std::vector<std::uint8_t> readFile(const fs::path& path)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);

    if (!file)
        throw std::runtime_error("Unable to open DLL.");

    const auto size = file.tellg();

    if (size <= 0)
        throw std::runtime_error("DLL is empty.");

    std::vector<std::uint8_t> data(
        static_cast<std::size_t>(size)
    );

    file.seekg(0);
    file.read(
        reinterpret_cast<char*>(data.data()),
        static_cast<std::streamsize>(data.size())
    );

    if (!file)
        throw std::runtime_error("Unable to read DLL.");

    return data;
}

void patchDLL(const fs::path& input)
{
    Console::print("[+]", "Reading DLL...", Console::CYAN);

    auto data = readFile(input);
    const auto offset = rvaToOffset(data, PATCH_RVA);

    fs::path output = input.parent_path() /
        (input.stem().wstring() + L"_patched" +
            input.extension().wstring());

    std::cout << '\n';

    Console::print("[+]", "Target DLL:");
    std::wcout << L"      " << input.wstring() << L'\n';

    Console::print("[+]", "Output DLL:");
    std::wcout << L"      " << output.wstring() << L'\n';

    Console::print("[+]", "Patch RVA: 0x6AFDE");

    std::cout << '\n';

    if (data[offset] == PATCHED)
    {
        Console::print(
            "[!]", "DLL is already patched.", Console::CYAN
        );
        return;
    }

    if (data[offset] != ORIGINAL)
    {
        Console::print(
            "[ERROR]",
            "Unexpected opcode. Patch cancelled.",
            Console::RED
        );
        return;
    }

    Console::print(
        "[OK]",
        "Original opcode verified: JNZ (0x75)",
        Console::GREEN
    );

    std::cout << '\n';
    Console::color(Console::RED);
    std::cout << "  Apply patch? [Y/N]: ";
    Console::color(Console::WHITE);

    std::string answer;
    std::getline(std::cin, answer);

    if (answer != "Y" && answer != "y")
    {
        Console::print(
            "[!]", "Operation cancelled.", Console::GRAY
        );
        return;
    }

    if (fs::exists(output))
        throw std::runtime_error(
            "Output already exists. Move or rename it first."
        );

    data[offset] = PATCHED;

    std::ofstream file(
        output, std::ios::binary | std::ios::trunc
    );

    if (!file)
        throw std::runtime_error(
            "Unable to create patched DLL."
        );

    file.write(
        reinterpret_cast<const char*>(data.data()),
        static_cast<std::streamsize>(data.size())
    );

    file.close();

    if (!file)
        throw std::runtime_error(
            "Unable to save patched DLL."
        );

    Console::print(
        "[SUCCESS]",
        "Patch applied: JNZ -> JZ",
        Console::GREEN
    );

    Console::print(
        "[OK]",
        "Patched DLL saved successfully.",
        Console::GREEN
    );
}

int wmain(int argc, wchar_t* argv[])
{
    SetConsoleTitleW(L"DEFACED | DLL PATCHER");
    Console::header();

    try
    {
        fs::path input;

        if (argc >= 2)
        {
            input = argv[1];
        }
        else
        {
            Console::print(
                "[+]",
                "Drag a DLL into this window or enter its path:",
                Console::CYAN
            );

            std::wcout << L"\n  > ";

            std::wstring path;
            std::getline(std::wcin, path);

            if (path.size() >= 2 &&
                path.front() == L'"' &&
                path.back() == L'"')
            {
                path = path.substr(1, path.size() - 2);
            }

            input = path;
        }

        if (!fs::exists(input) || !fs::is_regular_file(input))
            throw std::runtime_error("DLL file not found.");

        if (input.extension() != L".dll")
            throw std::runtime_error("Please select a DLL file.");

        patchDLL(input);
    }
    catch (const std::exception& e)
    {
        Console::print(
            "[ERROR]", e.what(), Console::RED
        );
    }

    Console::pause();
    return 0;
}
