#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <fstream>
#include <string>
#include <string_view>
#include <numeric>
#include <vector>
#include <memory_resource>

char to_base64_char(std::uint8_t index) {
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[index & 63];
}

std::uint8_t from_base64_char(char ch) {
    if ('A' <= ch && ch <= 'Z') {
        return ch - 'A';
    } else if ('a' <= ch && ch <= 'z') {
        return 26 + (ch - 'a');
    } else if ('0' <= ch && ch <= '9') {
        return 52 + (ch - '0');
    } else if (ch == '+') {
        return 62;
    } else if (ch == '/') {
        return 63;
    } else if (ch == '=') {
        return 0;
    } else {
        std::cerr << "from_base64_char: character '" << std::string{ch} << "' cannot be converted to an index\n";
        return 255;
    }
}

std::string base64_encode(const char *bytes, std::size_t size) {
    std::string result{};

    std::size_t remainder = size % 3;
    std::size_t i = 0;
    for (; i < size - remainder; i += 3) {
        std::uint32_t triplet = static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i])) << 16 |
                                static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 1])) << 8 |
                                static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[i + 2]));

        std::uint8_t first = (triplet & (0b111111 << 18)) >> 18;
        std::uint8_t second = (triplet & (0b111111 << 12)) >> 12;
        std::uint8_t third = (triplet & (0b111111 << 6)) >> 6;
        std::uint8_t fourth = triplet & 0b111111;
        result += to_base64_char(first);
        result += to_base64_char(second);
        result += to_base64_char(third);
        result += to_base64_char(fourth);
    }

    // We have some of a triplet still left
    if (remainder != 0) {
        if (remainder == 1) {
            std::uint8_t singlet = static_cast<std::uint8_t>(bytes[size - 1]);
            std::uint8_t first = (singlet & (0b111111 << 2)) >> 2;
            std::uint8_t second = (singlet & 0b11) << 4;

            result += to_base64_char(first);
            result += to_base64_char(second);
            result += "==";
        } else if (remainder == 2) {
            std::uint16_t doublet =
                static_cast<std::uint8_t>(bytes[size - 2]) << 8 | static_cast<std::uint8_t>(bytes[size - 1]);
            std::uint8_t first = (doublet & (0b111111 << 10)) >> 10;
            std::uint8_t second = (doublet & (0b111111 << 4)) >> 4;
            std::uint8_t third = (doublet & 0b11111) << 2;

            result += to_base64_char(first);
            result += to_base64_char(second);
            result += to_base64_char(third);
            result += '=';
        }
    }

    return result;
}

std::string base64_decode(std::string_view str) {
    if ((str.length() & 3) != 0) {
        std::cerr << "base64_decode: string length not a multiple of 4, padded incorrectly";
    }

    std::string result{};

    std::size_t remainder = str.length() & 3;
    std::size_t i = 0;
    for (; i < str.length() - remainder; i += 4) {
        std::uint32_t value = from_base64_char(str[i]) << 18 | from_base64_char(str[i + 1]) << 12 |
                              from_base64_char(str[i + 2]) << 6 | from_base64_char(str[i + 3]);

        result.push_back(static_cast<unsigned char>(value >> 16));
        if (str[i + 2] != '=') {
            result.push_back(static_cast<unsigned char>(value >> 8));
        }
        if (str[i + 3] != '=') {
            result.push_back(static_cast<unsigned char>(value));
        }
    }

    if (remainder != 0) {
        if (remainder == 2) {
            std::uint8_t value =
                from_base64_char(str[str.length() - 2]) << 2 | from_base64_char(str[str.length() - 1]) >> 4;

            result.push_back(static_cast<unsigned char>(value));
        } else if (remainder == 3) {
            std::uint16_t value = from_base64_char(str[str.length() - 3]) << 10 |
                                  from_base64_char(str[str.length() - 2]) << 4 |
                                  from_base64_char(str[str.length() - 1]) >> 2;

            result.push_back(static_cast<unsigned char>(value >> 8));
            result.push_back(static_cast<unsigned char>(value & 0b11111111));
        }
    }

    return result;
}

char substitute(char a, char b) {
    return to_base64_char(from_base64_char(a) + from_base64_char(b));
}

char inverse_substitute(char a, char b) {
    return to_base64_char((from_base64_char(a) - from_base64_char(b)) % 64);
}

char xor_sub(char a, char b) {
    return to_base64_char(from_base64_char(a) ^ from_base64_char(b));
}

char xor_sub2(char a, char b) {
    return to_base64_char(from_base64_char(a) ^ b);
}

std::string setkeysize(std::string key) {
    if (key.length() > 12) {
        return base64_encode(key.data(), 12);
    } else {
        std::size_t i = 0;
        std::size_t orig_len = key.length();
        key.reserve(key.length() + 12 % key.length());
        while (key.length() != 12) {
            key += key[i++ % orig_len];
        }
        return base64_encode(key.data(), 12);
    }
}

std::string rotleft(std::string key) {
    std::string rotated{key.begin() + 1, key.end()};
    rotated += key[0];
    return rotated;
}

std::string encrypt(std::pmr::string message, std::size_t length, std::string key) {
    std::size_t len = length;
    constexpr char chars[] = "abcdefghijklmnopqrstuvwxyz";
    std::size_t count_padding = 12 - length % 12;
    std::string padded;
    padded.resize(count_padding);
    for (std::size_t i = 0; i < count_padding; i++) {
        padded[i] = chars[(length + i) % 26];
    }
    // padded[count_padding] = 0;
    length += count_padding;
    // std::cout << padded << '\n';
    for (std::size_t i = 0; i < padded.length(); i++) {
        message += padded[i];
    }
    // message.resize(message.length() + count_padding);
    // message += std::move(padded);
    // std::cout << message << '\n';
    std::string message_len = std::to_string(len);
    count_padding = 12 - message_len.length() % 12;
    padded = "";
    padded.resize(count_padding);
    for (std::size_t i = 0; i < count_padding; i++) {
        padded[i] = chars[(message_len.length() + i) % 26];
    }
    std::reverse(padded.begin(), padded.end());
    message_len = std::move(padded) + std::move(message_len);
    length += message_len.length();
    // std::cout << message_len << '\n';
    message += std::move(message_len);
    // key = setkeysize(std::move(key));
    std::string encoded = base64_encode(message.data(), length);
    // std::cout << "Original: " << message << '\n';// << "\nEncoded: " << encoded << '\n';
    std::vector<std::string> blocks;
    for (std::size_t i = 0; i < encoded.length() / 16; i++) {
        blocks.push_back("");
        blocks.back().resize(16);
        std::string_view block{&encoded[i * 16], 16};
        std::size_t combined = 0;
        for (char ch : block) {
            combined ^= from_base64_char(ch);
        }
        std::string modified;
        modified.reserve(16);
        std::size_t j = 0;
        for (char ch : block) {
            modified[j++] = to_base64_char(from_base64_char(ch) ^ combined);
        }
        // std::cout << combined << '\n';
        for (std::size_t i = 0; i < 16; i++) {
            blocks.back()[i] = substitute(modified[i], key[i]);
        }

        key = rotleft(std::move(key));
        for (std::size_t i = 0; i < 16; i++) {
            key[i] = xor_sub2(key[i], combined);
        }
    }
    std::string encrypted = std::accumulate(blocks.begin(), blocks.end(), std::string{});
    // std::cout << "Encrypted: " << encrypted << '\n';
    return base64_decode(encrypted);
}

std::string decrypt(const char *encrypted, std::size_t length, std::string key) {
    std::string decrypted = base64_encode(encrypted, length);
    // char buffer[4096];
    // std::pmr::monotonic_buffer_resource res{buffer, 4096};
    // std::pmr::polymorphic_allocator<char> pa{&res};
    std::vector<std::string> blocks{};
    for (std::size_t i = 0; i < decrypted.length() / 16; i++) {
        blocks.push_back("");
        blocks.back().resize(16);
        std::string_view block{&decrypted[i * 16], 16};
        for (std::size_t i = 0; i < 16; i++) {
            blocks.back()[i] = inverse_substitute(block[i], key[i]);
        }
        std::size_t combined = 0;
        for (char ch : blocks.back()) {
            combined ^= from_base64_char(ch);
        }
        for (std::size_t i = 0; i < 16; i++) {
            blocks.back()[i] = to_base64_char(from_base64_char(blocks.back()[i]) ^ combined);
        }
        // std::cout << blocks.back();
        key = rotleft(std::move(key));
        for (std::size_t i = 0; i < 16; i++) {
            // for (std::size_t j = 0; j < 16; j++) {
                key[i] = xor_sub2(key[i], combined);
            // }
        }
        // std::cout << blocks.back();
    }

    decrypted = std::accumulate(blocks.begin(), blocks.end(), std::string{});
    // std::cout << "Decrypted: " << decrypted << '\n';
    decrypted = base64_decode(decrypted);
    // std::cout << "Decrypted: " << decrypted << '\n' << '\n';
    const char *length2 = &decrypted[decrypted.length() - 12];
    std::size_t counted = 0;
    while (counted < 12 && !std::isdigit(*(length2 + counted))) {
        counted++;
    }
    std::string_view orig_len{length2 + counted, 12 - counted};
    // std::cout << orig_len << '\n';
    return decrypted.substr(0, std::atoi(orig_len.data()));
}

int main(int argc, char ** argv) {
    // std::ifstream message{};
    std::string key{};

    // std::cout << "Message: ";
    // std::getline(std::cin, message);

    // std::cout << "Key: ";
    key = setkeysize(argv[1]);
    // std::getline(std::cin, key);

    // std::ifstream message = std::ifstream{argv[2], std::ios::in | std::ios::binary};
    // key = setkeysize(std::move(key));
    FILE *f = fopen(argv[2], "rb");
    if (argc >= 4 && std::string{argv[3]} == "--decrypt") {
        char block[528];
        while (!feof_unlocked(f)) {
            std::size_t len = fread_unlocked(block, 1, 528, f);
            // std::string encrypted = encrypt(context, block , key);
            std::cout << decrypt(block, len, key);
        }
    } else {
        char block[512];
        char buffer[2048];
        while (!feof(f)) {
            std::pmr::monotonic_buffer_resource alloc{buffer, 2048};
            std::pmr::polymorphic_allocator<char> pa{&alloc};
            std::size_t len = std::fread(block, 1, 512, f);
            // std::string encrypted = encrypt(context, block , key);
            std::cout << encrypt(std::pmr::string{block, len, pa}, len, key);
        }
    }
    fclose(f);

    // std::string decrypted = decrypt(encrypted, key);
    // std::cout << decrypted << '\n';
}
