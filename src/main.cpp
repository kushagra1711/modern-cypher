#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <numeric>
#include <vector>

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

std::string base64_encode(std::string::iterator bytes, std::size_t size) {
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
    return to_base64_char(static_cast<std::uint32_t>(from_base64_char(a) - from_base64_char(b)) & 63);
}

char xor_sub(char a, char b) {
    return to_base64_char(from_base64_char(a) ^ from_base64_char(b));
}

char xor_sub2(char a, char b) {
    return to_base64_char(from_base64_char(a) ^ b);
}

std::string setkeysize(std::string key) {
    if (key.length() > 12) {
        return base64_encode(key.begin(), 12);
    } else {
        std::size_t i = 0;
        std::size_t orig_len = key.length();
        key.reserve(key.length() + 12 % key.length());
        while (key.length() != 12) {
            key += key[i++ % orig_len];
        }
        return base64_encode(key.begin(), 12);
    }
}

std::string rotleft(std::string key) {
    std::string rotated{key.begin() + 1, key.end()};
    rotated += key[0];
    return rotated;
}

std::string encrypt(std::string message, std::string key) {
    std::size_t len = message.length();
    constexpr char chars[] = "abcdefghijklmnopqrstuvwxyz";
    std::size_t count_padding = 12 - message.length() % 12;
    std::string padded;
    padded.resize(count_padding);
    for (std::size_t i = 0; i < count_padding; i++) {
        padded[i] = chars[(message.length() + i) % 26];
    }
    message += std::move(padded);
    std::string message_len = std::to_string(len);
    count_padding = 12 - message_len.length() % 12;
    padded = "";
    padded.resize(count_padding);
    for (std::size_t i = 0; i < count_padding; i++) {
        padded[i] = chars[(message_len.length() + i) % 26];
    }
    std::reverse(padded.begin(), padded.end());
    message_len = std::move(padded) + std::move(message_len);
    message += std::move(message_len);
    key = setkeysize(std::move(key));
    std::string encoded = base64_encode(message.begin(), message.length());
    std::cout << "Original: " << message << "\nEncoded: " << encoded << '\n';
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
        for (std::size_t i = 0; i < 16; i++) {
            blocks.back()[i] = substitute(modified[i], key[i]);
        }

        key = rotleft(std::move(key));
        for (std::size_t i = 0; i < 16; i++) {
            key[i] = xor_sub2(key[i], combined);
        }
    }
    std::string encrypted = std::accumulate(blocks.begin(), blocks.end(), std::string{});
    std::cout << "Encrypted: " << encrypted << '\n';
    return base64_decode(encrypted);
}

std::string decrypt(std::string encrypted, std::string key) {
    key = setkeysize(std::move(key));
    std::string decrypted = base64_encode(encrypted.begin(), encrypted.length());
    std::vector<std::string> blocks;
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
        key = rotleft(std::move(key));
        for (std::size_t i = 0; i < 16; i++) {
            for (std::size_t j = 0; j < 16; j++) {
                key[i] = xor_sub(key[i], blocks.back()[j]);
            }
        }
    }

    decrypted = std::accumulate(blocks.begin(), blocks.end(), std::string{});
    std::cout << "Decrypted: " << decrypted << '\n';
    decrypted = base64_decode(decrypted);
    const char *length = &decrypted[decrypted.length() - 12];
    std::size_t counted = 0;
    while (counted < 12 && !std::isdigit(*(length + counted))) {
        counted++;
    }
    std::string_view orig_len{length + counted, 12 - counted};
    return decrypted.substr(0, std::atoi(orig_len.data()));
}

int main() {
    std::string message{};
    std::string key{};

    std::cout << "Message: ";
    std::getline(std::cin, message);

    std::cout << "Key: ";
    std::getline(std::cin, key);

    std::string encrypted = encrypt(message, key);
    std::string decrypted = decrypt(encrypted, key);
    std::cout << decrypted << '\n';
}