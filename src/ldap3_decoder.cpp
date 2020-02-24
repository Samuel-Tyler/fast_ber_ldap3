#include "autogen/rfc-4511.hpp"

#include <fstream>
#include <vector>
#include <iostream>

int decode_file(const std::string& filename)
{
    std::ifstream input(filename, std::ios::binary);
    if (!input.good())
    {
        std::cout << "Failed to open input file: " << filename << "\n";
        return -1;
    }
    const auto buffer = std::vector<uint8_t>{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};

    fast_ber::Lightweight_Directory_Access_Protocol_V3::LDAPMessage<> message;
    fast_ber::DecodeResult res = fast_ber::decode(absl::Span<const uint8_t>(buffer.data(), buffer.size()), message);
    if (!res.success)
    {
        std::cout << "Failed to parse ldap3: " << filename << "\n";
        return 1;
    }

    std::cout << message << std::endl;
    return 0;
}

int main(int argc, const char** argv)
{
    if (argc != 2)
    {
        std::cout << "Usage: ./ldap3_decoder [ldap3.ber]\n";
        return 1;
    }

    return decode_file(argv[1]);
}
