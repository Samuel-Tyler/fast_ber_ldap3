#include "autogen/rfc-4511.hpp"

#include <fstream>
#include <vector>
#include <iostream>

int encode_file(const std::string& filename)
{
    namespace ldap3 = fast_ber::Lightweight_Directory_Access_Protocol_V3;

    std::ofstream output(filename, std::ios::binary);
    if (!output.good())
    {
        std::cout << "Failed to open input file: " << filename << "\n";
        return -1;
    }

    ldap3::SearchRequest<> request = {
                            "ldapv3",
                            decltype(ldap3::SearchRequest<>::scope)::Values::wholeSubtree,
                            decltype(ldap3::SearchRequest<>::derefAliases)::Values::neverDerefAliases,
                            10,
                            20,
                            false,
                            ldap3::AttributeDescription<fast_ber::Id<fast_ber::Class::context_specific, 7>>("description"),
                            { "one", "two", "three" }
                        };

    ldap3::LDAPMessage<> message;
    message.messageID = 1;
    message.protocolOp = request;
    message.controls = fast_ber::empty;

    auto buffer = std::vector<uint8_t>(fast_ber::encoded_length(message));
    fast_ber::EncodeResult res = fast_ber::encode(absl::Span<uint8_t>(buffer), message);
    if (!res.success)
    {
        std::cout << "Failed to encode ldap3: " << filename << "\n";
        return -1;
    }

    output.write(reinterpret_cast<const char*>(buffer.data()), res.length);
    return 0;
}

int main(int argc, const char** argv)
{
    if (argc != 2)
    {
        std::cout << "Usage: ./ldap3_encoder [ldap3.ber]\n";
        return 1;
    }

    return encode_file(argv[1]);
}
