#include "autogen/rfc-4511.hpp"

#include <sstream>

using namespace fast_ber;
using namespace abbreviations;

namespace ldap3 = Lightweight_Directory_Access_Protocol_V3;

template <typename T>
void parse(ldap3::Filter<T> const& filter)
{
    if (fast_ber::holds_alternative<SetOf<ldap3::Filter<>, Id<ctx, 0>, StorageMode::dynamic>>(filter))
    {
        auto const& and_ = fast_ber::get<SetOf<ldap3::Filter<>, Id<ctx, 0>, StorageMode::dynamic>>(filter);
        std::cout << '(';
        bool first = true;
        for (auto const& f : and_)
        {
            if (!first)
                std::cout << " && ";
            parse(f);
            first = false;
        }
        std::cout << ')';

    }
    else if (fast_ber::holds_alternative<SetOf<ldap3::Filter<>, Id<ctx, 1>, StorageMode::dynamic>>(filter))
    {
        auto const& or_ = fast_ber::get<SetOf<ldap3::Filter<>, Id<ctx, 1>, StorageMode::dynamic>>(filter);
        std::cout << '(';
        bool first = true;
        for (auto const& f : or_)
        {
            if (!first)
                std::cout << " || ";
            parse(f);
            first = false;
        }
        std::cout << ')';
    }
    else if (fast_ber::holds_alternative<ldap3::Filter<Id<ctx, 2>>>(filter))
    {
        auto const& not_ = fast_ber::get<ldap3::Filter<Id<ctx, 2>>>(filter);
        std::cout << "!(";
        parse(not_);
        std::cout << ')';
    }
    else if (fast_ber::holds_alternative<ldap3::AttributeValueAssertion<Id<ctx, 3>>>(filter))
    {
        auto const& equalityMatch = fast_ber::get<ldap3::AttributeValueAssertion<Id<ctx, 3>>>(filter);
        std::cout << "got equalityMatch" << equalityMatch.attributeDesc << " " << equalityMatch.assertionValue << std::endl;
    }
    else if (fast_ber::holds_alternative<ldap3::SubstringFilter<Id<ctx, 4>>>(filter))
    {
        auto const& substrings = fast_ber::get<ldap3::SubstringFilter<Id<ctx, 4>>>(filter);
        std::cout << "substring type [" << substrings.type << "] ";
        for (auto const& s: substrings.substrings)
        {
            if (fast_ber::holds_alternative<ldap3::AssertionValue<Id<ctx, 0>>>(s))
            {
                std::cout << "[initial] [" << fast_ber::get<ldap3::AssertionValue<Id<ctx, 0>>>(s) << ']';
            }
            else if (fast_ber::holds_alternative<ldap3::AssertionValue<Id<ctx, 1>>>(s))
            {
                std::cout << "[any] [" << fast_ber::get<ldap3::AssertionValue<Id<ctx, 1>>>(s) << ']';
            }
            else if (fast_ber::holds_alternative<ldap3::AssertionValue<Id<ctx, 2>>>(s))
            {
                std::cout << "[final] [" << fast_ber::get<ldap3::AssertionValue<Id<ctx, 2>>>(s) << ']';
            }
        }
    }
    else if (fast_ber::holds_alternative<ldap3::AttributeValueAssertion<Id<ctx, 5>>>(filter))
    {
        auto const& greaterOrEqual = fast_ber::get<ldap3::AttributeValueAssertion<Id<ctx, 5>>>(filter);
        std::cout << "got greaterOrEqual" << greaterOrEqual.attributeDesc << " " << greaterOrEqual.assertionValue << std::endl;
    }
    else if (fast_ber::holds_alternative<ldap3::AttributeValueAssertion<Id<ctx, 6>>>(filter))
    {
        auto const& lessOrEqual = fast_ber::get<ldap3::AttributeValueAssertion<Id<ctx, 6>>>(filter);
        std::cout << "" << lessOrEqual.attributeDesc << " <= " << lessOrEqual.assertionValue;
    }
    else if (fast_ber::holds_alternative<ldap3::AttributeDescription<Id<ctx, 7>>>(filter))
    {
        auto const& present = fast_ber::get<ldap3::AttributeDescription<Id<ctx, 7>>>(filter);
        std::cout << "present " << present;
    }
    else if (fast_ber::holds_alternative<ldap3::AttributeValueAssertion<Id<ctx, 8>>>(filter))
    {
        auto const& approxMatch = fast_ber::get<ldap3::AttributeValueAssertion<Id<ctx, 8>>>(filter);
        std::cout << "got approxMatch" << approxMatch.attributeDesc << " " << approxMatch.assertionValue << std::endl;
    }
    else if (fast_ber::holds_alternative<ldap3::MatchingRuleAssertion<Id<ctx, 9>>>(filter))
    {
        auto const& extensibleMatch = fast_ber::get<ldap3::MatchingRuleAssertion<Id<ctx, 9>>>(filter);
        std::cout << "got extensibleMatch" << extensibleMatch << std::endl;
    }
}

void searchRequestHandle(const std::string &pdu_body) 
{
    ldap3::LDAPMessage<> msg;
    fast_ber::DecodeResult res = fast_ber::decode(absl::Span<const uint8_t>(reinterpret_cast<const uint8_t*>(pdu_body.data()), pdu_body.size()), msg);

    if (!res.success) {
        printf("failed to parse ldap3");

        return;
    }            

    std::cout << "Parsing packet of length "     << pdu_body.length() << ":" << std::endl;
    parse(fast_ber::get<ldap3::SearchRequest<>>(msg.protocolOp).filter);
    std::cout << std::endl;
}

#pragma GCC diagnostic ignored "-Wnarrowing"

int main()
{
    std::string pdu1 =  {
          0x30, 0x54, 0x02, 0x01, 0x09, 0x63, 0x4f, 0x04, 0x04, 0x63, 0x3d, 0x4b,
          0x5a, 0x0a, 0x01, 0x02, 0x0a, 0x01, 0x03, 0x02, 0x02, 0x03, 0xe8, 0x02,
          0x01, 0x00, 0x01, 0x01, 0x00, 0xa0, 0x32, 0x87, 0x0f, 0x75, 0x73, 0x65,
          0x72, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
          0xa6, 0x1f, 0x04, 0x0a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x69, 0x74, 0x79,
          0x54, 0x6f, 0x04, 0x11, 0x27, 0x32, 0x30, 0x32, 0x31, 0x30, 0x34, 0x32,
          0x36, 0x30, 0x33, 0x35, 0x39, 0x30, 0x32, 0x5a, 0x27, 0x30, 0x03, 0x04,
          0x01, 0x2a
        };

    std::string pdu2 = {
          0x30, 0x25, 0x02, 0x01, 0x02, 0x63, 0x20, 0x04, 0x00, 0x0a, 0x01, 0x02,
          0x0a, 0x01, 0x03, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00,
          0xa4, 0x0b, 0x04, 0x04, 0x6d, 0x61, 0x69, 0x6c, 0x30, 0x03, 0x82, 0x01,
          0x40, 0x30, 0x00
        };

    std::string pdu3 = {
          0x30, 0x25, 0x02, 0x01, 0x04, 0x63, 0x20, 0x04, 0x00, 0x0a, 0x01, 0x02,
          0x0a, 0x01, 0x03, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00,
          0xa4, 0x0b, 0x04, 0x04, 0x6d, 0x61, 0x69, 0x6c, 0x30, 0x03, 0x81, 0x01,
          0x40, 0x30, 0x00
        };
       
    searchRequestHandle(pdu1);
    searchRequestHandle(pdu2);
    searchRequestHandle(pdu3);

}
