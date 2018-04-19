#pragma once

#include <array>
#include <iomanip>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <vector>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ripemd.h>

namespace openssl
{
    using bio = std::unique_ptr<BIO, void (*)(BIO*)>;
    using address = std::array<unsigned char, RIPEMD160_DIGEST_LENGTH + 5>;
    using buffer = std::vector<unsigned char>;

    class error : public std::runtime_error
    {
    public:
        error();
    };

    class init
    {
    private:
        init(const init& rhs);
        init& operator=(const init& rhs);

    public:
        init();
        ~init();
    };

    class ec_key
    {
    public:
        static ec_key generate();

        ec_key();

        buffer public_key() const;
        buffer private_key() const;

        EC_KEY* handle() const;

        void write_priv_key_as_pem(const bio& b) const;
        void write_pub_key_as_pem(const bio& b) const;

        address generate_address() const;

    private:
        using handle_type = std::unique_ptr<EC_KEY, void (*)(EC_KEY*)>;

        handle_type _k;
    };

    bio make_file_bio(const char* filename);
    bio make_stdout_bio();

    template<typename _Type>
    inline std::ostream& print_hex(std::ostream& os, const _Type& a)
    {
        const auto w = os.width();
        const auto f = os.fill();

        os << std::hex;
        for(const int b : a)
            os << std::setfill('0') << std::setw(2) << (int)b;

        os.width(w);
        os.fill(f);

        return os << std::dec;
    }
}

