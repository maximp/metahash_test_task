#include "openssl.hpp"

#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace openssl
{
    error::error()
        :   std::runtime_error(ERR_error_string(ERR_get_error(), nullptr))
    {}

    init::init()
    {
        // these function calls initialize openssl for correct work
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();
        SSL_load_error_strings();

        // initialize SSL library and register algorithms
        SSL_library_init();
    }

    init::~init()
    {
        ERR_free_strings();
    }

    ec_key ec_key::generate()
    {
        handle_type h(EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free);
        if(!h)
            throw error();

        EC_KEY_set_asn1_flag(h.get(), OPENSSL_EC_NAMED_CURVE);

        if( EC_KEY_generate_key(h.get()) < 0 )
            throw error();

        ec_key r;
        r._k = std::move(h);

        return r;
    }

    ec_key::ec_key()
        :   _k(nullptr, EC_KEY_free)
    {}

    buffer ec_key::public_key() const
    {
        unsigned char* out = nullptr;
        const int len = i2d_EC_PUBKEY(handle(), &out);
        if(!len)
            throw std::runtime_error("Public key is missed for EC key");

        buffer r(out, out + len);

        OPENSSL_free(out);

        return r;
    }

    buffer ec_key::private_key() const
    {
        unsigned char* out = nullptr;
        const int len = i2d_ECPrivateKey(handle(), &out);
        if(!len)
            throw std::runtime_error("Private key is missed for EC key");

        buffer r(out, out + len);

        OPENSSL_free(out);

        return r;
    }

    EC_KEY* ec_key::handle() const
    {
        return _k.get();
    }

    void ec_key::write_priv_key_as_pem(const bio& b) const
    {
        int success = PEM_write_bio_ECPrivateKey(b.get(), handle(), nullptr, nullptr, 0, nullptr, nullptr);
        if(!success)
            throw error();
    }

    void ec_key::write_pub_key_as_pem(const bio& b) const
    {
        int success = PEM_write_bio_EC_PUBKEY(b.get(), handle());
        if(!success)
            throw error();
    }

    address ec_key::generate_address() const
    {
        buffer pubkey = public_key();

        enum { MAGIC = 65 };

        unsigned char* start = &pubkey[0] + pubkey.size() - MAGIC;

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(start, MAGIC, hash);

        address result;
        RIPEMD160(hash, SHA256_DIGEST_LENGTH, &result[1]);
        result[0] = 0;

        SHA256(&result[0], RIPEMD160_DIGEST_LENGTH + 1, hash);

        unsigned char hash2[SHA256_DIGEST_LENGTH];
        SHA256(hash, SHA256_DIGEST_LENGTH, hash2);

        result[RIPEMD160_DIGEST_LENGTH + 1] = hash2[0];
        result[RIPEMD160_DIGEST_LENGTH + 2] = hash2[1];
        result[RIPEMD160_DIGEST_LENGTH + 3] = hash2[2];
        result[RIPEMD160_DIGEST_LENGTH + 4] = hash2[3];

        return result;
    }

    bio make_file_bio(const char* filename)
    {
        bio b(BIO_new(BIO_s_file()), BIO_free_all);

        if (BIO_write_filename(b.get(), (void*)filename) <= 0)
            throw error();

        return b;
    }

    bio make_stdout_bio()
    {
        return { BIO_new_fp(stdout, BIO_NOCLOSE), BIO_free_all };
    }
}

