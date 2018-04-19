#include <iostream>

#include "openssl.hpp"

int main(int argc, char **argv)
{
    try
    {
        using namespace openssl;

        init initssl;
        bio bio_stdout = make_stdout_bio();

        ec_key key = ec_key::generate();

        key.write_priv_key_as_pem(bio_stdout);
        std::cout << std::endl;

        std::cout << "Private key (hex): " << std::endl;
        print_hex(std::cout, key.private_key());
        std::cout << std::endl << std::endl;

        key.write_pub_key_as_pem(bio_stdout);
        std::cout << std::endl;

        std::cout << "Public key (hex): " << std::endl;
        print_hex(std::cout, key.public_key());
        std::cout << std::endl << std::endl;

        key.write_priv_key_as_pem(make_file_bio("test.pem"));
        std::cout << "Private key was written to test.pem" << std::endl;

        key.write_pub_key_as_pem(make_file_bio("test.pub"));
        std::cout << "Public key was written to test.pub" << std::endl << std::endl;

        address a = key.generate_address();
        std::cout << "Address: ";
        print_hex(std::cout, a);
        std::cout << std::endl;
    }
    catch(const std::exception& e)
    {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
