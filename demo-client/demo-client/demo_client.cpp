//
// demo_client.cpp
// ~~~~~~~~~~~~~~~
//

#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00

#define _CRT_SECURE_NO_WARNINGS

#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cassert>
#include <algorithm>
#include <fstream>
#include <iostream>

#include <boost/asio.hpp>

#include "../../pgp_message.hpp"

#pragma comment(lib, "librnp-0.lib")
#pragma comment(lib, "botan.lib")
#pragma comment(lib, "json-c-static.lib")
#pragma comment(lib, "libbz2.lib")
#pragma comment(lib, "zlibstatic.lib")

using boost::asio::ip::tcp;

int main(int argc, char* argv[])
{
  try
  {
    if (argc != 3)
    {
      std::cerr << "Usage: demo-client <host> <port>\n";
      return 1;
    }

    const char* pubkey_filename = "../../pubring.pgp";

    boost::asio::io_context io_context;

    tcp::socket s(io_context);
    tcp::resolver resolver(io_context);
    boost::asio::connect(s, resolver.resolve(argv[1], argv[2]));

    int result = pgp::RNP_SUCCESS;

    // Send the generated public key
    constexpr size_t key_length = 4096;
    std::array<uint8_t, key_length> pubkey_buffer;
    std::array<uint8_t, key_length> securekey_buffer;

    size_t pubkey_len = 0;
    size_t securekey_len = 0;

    result = pgp::ffi_generate_keys(pubkey_buffer.data(), key_length, pubkey_len, securekey_buffer.data(), key_length, securekey_len);
    if (result != pgp::RNP_SUCCESS)
    {
      std::cerr << "Key generation failed with result " << result << '\n';
      return result;
    }

    constexpr size_t max_length = 8192;
    std::array<uint8_t, max_length> out_buffer;
    std::array<uint8_t, max_length> in_buffer;

    size_t buffer_len = 0;
    result = pgp::ffi_encrypt(pubkey_buffer.data(), pubkey_len, "pubkey.pgp", pubkey_filename, out_buffer.data(), max_length, buffer_len);

    boost::asio::write(s, boost::asio::buffer(out_buffer, buffer_len));

    boost::system::error_code error;
    auto reply_length = s.read_some(boost::asio::buffer(in_buffer), error);
    if (error)
    {
      std::cerr << error.message() << std::endl;
    }
    else
    {
      if (pgp::ffi_decrypt_from_mem(in_buffer.data(), reply_length, true, securekey_buffer.data(), securekey_len, in_buffer.data(), max_length, reply_length) == pgp::RNP_SUCCESS)
      {
        std::cout.write(reinterpret_cast<char*>(in_buffer.data()), reply_length);
      }
      else
      {
        std::cout << "Decrypt error!";
      }

      std::cout << std::endl;
    }

    std::cout << "Enter name of the file to be uploaded: ";
    std::array<char, MAX_PATH + 1> filename;
    std::cin.getline(filename.data(), MAX_PATH);
    std::basic_ifstream<uint8_t> ifs(filename.data(), std::ios::binary | std::ios::ate);
    //std::ifstream ifs(filename.data(), std::ios::binary | std::ios::ate);

    while (!ifs.is_open())
    {
      std::cerr << "Failed to open " << filename.data() << "\n\nEnter name of the file to be uploaded: ";
      std::cin.getline(filename.data(), MAX_PATH);
      ifs.open(filename.data(), std::ios::binary | std::ios::ate);
    }

    // First, send the filename
    result = pgp::ffi_encrypt(reinterpret_cast<uint8_t*>(filename.data()), ::strlen(filename.data()), filename.data(), pubkey_filename, out_buffer.data(), max_length, buffer_len);
    if (result != pgp::RNP_SUCCESS)
    {
      std::cerr << "Encryption failed with result " << result << '\n';
      return result;
    }

    boost::asio::write(s, boost::asio::buffer(out_buffer, buffer_len));

    size_t remained_size = static_cast<size_t>(ifs.tellg());
    ifs.seekg(std::ios_base::beg);

    reply_length = s.read_some(boost::asio::buffer(in_buffer), error);
    if (error)
    {
      std::cerr << error.message() << std::endl;
    }
    else
    {
      if (pgp::ffi_decrypt_from_mem(in_buffer.data(), reply_length, true, securekey_buffer.data(), securekey_len, in_buffer.data(), max_length, reply_length) == pgp::RNP_SUCCESS)
      {
        std::cout.write(reinterpret_cast<char*>(in_buffer.data()), reply_length);
      }
      else
      {
        std::cout << "Decrypt error!";
      }

      std::cout << std::endl;
    }

    size_t sent_size = 0;

    while (remained_size > 0)
    {
      auto size = std::min(max_length / 4, remained_size);

      ifs.read(out_buffer.data(), size);

      result = pgp::ffi_encrypt(out_buffer.data(), size, filename.data(), pubkey_filename, out_buffer.data(), max_length, buffer_len);
      if (result != pgp::RNP_SUCCESS)
      {
        std::cerr << "Encryption failed with result " << result << '\n';
        return result;
      }

      size_t written_size = boost::asio::write(s, boost::asio::buffer(out_buffer, buffer_len));
      assert(written_size == buffer_len);
      remained_size -= size;
      sent_size += size;
      std::cout << sent_size << " bytes sent\n";

      reply_length = s.read_some(boost::asio::buffer(in_buffer), error);
      if (error)
      {
        std::cerr << error.message() << std::endl;
      }
      else
      {
        if (pgp::ffi_decrypt_from_mem(in_buffer.data(), reply_length, true, securekey_buffer.data(), securekey_len, in_buffer.data(), max_length, reply_length) == pgp::RNP_SUCCESS)
        {
          std::cout.write(reinterpret_cast<char*>(in_buffer.data()), reply_length);
        }
        else
        {
          std::cout << "Decrypt error!";
        }

        std::cout << std::endl;
      }
    }

    std::cout << "\nFile transfer has finished successfully!" << std::endl;
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}
