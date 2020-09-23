//
// chat_server.cpp
// ~~~~~~~~~~~~~~~
//

#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00

#define _CRT_SECURE_NO_WARNINGS

#include <cstdlib>
#include <memory>
#include <utility>
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

namespace pgp {
  namespace demo {
    constexpr const char* securkey_filename = "../../secring.pgp";

    class session
      : public std::enable_shared_from_this<session>
    {
    public:
      explicit session(tcp::socket socket)
        : socket_(std::move(socket))
      {
      }

      void start()
      {
        // First, get the client's public key
        boost::system::error_code blocking_error;
        size_t length = socket_.read_some(boost::asio::buffer(data_), blocking_error);

        if (blocking_error)
        {
          std::cerr << blocking_error.message() << std::endl;
          return;
        }
        else
        {
          int result = pgp::ffi_decrypt(data_.data(), length, true, securkey_filename, pubkey_.data(), max_length, pubkey_len_);

          if (result == pgp::RNP_SUCCESS)
          {
            // Encrypt it and respond with OK
            result = pgp::ffi_encrypt_from_mem(reinterpret_cast<const uint8_t*>("OK"), 2, "", pubkey_.data(), pubkey_len_, data_.data(), max_length, length);
            if (result == pgp::RNP_SUCCESS)
            {
              socket_.write_some(boost::asio::buffer(data_, length), blocking_error);
            }
            else
            {
              std::cerr << "Encrypt error: " << result << '\n';
              return;
            }
          }
          else
          {
            std::cerr << "Decrypt error: " << result << '\n';
            return;
          }
        }

        // Then, get the filename
        auto self(shared_from_this());
        socket_.async_read_some(boost::asio::buffer(data_, max_length),
          [this, self](boost::system::error_code ec, std::size_t length)
          {
            if (!ec)
            {
              std::array<uint8_t, MAX_PATH> filename_buffer;
              size_t filename_buffer_len = 0;
              int result = pgp::ffi_decrypt(data_.data(), length, true, securkey_filename, filename_buffer.data(), max_length, filename_buffer_len);

              if (result == pgp::RNP_SUCCESS)
              {
                if (filename_buffer_len > 0)
                {
                  const char* filename = reinterpret_cast<char *>(filename_buffer.data());
                  ofs_.open(filename, std::ios::binary);
                  if (ofs_.is_open())
                  {
                    do_write_ok();
                  }
                  else
                  {
                    std::string error("Failed to open ");
                    error += filename;
                    error += " for writing";
                    std::cerr << error << '\n';
                    do_write_error(error.c_str(), error.length());
                  }
                }
                else
                {
                  std::string error("Expected filename, got empty string!");
                  std::cerr << error << '\n';
                  do_write_error(error.c_str(), error.length());
                }
              }
              else
              {
                std::string error("Decrypt error: ");
                error += std::to_string(result);
                do_write_error(error.c_str(), error.length());
              }
            }
            else
            {
              const std::string& error = ec.message();
              do_write_error(error.c_str(), error.length());
            }
          });
      }

    private:
      void do_read()
      {
        auto self(shared_from_this());
        socket_.async_read_some(boost::asio::buffer(data_, max_length),
          [this, self](boost::system::error_code ec, std::size_t length)
          {
            if (!ec)
            {
              size_t encrypted_data_len = 0;
              int result = pgp::ffi_decrypt(data_.data(), length, true, securkey_filename, data_.data(), max_length, encrypted_data_len);
              if (result == pgp::RNP_SUCCESS)
              {
                if (encrypted_data_len > 0)
                {
                  ofs_.write(data_.data(), encrypted_data_len);
                }

                do_write_ok();
              }
              else
              {
                std::string error("Decrypt error: ");
                error += std::to_string(result);
                do_write_error(error.c_str(), error.length());
              }
            }
            else
            {
              const std::string& error = ec.message();
              do_write_error(error.c_str(), error.length());
            }
          });
      }

      void do_write_ok()
      {
        auto self(shared_from_this());
        size_t length = 0;
        int result = pgp::ffi_encrypt_from_mem(reinterpret_cast<const uint8_t*>("OK"), 2, "", pubkey_.data(), pubkey_len_, data_.data(), max_length, length);
        if (result == pgp::RNP_SUCCESS)
        {
          boost::asio::async_write(socket_, boost::asio::buffer(data_, length),
            [this, self](boost::system::error_code ec, std::size_t /*length*/)
            {
              if (!ec)
              {
                do_read();
              }
            });
        }
        else
        {
          std::cerr << "Encrypt error: " << result << '\n';
        }
      }

      void do_write_error(const char *error, size_t length)
      {
        auto self(shared_from_this());
        int result = pgp::ffi_encrypt_from_mem(reinterpret_cast<const uint8_t*>(error), length, "", pubkey_.data(), pubkey_len_, data_.data(), max_length, length);
        boost::asio::async_write(socket_, boost::asio::buffer(data_, length),
          [this, self](boost::system::error_code ec, std::size_t /*length*/)
          {
            if (!ec)
            {
              do_read();
            }
          });
      }

      tcp::socket socket_;
      enum { max_length = 4096 };
      std::array<uint8_t, max_length> data_;
      std::array<uint8_t, max_length> pubkey_;
      size_t pubkey_len_ = 0;
      std::basic_ofstream<uint8_t> ofs_;
    };

    class server
    {
    public:
      server(boost::asio::io_context& io_context, short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
      {
        do_accept();
      }

    private:
      void do_accept()
      {
        acceptor_.async_accept(
          [this](boost::system::error_code ec, tcp::socket socket)
          {
            if (!ec)
            {
              std::make_shared<session>(std::move(socket))->start();
            }

            do_accept();
          });
      }

      tcp::acceptor acceptor_;
    };
  }
}

int main(int argc, char* argv[])
{
  try
  {
    if (argc != 2)
    {
      std::cerr << "Usage: demo-server <port>\n";
      return 1;
    }

    boost::asio::io_context io_context;

    pgp::demo::server s(io_context, std::atoi(argv[1]));

    io_context.run();
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}
