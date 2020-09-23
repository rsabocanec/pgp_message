#ifndef PGP_MESSAGE_HPP
#define PGP_MESSAGE_HPP

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <rnp/rnp.h>


namespace pgp {
  constexpr int RNP_SUCCESS = 0;

  int ffi_encrypt(const uint8_t* in_buffer, size_t in_buffer_len, 
    const char* filename, const char* pubkey_filename, 
    uint8_t* out_buffer, size_t out_buffer_max_size, size_t& out_buffer_len)
  {
    int result = 1;

    // initialize FFI object 
    rnp_ffi_t ffi = nullptr;
    if (rnp_ffi_create(&ffi, "GPG", "GPG") != RNP_SUCCESS)
    {
      return result;
    }

    rnp_input_t input = nullptr;
    rnp_output_t output = nullptr;
    rnp_op_encrypt_t encrypt = nullptr;
    rnp_key_handle_t key = nullptr;
    uint8_t* buf = nullptr;
    size_t buf_len = 0;

    // load public keyring - we do not need secret for encryption 
    rnp_input_t keyfile = nullptr;
    if (rnp_input_from_path(&keyfile, pubkey_filename) != RNP_SUCCESS)
    {
      std::cerr << "Failed to open " << pubkey_filename << ". Did you run ./generate sample?\n";
      goto finish;
    }

    // we may use RNP_LOAD_SAVE_SECRET_KEYS | RNP_LOAD_SAVE_PUBLIC_KEYS as well 
    if (rnp_load_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_PUBLIC_KEYS) != RNP_SUCCESS)
    {
      std::cerr << "Failed to read " << pubkey_filename << '\n';
      goto finish;
    }
    rnp_input_destroy(keyfile);
    keyfile = nullptr;

    // create memory input and file output objects for the message and encrypted message 
    if (rnp_input_from_memory(&input, in_buffer, in_buffer_len, false) != RNP_SUCCESS)
    {
      std::cerr << "Failed to create input object\n";
      goto finish;
    }

    if (rnp_output_to_memory(&output, 0) != RNP_SUCCESS) {
      //if (rnp_output_to_path(&output, "encrypted.asc") != RNP_SUCCESS) {
      std::cerr << "Failed to create output object\n";
      goto finish;
    }

    // create encryption operation 
    if (rnp_op_encrypt_create(&encrypt, ffi, input, output) != RNP_SUCCESS) {
      std::cerr << "Failed to create encrypt operation\n";
      goto finish;
    }

    // setup encryption parameters 
    rnp_op_encrypt_set_armor(encrypt, true);
    rnp_op_encrypt_set_file_name(encrypt, filename);
    rnp_op_encrypt_set_file_mtime(encrypt, static_cast<uint32_t>(time(NULL)));
    rnp_op_encrypt_set_compression(encrypt, "ZIP", 6);
    rnp_op_encrypt_set_cipher(encrypt, RNP_ALGNAME_AES_256);
    rnp_op_encrypt_set_aead(encrypt, "None");

    // locate recipient's key and add it to the operation context. While we search by userid
    // (which is easier), you can search by keyid, fingerprint or grip. 
    if (rnp_locate_key(ffi, "userid", "rsa@key", &key) != RNP_SUCCESS) {
      std::cerr << "Failed to locate recipient key rsa@key.\n";
      goto finish;
    }

    if (rnp_op_encrypt_add_recipient(encrypt, key) != RNP_SUCCESS) {
      std::cerr << "Failed to add recipient\n";
      goto finish;
    }
    rnp_key_handle_destroy(key);
    key = nullptr;
#if 0
    // add encryption password as well 
    if (rnp_op_encrypt_add_password(
      encrypt, "encpassword", RNP_ALGNAME_SHA256, 0, RNP_ALGNAME_AES_256) != RNP_SUCCESS) {
      std::cerr << "Failed to add encryption password\n";
      goto finish;
    }
#endif
    // execute encryption operation 
    if (rnp_op_encrypt_execute(encrypt) != RNP_SUCCESS) {
      std::cerr << "Encryption failed\n";
      goto finish;
    }

    /* get the decrypted message from the output structure */
    if (rnp_output_memory_get_buf(output, &buf, &buf_len, false) != RNP_SUCCESS) {
      goto finish;
    }

    if (buf_len > out_buffer_max_size) {
      std::cerr << "Provided buffer not large enough, given " << out_buffer_max_size << ", needed " << buf_len << '\n';
      goto finish;
    }

    out_buffer_len = buf_len;
    ::memcpy(out_buffer, buf, out_buffer_len);
#if 0
    fprintf(stdout,
      "Encryption succeded. Encrypted message:\n%.*s\n",
      (int)buf_len,
      buf);
#endif
    result = 0;

  finish:
    rnp_op_encrypt_destroy(encrypt);
    rnp_input_destroy(keyfile);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);

    return result;
  }

  int ffi_encrypt_from_mem(const uint8_t* in_buffer, size_t in_buffer_len,
    const char* filename, const uint8_t* pubkey, size_t pubkey_len,
    uint8_t* out_buffer, size_t out_buffer_max_size, size_t& out_buffer_len)
  {
    int result = 1;

    // initialize FFI object 
    rnp_ffi_t ffi = nullptr;
    if (rnp_ffi_create(&ffi, "GPG", "GPG") != RNP_SUCCESS)
    {
      return result;
    }

    rnp_input_t input = nullptr;
    rnp_output_t output = nullptr;
    rnp_op_encrypt_t encrypt = nullptr;
    rnp_key_handle_t key = nullptr;
    uint8_t* buf = nullptr;
    size_t buf_len = 0;

    // load public keyring - we do not need secret for encryption 
    rnp_input_t keyfile = nullptr;

    if (rnp_input_from_memory(&keyfile, pubkey, pubkey_len, false) != RNP_SUCCESS)
    {
      std::cerr << "Failed to open public key from memory.\n";
      goto finish;
    }

    // we may use RNP_LOAD_SAVE_SECRET_KEYS | RNP_LOAD_SAVE_PUBLIC_KEYS as well 
    if (rnp_load_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_PUBLIC_KEYS) != RNP_SUCCESS)
    {
      std::cerr << "Failed to read public key from memory\n";
      goto finish;
    }
    rnp_input_destroy(keyfile);
    keyfile = nullptr;

    // create memory input and file output objects for the message and encrypted message 
    if (rnp_input_from_memory(&input, in_buffer, in_buffer_len, false) != RNP_SUCCESS)
    {
      std::cerr << "Failed to create input object\n";
      goto finish;
    }

    if (rnp_output_to_memory(&output, 0) != RNP_SUCCESS) {
      //if (rnp_output_to_path(&output, "encrypted.asc") != RNP_SUCCESS) {
      std::cerr << "Failed to create output object\n";
      goto finish;
    }

    // create encryption operation 
    if (rnp_op_encrypt_create(&encrypt, ffi, input, output) != RNP_SUCCESS) {
      std::cerr << "Failed to create encrypt operation\n";
      goto finish;
    }

    // setup encryption parameters 
    rnp_op_encrypt_set_armor(encrypt, true);
    rnp_op_encrypt_set_file_name(encrypt, filename);
    rnp_op_encrypt_set_file_mtime(encrypt, static_cast<uint32_t>(time(nullptr)));
    rnp_op_encrypt_set_compression(encrypt, "ZIP", 6);
    rnp_op_encrypt_set_cipher(encrypt, RNP_ALGNAME_AES_256);
    rnp_op_encrypt_set_aead(encrypt, "None");

    // locate recipient's key and add it to the operation context. While we search by userid
    // (which is easier), you can search by keyid, fingerprint or grip. 
    if (rnp_locate_key(ffi, "userid", "rsa@key", &key) != RNP_SUCCESS) {
      std::cerr << "Failed to locate recipient key rsa@key.\n";
      goto finish;
    }

    if (rnp_op_encrypt_add_recipient(encrypt, key) != RNP_SUCCESS) {
      std::cerr << "Failed to add recipient\n";
      goto finish;
    }
    rnp_key_handle_destroy(key);
    key = nullptr;
#if 0
    // add encryption password as well 
    if (rnp_op_encrypt_add_password(
      encrypt, "encpassword", RNP_ALGNAME_SHA256, 0, RNP_ALGNAME_AES_256) != RNP_SUCCESS) {
      std::cerr << "Failed to add encryption password\n";
      goto finish;
    }
#endif
    // execute encryption operation 
    if (rnp_op_encrypt_execute(encrypt) != RNP_SUCCESS) {
      std::cerr << "Encryption failed\n";
      goto finish;
    }

    /* get the decrypted message from the output structure */
    if (rnp_output_memory_get_buf(output, &buf, &buf_len, false) != RNP_SUCCESS) {
      goto finish;
    }

    if (buf_len > out_buffer_max_size) {
      std::cerr << "Provided buffer not large enough, given " << out_buffer_max_size << ", needed " << buf_len << '\n';
      goto finish;
    }

    out_buffer_len = buf_len;
    ::memcpy(out_buffer, buf, out_buffer_len);
#if 0
    fprintf(stdout,
      "Encryption succeded. Encrypted message:\n%.*s\n",
      (int)buf_len,
      buf);
#endif
    result = 0;

  finish:
    rnp_op_encrypt_destroy(encrypt);
    rnp_input_destroy(keyfile);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);

    return result;
  }

  // sample pass provider implementation, which always return 'password' for key decryption and
  // 'encpassword' when password is needed for file decryption. You may ask for password via
  // stdin, or choose password based on key properties, whatever else 
  bool example_pass_provider(rnp_ffi_t ffi,
    void* app_ctx,
    rnp_key_handle_t key,
    const char* pgp_context,
    char buf[],
    size_t buf_len)
  {
    if (!strcmp(pgp_context, "decrypt (symmetric)")) {
      strncpy(buf, "encpassword", buf_len);
      return true;
    }
    if (!strcmp(pgp_context, "decrypt")) {
      strncpy(buf, "password", buf_len);
      return true;
    }

    return false;
  }

  // basic pass provider implementation, which always return 'password' for key protection.
  // You may ask for password via stdin, or choose password based on key properties, whatever else
  static bool  example_protect_pass_provider(rnp_ffi_t        ffi,
      void* app_ctx,
      rnp_key_handle_t key,
      const char* pgp_context,
      char             buf[],
      size_t           buf_len)
  {
    if (strcmp(pgp_context, "protect")) {
      return false;
    }

    strncpy(buf, "password", buf_len);
    return true;
  }


  int ffi_decrypt(const uint8_t* in_buffer, size_t in_buffer_len, 
    bool usekeys, const char *securekey_filename, 
    uint8_t* out_buffer, size_t out_buffer_max_size, size_t& out_buffer_len)
  {
    // initialize FFI object 
    rnp_ffi_t ffi = nullptr;

    int result = rnp_ffi_create(&ffi, "GPG", "GPG");
    if (result != RNP_SUCCESS) {
      return result;
    }

    rnp_input_t keyfile = nullptr;
    rnp_input_t input = nullptr;
    rnp_output_t output = nullptr;
    uint8_t* buf = nullptr;
    size_t buf_len = 0;

    // check whether we want to use key or password for decryption 
    if (usekeys) {
      // load secret keyring, as it is required for public-key decryption. However, you may
      // need to load public keyring as well to validate key's signatures. 
      result = rnp_input_from_path(&keyfile, securekey_filename);
      if (result != RNP_SUCCESS) {
        std::cerr << "Failed to open " << securekey_filename << ". Did you run ./generate sample?\n";
        goto finish;
      }

      // we may use RNP_LOAD_SAVE_SECRET_KEYS | RNP_LOAD_SAVE_PUBLIC_KEYS as well
      result = rnp_load_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_SECRET_KEYS);
      if (result != RNP_SUCCESS) {
        std::cerr << "Failed to read " << securekey_filename << '\n';
        goto finish;
      }

      rnp_input_destroy(keyfile);
      keyfile = nullptr;
    }

    // set the password provider 
    rnp_ffi_set_pass_provider(ffi, example_pass_provider, nullptr);

    // create file input and memory output objects for the encrypted message and decrypted
    // message 
    result = rnp_input_from_memory(&input, in_buffer, in_buffer_len, false);
    if (result != RNP_SUCCESS) {
      //if (rnp_input_from_path(&input, "encrypted.asc") != RNP_SUCCESS) {
      std::cerr << "Failed to create input object\n";
      goto finish;
    }

    result = rnp_output_to_memory(&output, 0);
    if (result != RNP_SUCCESS) {
      std::cerr << "Failed to create output object\n";
      goto finish;
    }

    result = rnp_decrypt(ffi, input, output);
    if (result != RNP_SUCCESS) {
      std::cerr << "Public-key decryption failed\n";
      goto finish;
    }

    // get the decrypted message from the output structure 
    result = rnp_output_memory_get_buf(output, &buf, &buf_len, false);
    if (result != RNP_SUCCESS) {
      goto finish;
    }

    if (buf_len > out_buffer_max_size) {
      std::cerr << "Provided buffer not large enough, given " << out_buffer_max_size << ", needed " << buf_len << '\n';
      goto finish;
    }

    out_buffer_len = buf_len;
    ::memcpy(out_buffer, buf, out_buffer_len);
#if 0
    fprintf(stdout,
      "Decrypted message (%s):\n%.*s\n",
      usekeys ? "with key" : "with password",
      (int)buf_len,
      buf);
#endif
    result = 0;
  finish:
    rnp_input_destroy(keyfile);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_ffi_destroy(ffi);

    return result;
  }


  int ffi_decrypt_from_mem(const uint8_t* in_buffer, size_t in_buffer_len, bool usekeys, 
    const uint8_t* securekey, size_t securekey_len, 
    uint8_t* out_buffer, size_t out_buffer_max_size, size_t& out_buffer_len)
  {
    // initialize FFI object 
    rnp_ffi_t ffi = nullptr;

    int result = rnp_ffi_create(&ffi, "GPG", "GPG");
    if (result != RNP_SUCCESS) {
      return result;
    }

    rnp_input_t keyfile = nullptr;
    rnp_input_t input = nullptr;
    rnp_output_t output = nullptr;
    uint8_t* buf = nullptr;
    size_t buf_len = 0;

    // check whether we want to use key or password for decryption 
    if (usekeys) {
      // load secret keyring, as it is required for public-key decryption. However, you may
      // need to load public keyring as well to validate key's signatures. 
      result = rnp_input_from_memory(&keyfile, securekey, securekey_len, false);
      if (result != RNP_SUCCESS) {
        std::cerr << "Failed to open secure key from memory.\n";
        goto finish;
      }

      // we may use RNP_LOAD_SAVE_SECRET_KEYS | RNP_LOAD_SAVE_PUBLIC_KEYS as well
      result = rnp_load_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_SECRET_KEYS);
      if (result != RNP_SUCCESS) {
        std::cerr << "Failed to read secure key from memory.\n";
        goto finish;
      }

      rnp_input_destroy(keyfile);
      keyfile = nullptr;
    }

    // set the password provider 
    rnp_ffi_set_pass_provider(ffi, example_pass_provider, nullptr);

    // create file input and memory output objects for the encrypted message and decrypted
    // message 
    result = rnp_input_from_memory(&input, in_buffer, in_buffer_len, false);
    if (result != RNP_SUCCESS) {
      //if (rnp_input_from_path(&input, "encrypted.asc") != RNP_SUCCESS) {
      std::cerr << "Failed to create input object\n";
      goto finish;
    }

    result = rnp_output_to_memory(&output, 0);
    if (result != RNP_SUCCESS) {
      std::cerr << "Failed to create output object\n";
      goto finish;
    }

    result = rnp_decrypt(ffi, input, output);
    if (result != RNP_SUCCESS) {
      std::cerr << "Public-key decryption failed\n";
      goto finish;
    }

    // get the decrypted message from the output structure 
    result = rnp_output_memory_get_buf(output, &buf, &buf_len, false);
    if (result != RNP_SUCCESS) {
      goto finish;
    }

    if (buf_len > out_buffer_max_size) {
      std::cerr << "Provided buffer not large enough, given " << out_buffer_max_size << ", needed " << buf_len << '\n';
      goto finish;
    }

    out_buffer_len = buf_len;
    ::memcpy(out_buffer, buf, out_buffer_len);
#if 0
    fprintf(stdout,
      "Decrypted message (%s):\n%.*s\n",
      usekeys ? "with key" : "with password",
      (int)buf_len,
      buf);
#endif
    result = 0;
  finish:
    rnp_input_destroy(keyfile);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_ffi_destroy(ffi);

    return result;
  }

  // RSA key JSON description. 31536000 = 1 year expiration, 15768000 = half year */
  const char* RSA_KEY_DESC = "{\
    'primary': {\
        'type': 'RSA',\
        'length': 2048,\
        'userid': 'rsa@key',\
        'expiration': 31536000,\
        'usage': ['sign'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    },\
    'sub': {\
        'type': 'RSA',\
        'length': 2048,\
        'expiration': 15768000,\
        'usage': ['encrypt'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    }\
}";

  const char* CURVE_25519_KEY_DESC = "{\
    'primary': {\
        'type': 'EDDSA',\
        'userid': '25519@key',\
        'expiration': 0,\
        'usage': ['sign'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    },\
    'sub': {\
        'type': 'ECDH',\
        'curve': 'Curve25519',\
        'expiration': 15768000,\
        'usage': ['encrypt'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    }\
}";

  // this example function generates RSA/RSA and Eddsa/X25519 keypairs 
  int ffi_generate_keys(uint8_t* pubkey_buffer, size_t pubkey_buffer_max_size, size_t& pubkey_len,
    uint8_t* securekey_buffer, size_t securekey_buffer_max_size, size_t& securekey_len)
  {
    rnp_ffi_t ffi = nullptr;

    // initialize FFI object 
    int result = rnp_ffi_create(&ffi, "GPG", "GPG");
    if (result != RNP_SUCCESS) {
      return result;
    }

    rnp_output_t keyfile = nullptr;
    char* key_grips = nullptr;

    uint8_t* buf = nullptr;
    size_t buf_len = 0;

    // set password provider 
    if (rnp_ffi_set_pass_provider(ffi, example_protect_pass_provider, nullptr)) {
      goto finish;
    }

    // generate EDDSA/X25519 keypair 
    result = rnp_generate_key_json(ffi, CURVE_25519_KEY_DESC, &key_grips);
    if (result != RNP_SUCCESS) {
      std::cerr << "Failed to generate eddsa key\n";
      goto finish;
    }

    std::cout << "Generated 25519 key/subkey:\n" << key_grips << '\n';
    // destroying key_grips buffer is our obligation 
    rnp_buffer_destroy(key_grips);
    key_grips = nullptr;

    // generate RSA keypair 
    result = rnp_generate_key_json(ffi, RSA_KEY_DESC, &key_grips);
    if (result != RNP_SUCCESS) {
      std::cerr << "Failed to generate rsa key\n";
      goto finish;
    }

    std::cout << "Generated RSA key/subkey:\n" << key_grips << '\n';
    rnp_buffer_destroy(key_grips);
    key_grips = nullptr;

    // create file output object and save public keyring with generated keys, overwriting
    // previous file if any. You may use rnp_output_to_memory() here as well. 
    result = rnp_output_to_memory(&keyfile, 0);
    //result = rnp_output_to_path(&keyfile, "pubring.pgp");
    if (result != RNP_SUCCESS) {
      std::cerr << "Failed to initialize pubring.pgp writing\n";
      goto finish;
    }

    result = rnp_save_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_PUBLIC_KEYS);
    if (result != RNP_SUCCESS) {
      std::cerr << "Failed to save pubring\n";
      goto finish;
    }

    // get the pubkey from the output structure 
    result = rnp_output_memory_get_buf(keyfile, &buf, &buf_len, false);
    if (result != RNP_SUCCESS) {
      goto finish;
    }

    if (buf_len > pubkey_buffer_max_size) {
      std::cerr << "Provided pubkey buffer not large enough, given " << pubkey_buffer_max_size << ", needed " << buf_len << '\n';
      goto finish;
    }

    pubkey_len = buf_len;
    ::memcpy(pubkey_buffer, buf, pubkey_len);

    rnp_output_destroy(keyfile);
    keyfile = nullptr;

    // create file output object and save secret keyring with generated keys 
    result = rnp_output_to_memory(&keyfile, 0);
    //result = rnp_output_to_path(&keyfile, "secring.pgp");
    if (result != RNP_SUCCESS) {
      std::cerr << "Failed to initialize secring.pgp writing\n";
      goto finish;
    }

    result = rnp_save_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_SECRET_KEYS);
    if (result != RNP_SUCCESS) {
      std::cerr << "Failed to save secring\n";
      goto finish;
    }

    // get the securekey from the output structure 
    result = rnp_output_memory_get_buf(keyfile, &buf, &buf_len, false);
    if (result != RNP_SUCCESS) {
      goto finish;
    }

    if (buf_len > securekey_buffer_max_size) {
      std::cerr << "Provided pubkey buffer not large enough, given " << securekey_buffer_max_size << ", needed " << buf_len << '\n';
      goto finish;
    }

    securekey_len = buf_len;
    ::memcpy(securekey_buffer, buf, securekey_len);

    rnp_output_destroy(keyfile);
    keyfile = nullptr;

    result = 0;
  finish:
    rnp_buffer_destroy(key_grips);
    rnp_output_destroy(keyfile);
    rnp_ffi_destroy(ffi);

    return result;
  }
}
#endif // PGP_MESSAGE_HPP
