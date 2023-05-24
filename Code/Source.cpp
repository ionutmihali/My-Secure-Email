#define _CRT_SECURE_NO_WARNINGS

#pragma warning(disable : 4996)

#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/applink.c>

#include <string.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <stdexcept>
#include <stdlib.h>

typedef struct EMAIL {
    ASN1_PRINTABLESTRING* From;
    ASN1_PRINTABLESTRING* To;
    ASN1_PRINTABLESTRING* Title;
    ASN1_PRINTABLESTRING* Body;
    ASN1_OCTET_STRING* Signature;
    ASN1_UTCTIME* Time;
    ASN1_PRINTABLESTRING* Encoded_key;
} EMAIL;

ASN1_SEQUENCE(EMAIL) = {
    ASN1_SIMPLE(EMAIL, From, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(EMAIL, To, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(EMAIL, Title, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(EMAIL, Body, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(EMAIL, Signature, ASN1_OCTET_STRING),
    ASN1_SIMPLE(EMAIL, Time, ASN1_UTCTIME),
    ASN1_SIMPLE(EMAIL, Encoded_key, ASN1_PRINTABLESTRING)
} ASN1_SEQUENCE_END(EMAIL);

DECLARE_ASN1_FUNCTIONS(EMAIL);
IMPLEMENT_ASN1_FUNCTIONS(EMAIL);

bool isSquare(int n) {
    int root = sqrt(n);
    return (root * root == n);
}

int nextSquareFree(int n) {
    n += (n % 2) + 1;
    while (true) {
        if (!isSquare(n) && (n % 7 != 0)) {
            return n;
        }
        n += 2;
    }
}

void generateRSAKeyPair(const std::string& pubFile, const std::string& prvFile) {
    RSA* rsa = RSA_new();
    BIGNUM* exp = BN_new();
    time_t now = time(NULL);
    int e = 3;
    int bits = 4096;
    int retries = 100;

    while (true) {
        BN_set_word(exp, e);
        RSA_generate_key_ex(rsa, bits, exp, NULL);

        if (BN_is_odd(exp) && !isSquare(BN_get_word(exp)) && (BN_get_word(exp) % 7 != 0)) {
            break;
        }

        e += 2;
        if (e % 7 == 0) {
            e += 2;
        }
        retries--;
        if (retries == 0) {
            std::cerr << "Failed to generate RSA key pair" << std::endl;
            RSA_free(rsa);
            BN_free(exp);
            return;
        }
    }

    FILE* f = fopen(prvFile.c_str(), "wb");
    PEM_write_RSAPrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    FILE* f1 = fopen(pubFile.c_str(), "wb");
    PEM_write_RSAPublicKey(f1, rsa);
    fclose(f1);

    RSA_free(rsa);
    BN_free(exp);
}

void generateNonce(std::ofstream& noncefile) {
    std::vector<unsigned char> nonce(EVP_MAX_KEY_LENGTH);
    RAND_bytes(nonce.data(), EVP_MAX_KEY_LENGTH);

    std::stringstream ss;
    ss << "Nonce: ";
    for (auto byte : nonce) {
        ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(byte);
    }
    ss << '\n';

    noncefile << ss.str();
}

void generateSymmetricKey(std::ofstream& keyfile) {
    std::vector<unsigned char> key(EVP_MAX_KEY_LENGTH);
    RAND_bytes(key.data(), EVP_MAX_KEY_LENGTH);

    std::stringstream ss;
    ss << "Symmetric key: ";
    for (auto byte : key) {
        ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(byte);
    }
    ss << '\n';

    keyfile << ss.str();
}

void writeToParamFile(const std::string& username)
{
    std::string filename = username + "-param.crypto";
    std::ofstream ofile(filename.c_str(), std::ios_base::app);

    generateSymmetricKey(ofile);
    generateNonce(ofile);

    std::string filename2 = username + "-key.pub";
    std::string filename3 = username + "-key.prv";
    ofile << "Public key: " << filename2 << '\n';
    ofile << "Private key: " << filename3 << '\n';

    ofile.close();

    generateRSAKeyPair(filename2.c_str(), filename3.c_str());
}

void writeToKeyPubs(const std::string& username)
{
    std::string filename = username + "-key.pub";
    std::ofstream ofile(filename.c_str());
    ofile.close();

    std::string filename2 = "key-pubs.txt";
    std::string pubkey_file = username + "-key.pub";
    std::ofstream ofs2(filename2.c_str(), std::ios_base::app);
    ofs2 << username << ": " << pubkey_file << '\n';
    ofs2.close();
}

void createAccount(const std::string& username)
{
    std::string filename = username + ".account";
    std::ifstream ifile(filename.c_str());
    if (ifile.good())
    {
        std::cerr << "Username/Email already exists!\n";
        ifile.close();
        return;
    }

    ifile.close();

    std::ofstream ofs(filename.c_str());
    ofs.close();

    writeToKeyPubs(username);
    writeToParamFile(username);

    std::cout << "Account created successfully!\n";
}

std::vector<unsigned char> getKey(std::ifstream& file)
{
    std::string symKeyHex;
    std::getline(file, symKeyHex);

    size_t colon_pos = symKeyHex.find(":");
    std::string value = symKeyHex.substr(colon_pos + 2);

    std::vector<unsigned char> asciiValue;
    for (size_t i = 0; i < value.length() - 2; i += 2) {
        std::string byteString = value.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        asciiValue.push_back(byte);
    }

    return asciiValue;
}

std::vector<unsigned char> getNonce(std::ifstream& file)
{
    std::string nonceHex;
    std::getline(file, nonceHex);
    size_t colon_pos = nonceHex.find(":");
    std::string value = nonceHex.substr(colon_pos + 2);

    std::vector<unsigned char> asciiValue;
    for (size_t i = 0; i < value.length() - 2; i += 2) {
        std::string byteString = value.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        asciiValue.push_back(byte);
    }

    return asciiValue;
}

std::string decryptEMAIL(const std::string& input, const std::vector<unsigned char>& key) {
    std::string iv = input.substr(0, 16);
    std::string ciphertext = input.substr(16, input.size() - 16 - EVP_GCM_TLS_TAG_LEN);
    std::string tag = input.substr(input.size() - EVP_GCM_TLS_TAG_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);

    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), (unsigned char*)iv.data());

    int plaintext_len = 0;
    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    EVP_DecryptUpdate(ctx, plaintext.data(), &plaintext_len, (unsigned char*)ciphertext.data(), ciphertext.size());

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, (void*)tag.data());

    EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return std::string((char*)plaintext.data());
}

std::string encryptEMAIL(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& nonce) {

    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    std::string iv(16, 0);
    for (size_t i = 0; i < 16; i++) {
        iv[i] = nonce[i] ^ ((timestamp >> (8 * (nonce.size() - i - 1))) & 0xFF);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);

    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), (unsigned char*)iv.data());

    int ciphertext_len = 0;
    std::vector<unsigned char> ciphertext(plaintext.size());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertext_len, (unsigned char*)plaintext.data(), plaintext.size());

    int tag_len = 0;
    std::vector<unsigned char> tag(EVP_GCM_TLS_TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN, tag.data());

    EVP_CIPHER_CTX_free(ctx);

    std::string output;
    output.reserve(iv.size() + ciphertext.size() + tag.size());
    output.append((char*)iv.data(), iv.size());
    output.append((char*)ciphertext.data(), ciphertext.size());
    output.append((char*)tag.data(), tag.size());

    return output;
}

void encryptKey(std::vector<unsigned char> ukey, const char* public_key_file, unsigned char** out)
{
    FILE* fp = fopen(public_key_file, "r");
    RSA* rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    fclose(fp);

    int rsa_len = RSA_size(rsa);

    *out = new unsigned char[rsa_len];

    int bytes_encrypted = RSA_public_encrypt(rsa_len, ukey.data(), *out, rsa, RSA_PKCS1_PADDING);
}

std::string base64Encode(const std::string& input) {
    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();

    int output_size = EVP_ENCODE_LENGTH(input.length());
    char* output_buffer = new char[output_size];

    EVP_EncodeInit(ctx);

    int output_length = 0;
    EVP_EncodeUpdate(ctx, (unsigned char*)output_buffer, &output_length, (const unsigned char*)input.c_str(), input.length());

    int final_output_length = 0;
    EVP_EncodeFinal(ctx, (unsigned char*)(output_buffer + output_length), &final_output_length);

    std::string output(output_buffer, output_length + final_output_length);

    delete[] output_buffer;
    EVP_ENCODE_CTX_free(ctx);

    return output;
}

std::string base64Decode(const std::string& input) {
    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();

    int output_size = EVP_DECODE_LENGTH(input.length());
    char* output_buffer = new char[output_size];

    EVP_DecodeInit(ctx);

    int output_length = 0;
    EVP_DecodeUpdate(ctx, (unsigned char*)output_buffer, &output_length, (const unsigned char*)input.c_str(), input.length());

    int final_output_length = 0;
    EVP_DecodeFinal(ctx, (unsigned char*)(output_buffer + output_length), &final_output_length);

    std::string output(output_buffer, output_length + final_output_length);

    delete[] output_buffer;
    EVP_ENCODE_CTX_free(ctx);

    return output;
}

std::string signRSA(const std::string& message, const std::string& privateKeyFile) {
    EVP_PKEY* privateKey = nullptr;
    EVP_MD_CTX* context = nullptr;
    std::string signature;

    FILE* file = fopen(privateKeyFile.c_str(), "r");
    if (!file) {
        return "";
    }
    privateKey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    if (!privateKey) {
        return "";
    }

    context = EVP_MD_CTX_new();
    if (!context) {
        return "";
    }
    if (EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, privateKey) != 1) {
        return "";
    }

    if (EVP_DigestSignUpdate(context, message.c_str(), message.size()) != 1) {
        return "";
    }

    size_t signatureSize = 0;
    if (EVP_DigestSignFinal(context, nullptr, &signatureSize) != 1) {
        return "";
    }

    signature.resize(signatureSize);

    if (EVP_DigestSignFinal(context, (unsigned char*)signature.c_str(), &signatureSize) != 1) {
        signature.clear();
        return "";
    }

    return signature.data();
}

bool verifyRSA(const std::string& message, const std::string& signature, const std::string& publicKeyFile) {
    EVP_PKEY* publicKey = nullptr;
    EVP_MD_CTX* context = nullptr;
    bool success = false;

    FILE* file = fopen(publicKeyFile.c_str(), "r");
    if (!file) {
        return false;
    }
    publicKey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);
    if (!publicKey) {
        return false;
    }

    context = EVP_MD_CTX_new();
    if (!context) {
        return false;
    }
    if (EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr, publicKey) != 1) {
        return false;
    }

    if (EVP_DigestVerifyUpdate(context, message.c_str(), message.size()) != 1) {
        return false;
    }

    if (EVP_DigestVerifyFinal(context, (const unsigned char*)signature.c_str(), signature.size()) != 1) {
        return false;
    }

    success = true;
    return success;
}

void writeEMAILtofile(struct EMAIL* e, std::string from, std::string to, std::string title, std::string body, std::string signature, std::string encoded_key, std::string filename) {
    e->From = ASN1_PRINTABLESTRING_new();
    ASN1_STRING_set(e->From, from.c_str(), from.length());

    e->To = ASN1_PRINTABLESTRING_new();
    ASN1_STRING_set(e->To, to.c_str(), to.length());

    e->Title = ASN1_PRINTABLESTRING_new();
    ASN1_STRING_set(e->Title, title.c_str(), title.length());

    e->Body = ASN1_PRINTABLESTRING_new();
    ASN1_STRING_set(e->Body, body.c_str(), body.length());

    e->Signature = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(e->Signature, (unsigned char*)signature.c_str(), signature.length());

    time_t t = time(NULL);
    e->Time = ASN1_UTCTIME_new();
    ASN1_UTCTIME_set(e->Time, t);

    e->Encoded_key = ASN1_PRINTABLESTRING_new();
    ASN1_STRING_set(e->Encoded_key, encoded_key.c_str(), encoded_key.length());

    std::ofstream file;
    file.open(filename, std::ios_base::app);
    if (!file.is_open()) {
        std::cerr << "Error: could not open file " << filename << " for writing" << std::endl;
        return;
    }
    int hex_len = i2d_EMAIL(e, nullptr);
    unsigned char* hex_buf = new unsigned char[hex_len];
    unsigned char* p = hex_buf;
    i2d_EMAIL(e, &p);
    for (int i = 0; i < hex_len; i++) {
        file << std::hex << std::setw(2) << std::setfill('0') << (int)hex_buf[i];
    }
    file << std::endl;
    file.close();
    delete[] hex_buf;
}

bool sendEmail(EMAIL* e, const std::string& username)
{
    std::cout << "Introduce datas:\n";
    bool check = true;
    std::string to_user;
    while (check == true)
    {
        std::cout << "To: ";
        std::cin >> to_user;

        std::string filename = to_user + ".account";
        std::ifstream ifile(filename.c_str());
        if (ifile.good())
        {
            check = false;
        }
        else
        {
            std::cerr << "Receiver doesn't exists!\n";
            ifile.close();
        }
    }

        std::cout << "Title: ";
        std::string title;
        std::cin >> title;

        std::cout << "Message: ";
        std::string message;
        std::getline(std::cin, message);
        std::getline(std::cin, message);

        std::string filename2 = username + "-param.crypto";
        std::ifstream f(filename2.c_str());

        std::vector<unsigned char> key = getKey(f);
        std::vector<unsigned char> nonce = getNonce(f);

        std::string body = encryptEMAIL(message, key, nonce);
        std::string bodye = base64Encode(body);


        std::string file1 = username + "-key.prv";
        std::string sign = signRSA(bodye, file1.c_str());

        std::string newKey(key.begin(), key.end());
        std::string encodedKey = base64Encode(newKey);

        std::string file = to_user + ".account";

        writeEMAILtofile(e, username, to_user, title, bodye, sign, encodedKey, file);
    

    return true;
}

EMAIL* readEMAILfromfile(int line_number, const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: could not open file " << filename << " for reading" << std::endl;
        return nullptr;
    }

    for (int i = 0; i < line_number; i++) {
        if (!file.ignore(std::numeric_limits<std::streamsize>::max(), '\n')) {
            std::cerr << "Error: line " << line_number << " does not exist in file " << filename << std::endl;
            file.close();
            return nullptr;
        }
    }

    std::string hex_str;
    if (!(std::getline(file, hex_str))) {
        std::cerr << "Error: could not read data from line " << line_number << " in file " << filename << std::endl;
        file.close();
        return nullptr;
    }

    std::vector<unsigned char> hex_buf;
    for (size_t i = 0; i < hex_str.length(); i += 2) {
        std::string byte_str = hex_str.substr(i, 2);
        unsigned char byte = (unsigned char)std::stoi(byte_str, nullptr, 16);
        hex_buf.push_back(byte);
    }

    const unsigned char* p = hex_buf.data();
    EMAIL* e = d2i_EMAIL(nullptr, &p, hex_buf.size());
    if (!e) {
        std::cerr << "Error: could not decode data from line " << line_number << " in file " << filename << std::endl;
        file.close();
        return nullptr;
    }

    file.close();
    return e;
}

void printEMAIL(struct EMAIL* e) {
    std::cout << std::endl << "Your EMAIL:" << std::endl;
    std::cout << "From: " << ASN1_STRING_get0_data(e->From) << std::endl;
    std::cout << "Title: " << ASN1_STRING_get0_data(e->Title) << std::endl;

    tm utc_time;
    ASN1_TIME_to_tm(e->Time, &utc_time);
    char time_str[80];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S UTC", &utc_time);
    std::cout << "Time: " << time_str << std::endl;

    const char* data0 = reinterpret_cast<const char*>(ASN1_STRING_get0_data(e->From));
    int length0 = ASN1_STRING_length(e->From);
    std::string from(data0, length0);
    std::string filename = from + "-key.pub";

    const char* data = reinterpret_cast<const char*>(ASN1_STRING_get0_data(e->Body));
    int length = ASN1_STRING_length(e->Body);
    std::string body_old(data, length);

    const char* data1 = reinterpret_cast<const char*>(ASN1_STRING_get0_data(e->Encoded_key));
    int length1 = ASN1_STRING_length(e->Encoded_key);
    std::string key_old(data1, length1);
    std::string decrypt_key = base64Decode(key_old);
    std::vector<unsigned char> new_key(decrypt_key.begin(), decrypt_key.end());

    std::string body_decrypt = base64Decode(body_old);
    std::string body = decryptEMAIL(body_decrypt, new_key);

    std::cout << "Body: " << body << std::endl;

    std::cout << "Signature: ";
    const char* data2 = reinterpret_cast<const char*>(ASN1_STRING_get0_data(e->Signature));
    int length2 = ASN1_STRING_length(e->Signature);
    std::string signature(data2, length2);

    if (verifyRSA(body_old, signature, filename.c_str()) == true)
    {
        std::cout << "Verified!";
    }
    else
    {
        std::cout << "NOT Verified!";
    }

    std::cout << std::endl;
}

bool readEmail(EMAIL* e, const std::string& username)
{
    bool test = true;
    while (test == true)
    {
        int l = 0;
        std::cout << "Give the line number of the email: ";
        std::cin >> l;

        std::string filename = username + ".account";
        e = readEMAILfromfile(l, filename);
        if (e != nullptr)
        {
            test = false;
        }
    }

    printEMAIL(e);

    return true;
}

bool checkAccountExists(const std::string& username)
{
    std::ifstream ifs(username + ".account");
    bool exists = ifs.good();
    ifs.close();
    return exists;
}

bool login(const std::string& username)
{
    if (!checkAccountExists(username))
    {
        std::cerr << "Username/Email does not exist!\n";
        return false;
    }

    std::cout << "\n\nWelcome, " << username << "!";

    char option;
    EMAIL* e = EMAIL_new();
    do
    {
        std::cout << "\nPlease select an option:\n"
            << "1. Send email\n"
            << "2. Read emails\n"
            << "3. Log out\n";

        std::cin >> option;

        switch (option)
        {
        case '1':
            sendEmail(e, username);
            break;

        case '2':
            readEmail(e, username);
            break;

        case '3':
            return true;

        default:
            std::cerr << "Invalid option!\n";
            break;
        }

    } while (true);

    EMAIL_free(e);
    return false;
}

int main()
{
    char option;
    do
    {
        std::cout << "\nPlease select an option:\n"
            << "1. Login\n"
            << "2. Create account\n"
            << "3. Exit\n";

        std::cin >> option;

        switch (option)
        {
        case '1':
        {
            std::string username;
            std::cout << "Please enter your username/email:\n";
            std::cin >> username;

            if (login(username))
            {
                std::cout << "Logged out.\n";
            }
            else
            {
                std::cerr << "Failed to login.\n";
            }

            break;
        }

        case '2':
        {
            std::string username;
            std::cout << "Please enter your desired username/your email:\n";
            std::cin >> username;

            createAccount(username);

            break;
        }

        case '3':
            std::cout << "Exiting...\n";
            return 0;

        default:
            std::cerr << "Invalid option!\n";
            break;
        }

    } while (true);

    return 0;
}