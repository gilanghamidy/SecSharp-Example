 
#include <SecSharp.Enclave.h>

struct SimpleEnclave_EnclaveHashWithArray {
  static constexpr size_t type_id = 1;
  void ObtainKey(boost::span<uint8_t> keyOut);
  void XorElement(boost::span<uint8_t> key, uint8_t val,
                  boost::span<uint8_t> opadOut);
  void ConcatBuffer(boost::span<uint8_t> b1, boost::span<uint8_t> b2,
                    boost::span<uint8_t> resultOut);
  void HMACSHA1(boost::span<uint8_t> message, boost::span<uint8_t> digestOut);
  void UIntToByteArray(uint32_t val, boost::span<uint8_t> buf, int32_t offset);
  void SHA1(boost::span<uint8_t> message, boost::span<uint8_t> digestOut);
};
void SimpleEnclave_EnclaveHashWithArray::ObtainKey(
    boost::span<uint8_t> keyOut) {
  for (int32_t i{0}; i < keyOut.size(); i++)
    secsharp::span_safe_access(keyOut, i) =
        static_cast<uint8_t>(((18 * i) % 255));
}
void SimpleEnclave_EnclaveHashWithArray::XorElement(
    boost::span<uint8_t> key, uint8_t val, boost::span<uint8_t> opadOut) {
  for (int32_t i{0}; i < key.size(); i++)
    secsharp::span_safe_access(opadOut, i) =
        static_cast<uint8_t>((secsharp::span_safe_access(key, i) ^ val));
}
void SimpleEnclave_EnclaveHashWithArray::ConcatBuffer(
    boost::span<uint8_t> b1, boost::span<uint8_t> b2,
    boost::span<uint8_t> resultOut) {
  for (int32_t i{0}; i < b1.size(); i++)
    secsharp::span_safe_access(resultOut, i) =
        secsharp::span_safe_access(b1, i);
  for (int32_t i{0}; i < b2.size(); i++)
    secsharp::span_safe_access(resultOut, i + b1.size()) =
        secsharp::span_safe_access(b2, i);
}
void SimpleEnclave_EnclaveHashWithArray::HMACSHA1(
    boost::span<uint8_t> message, boost::span<uint8_t> digestOut) {
  size_t __key_len = 64;
  auto __key_ptr = std::make_unique<uint8_t[]>(__key_len);
  boost::span<uint8_t> key{__key_ptr.get(), __key_len};
  this->ObtainKey(key);
  size_t __oKey_len = 64;
  auto __oKey_ptr = std::make_unique<uint8_t[]>(__oKey_len);
  boost::span<uint8_t> oKey{__oKey_ptr.get(), __oKey_len};
  this->XorElement(key, 92, oKey);
  size_t __iKey_len = 64;
  auto __iKey_ptr = std::make_unique<uint8_t[]>(__iKey_len);
  boost::span<uint8_t> iKey{__iKey_ptr.get(), __iKey_len};
  this->XorElement(key, 54, iKey);
  size_t __iKey_message_len = iKey.size() + message.size();
  auto __iKey_message_ptr = std::make_unique<uint8_t[]>(__iKey_message_len);
  boost::span<uint8_t> iKey_message{__iKey_message_ptr.get(),
                                    __iKey_message_len};
  this->ConcatBuffer(iKey, message, iKey_message);
  size_t __innerHash_len = 20;
  auto __innerHash_ptr = std::make_unique<uint8_t[]>(__innerHash_len);
  boost::span<uint8_t> innerHash{__innerHash_ptr.get(), __innerHash_len};
  this->SHA1(iKey_message, innerHash);
  size_t __oKey_innerHash_len = oKey.size() + innerHash.size();
  auto __oKey_innerHash_ptr = std::make_unique<uint8_t[]>(__oKey_innerHash_len);
  boost::span<uint8_t> oKey_innerHash{__oKey_innerHash_ptr.get(),
                                      __oKey_innerHash_len};
  this->ConcatBuffer(oKey, innerHash, oKey_innerHash);
  this->SHA1(oKey_innerHash, digestOut);
}
void SimpleEnclave_EnclaveHashWithArray::UIntToByteArray(
    uint32_t val, boost::span<uint8_t> buf, int32_t offset) {
  for (int32_t i{3}; i >= 0; i--)
    secsharp::span_safe_access(buf, offset + 3 - i) =
        static_cast<uint8_t>((val >> (8 * i)));
}
void SimpleEnclave_EnclaveHashWithArray::SHA1(boost::span<uint8_t> message,
                                              boost::span<uint8_t> digestOut) {
  uint32_t h0{1732584193}, h1{4023233417}, h2{2562383102}, h3{271733878},
      h4{3285377520};
  uint64_t ml{static_cast<uint64_t>((message.size() * 8))};
  int32_t zeroPadLen{(56 - (message.size() + 1) % 64) % 64};
  size_t __vs_len = message.size() + zeroPadLen + 1 + 8;
  auto __vs_ptr = std::make_unique<uint8_t[]>(__vs_len);
  boost::span<uint8_t> vs{__vs_ptr.get(), __vs_len};
  secsharp::span_safe_access(vs, message.size()) = 128;
  for (int32_t i{0}; i < zeroPadLen; i++)
    secsharp::span_safe_access(vs, message.size() + i + 1) = 0;
  for (int32_t i{0}; i < 8; i++) {
    secsharp::span_safe_access(vs, i + message.size() + zeroPadLen + 1) =
        static_cast<uint8_t>(((ml >> ((7 - i) * 8)) & 255));
  }
  for (int32_t i{0}; i < message.size(); i++) {
    secsharp::span_safe_access(vs, i) = secsharp::span_safe_access(message, i);
  }
  int32_t iteration{vs.size() / 64};
  for (int32_t i{0}; i < iteration; i++) {
    int32_t iterationBaseIdx{i * 512 / 8};
    size_t __w_len = 80;
    auto __w_ptr = std::make_unique<uint32_t[]>(__w_len);
    boost::span<uint32_t> w{__w_ptr.get(), __w_len};
    for (int32_t j{0}; j < 16; j++) {
      secsharp::span_safe_access(w, j) =
          secsharp::span_safe_access(vs, iterationBaseIdx + j * 4 + 3) |
          (static_cast<uint32_t>(
              secsharp::span_safe_access(vs, iterationBaseIdx + j * 4 + 2)))
              << 8 |
          (static_cast<uint32_t>(
              secsharp::span_safe_access(vs, iterationBaseIdx + j * 4 + 1)))
              << 16 |
          (static_cast<uint32_t>(
              secsharp::span_safe_access(vs, iterationBaseIdx + j * 4)))
              << 24;
    }
    for (int32_t j{16}; j < 80; j++) {
      uint32_t num{secsharp::span_safe_access(w, j - 3) ^
                   secsharp::span_safe_access(w, j - 8) ^
                   secsharp::span_safe_access(w, j - 14) ^
                   secsharp::span_safe_access(w, j - 16)};
      secsharp::span_safe_access(w, j) = (num << 1) | (num >> 31);
    }
    uint32_t a{h0};
    uint32_t b{h1};
    uint32_t c{h2};
    uint32_t d{h3};
    uint32_t e{h4};
    for (int32_t j{0}; j < 80; j++) {
      uint32_t f{0}, k{0};
      if (j <= 19) {
        f = (b & c) | (~b & d);
        k = 1518500249;
      } else if (j <= 39) {
        f = b ^ c ^ d;
        k = 1859775393;
      } else if (j <= 59) {
        f = (b & c) | (b & d) | (c & d);
        k = 2400959708;
      } else {
        f = b ^ c ^ d;
        k = 3395469782;
      }
      uint32_t temp{((a << 5) | (a >> 27)) + f + e + k +
                    secsharp::span_safe_access(w, j)};
      e = d;
      d = c;
      c = (b << 30) | (b >> 2);
      b = a;
      a = temp;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }
  UIntToByteArray(h0, digestOut, 0);
  UIntToByteArray(h1, digestOut, 1 * 4);
  UIntToByteArray(h2, digestOut, 2 * 4);
  UIntToByteArray(h3, digestOut, 3 * 4);
  UIntToByteArray(h4, digestOut, 4 * 4);
}
extern "C" void SimpleEnclave_EnclaveHashWithArray_HMACSHA1(
    SecSharpMessage *messages, size_t messages_count, size_t instance,
    uint8_t *message_ptr, size_t message_count, uint8_t *digestOut_ptr,
    size_t digestOut_count) {
  secsharp::enclave_entry_prolog({messages, messages_count});
  boost::span<uint8_t> message{message_ptr, message_count};
  boost::span<uint8_t> digestOut{digestOut_ptr, digestOut_count};
  secsharp::get_instance<SimpleEnclave_EnclaveHashWithArray>(instance).HMACSHA1(
      message, digestOut);
}
extern "C" void SimpleEnclave_EnclaveHashWithArray_SHA1(
    SecSharpMessage *messages, size_t messages_count, size_t instance,
    uint8_t *message_ptr, size_t message_count, uint8_t *digestOut_ptr,
    size_t digestOut_count) {
  secsharp::enclave_entry_prolog({messages, messages_count});
  boost::span<uint8_t> message{message_ptr, message_count};
  boost::span<uint8_t> digestOut{digestOut_ptr, digestOut_count};
  secsharp::get_instance<SimpleEnclave_EnclaveHashWithArray>(instance).SHA1(
      message, digestOut);
}
extern "C" void SimpleEnclave_EnclaveHashWithArray_ctor(
    SecSharpMessage *messages, size_t messages_count, size_t *instance) {
  secsharp::enclave_entry_prolog({messages, messages_count});
  *instance =
      secsharp::instantiate_object<SimpleEnclave_EnclaveHashWithArray>();
}
