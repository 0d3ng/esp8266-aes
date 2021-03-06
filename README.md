# esp8266-aes
Contoh penggunaan AES menggunakan esp8266, amica

## Contoh Penggunaan
```cpp
#include "AESLib.h"

AESLib aesLib;

int loopcount = 0;

char cleartext[256];
char ciphertext[512];

// AES Encryption Key
byte aes_key[] = {0x15, 0x2B, 0x7E, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};

// General initialization vector (you must use your own IV's in production for full security!!!)
byte aes_iv[N_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

String encrypt(char *msg, byte iv[])
{
  int msgLen = strlen(msg);
  char encrypted[2 * msgLen];
  aesLib.encrypt64(msg, msgLen, encrypted, aes_key, 256, iv);//untuk mengganti mode sesuaikan nilainya 128 bit, 256 bit, dan yang lain
  return String(encrypted);
}

String decrypt(char *msg, byte iv[])
{
  unsigned long ms = micros();
  int msgLen = strlen(msg);
  char decrypted[msgLen]; // half may be enough
  aesLib.decrypt64(msg, msgLen, decrypted, aes_key, 256, iv);//untuk mengganti mode sesuaikan nilainya 128 bit, 256 bit, dan yang lain
  return String(decrypted);
}

// Generate IV (once)
void aes_init()
{
  aesLib.gen_iv(aes_iv);
  // workaround for incorrect B64 functionality on first run...
  encrypt("HELLO WORLD!", aes_iv);
}

void setup()
{
  Serial.begin(115200);
  Serial.println("Contoh penggunaan AES");
  aes_init();
}

void loop()
{
  loopcount++;

  sprintf(cleartext, "START; %i \n", loopcount);

  // Encrypt
  byte enc_iv[N_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // iv_block gets written to, provide own fresh copy...
  String encrypted = encrypt(cleartext, enc_iv);
  sprintf(ciphertext, "%s", encrypted.c_str());
  Serial.print("Ciphertext: ");
  Serial.println(encrypted);

  // Decrypt
  byte dec_iv[N_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // iv_block gets written to, provide own fresh copy...
  String decrypted = decrypt(ciphertext, dec_iv);
  Serial.print("Cleartext: ");
  Serial.println(decrypted);

  delay(500);
}
```