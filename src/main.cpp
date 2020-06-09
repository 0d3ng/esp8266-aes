#include <Arduino.h>
#include <ArduinoJson.h>

#include "AES.h"
#include "base64.h"
#include "AES_config.h"


uint8_t getrnd()
{
    uint8_t really_random = *(volatile uint8_t *)0x3FF20E44;
    return really_random;
}

void gen_iv(byte *iv)
{
    for (int i = 0; i < N_BLOCK; i++)
    {
        iv[i] = (byte)getrnd();
    }
}

//aes128  CBC  pkcs7填充  随机IV
//data：Str: msg Str: IV
//json：Str: {"iv":"IV","msg":"data"}
String do_encrypt(String msg, byte *key)
{
    size_t encrypt_size_len = 2000; //缓存长度
    DynamicJsonDocument root(1024); //
    byte my_iv[N_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    char *b64data = new char[encrypt_size_len];
    byte *cipher = new byte[encrypt_size_len];

    AES aes;

    aes.set_key(key, sizeof(key));
    gen_iv(my_iv);

    memset(b64data, 0, encrypt_size_len);

    //IVbase64
    base64_encode(b64data, (char *)my_iv, N_BLOCK);
    root["iv"] = String(b64data);

    
    memset(b64data, 0, encrypt_size_len);
    memset(cipher, 0, encrypt_size_len);

    //msg base64
    int b64len = base64_encode(b64data, (char *)msg.c_str(), msg.length());

    //AES128，IV，CBCpkcs7
    aes.do_aes_encrypt((byte *)b64data, b64len, cipher, key, 128, my_iv);
    aes.clean();

    memset(b64data, 0, encrypt_size_len);
    
    base64_encode(b64data, (char *)cipher, aes.get_size());
    root["msg"] = String(b64data);

    String JsonBuff;
    serializeJson(root, JsonBuff);
    root.clear();
    // memset(b64data, 0, sizeof(b64data));
    // memset(cipher, 0, sizeof(cipher));
    delete[] b64data;
    delete[] cipher;

    return JsonBuff;
    // return msg;
}

//aes128  CBC  pkcs7
//CipherJson：Str: {"msg":"data","iv":"value iv"}
//return：Str
String do_decrypt(String CipherJson, byte *key, size_t len)
{
    DynamicJsonDocument root(len + 50); //

    DeserializationError error = deserializeJson(root, CipherJson);

    if (!error)
    {
        byte my_iv[N_BLOCK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        char my_iv_char[50];
        size_t encrypt_size_len = 2000;

        char *b64data = new char[encrypt_size_len];
        byte *cipher = new byte[encrypt_size_len];
        char *plain_msg = new char[encrypt_size_len];

        AES aes;

        String my_iv_str = root["iv"];
        String CipherText = root["msg"];

        root.clear();

        memset(b64data, 0, encrypt_size_len);

        memset(my_iv_char, 0, sizeof(my_iv_char));

        CipherText.toCharArray(b64data, CipherText.length() + 1);
        my_iv_str.toCharArray(my_iv_char, my_iv_str.length() + 1);

        base64_decode((char *)my_iv, my_iv_char, strlen(my_iv_char));

        memset(cipher, 0, encrypt_size_len);

        int cipherlen = base64_decode((char *)cipher, b64data, strlen(b64data));

        memset(b64data, 0, encrypt_size_len);


        aes.set_key(key, sizeof(key)); // Get the globally defined key
        aes.do_aes_decrypt(cipher, cipherlen, (byte *)b64data, key, 128, my_iv);
        aes.unpadPlaintext((byte *)b64data, aes.get_size());
        aes.clean();

        //base64
        memset(plain_msg, 0, encrypt_size_len);

        base64_decode(plain_msg, b64data, strlen(b64data));
        String plain_msg_str = String(plain_msg);

        delete[] b64data;
        delete[] cipher;
        delete[] plain_msg;

        return plain_msg_str;
    }

    root.clear();
    return "ERROR";
}

void setup()
{
    Serial.begin(115200);
    Serial.println(" ");

    // byte my_iv[N_BLOCK] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    byte key[] = {0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48};

    Serial.println("----->>>>> Start encryption <<<<<-----");
    String msg = "Hello Word";
    Serial.println("msg:" + msg);
    String data = do_encrypt(msg, key);
    Serial.println("Encrypted data:" + data);

    
    Serial.println("----->>>>> Start decrypting <<<<<-----");
    Serial.println("Encrypted data:" + data);
    Serial.println("Decrypted data:" + do_decrypt(data, key, 1000));

    ////////////////////////////////////////////////////////////////
    
    Serial.println("----->>>>> Start encryption <<<<<-----");
    String msg1 = "Hello Word Hello Word";
    Serial.println("msg1:" + msg1);
    String data1 = do_encrypt(msg1, key);
    Serial.println("Encrypted data:" + data1);

    
    Serial.println("----->>>>> Start decrypting <<<<<-----");
    Serial.println("Encrypted data:" + data1);
    Serial.println("Decrypted data:" + do_decrypt(data1, key, 1000));
}

void loop()
{
    // put your main code here, to run repeatedly:
    while (1)
    {
        delay(1);
    }
}
