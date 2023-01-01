package org.ryuu.encrypt;

import org.ryuu.encode.Base64;

import javax.crypto.Cipher;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class Encryptor {
    private final Cipher encryptCipher;
    private final Cipher decryptCipher;
    private Charset charset;

    public Encryptor(Cipher encryptCipher, Cipher decryptCipher, Charset charset) {
        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;
        this.charset = charset;
    }

    public byte[] encrypt(final byte[] bytes) {
        try {
            return encryptCipher.doFinal(bytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String encrypt(final String string) {
        return Base64.getUrlEncoder().encodeToString(encrypt(string.getBytes(charset)));
    }

    public byte[] decrypt(final byte[] bytes) {
        try {
            return decryptCipher.doFinal(bytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String decrypt(final String string) {
        byte[] bytes = decrypt(Base64.getUrlDecoder().decode(string));
        if (bytes == null) {
            return null;
        }
        return new String(bytes, charset);
    }
}