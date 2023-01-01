package org.ryuu.encrypt;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EncryptorTest {
    private static Encryptor encryptor;

    @BeforeAll
    static void beforeAll() {
        try {
            byte[] keyBytes = "com.cooyostudio.finger.glow.hockey".getBytes(StandardCharsets.UTF_8);
            keyBytes = MessageDigest.getInstance("SHA-256").digest(keyBytes);

            SecretKeySpec secretKeySpec = new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES"); // Key must be 16, 24 or 32 bytes long (respectively for *AES-128*, *AES-192* or *AES-256*).
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Arrays.copyOf(keyBytes, 16)); // IV length: must be 16 bytes long

            String transformation = "AES/CFB/NoPadding";

            Cipher encryptCipher = Cipher.getInstance(transformation);
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            Cipher decryptCipher = Cipher.getInstance(transformation);
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            encryptor = new Encryptor(encryptCipher, decryptCipher,StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void decryptAndEncryptTest() {
        String encryptString = "3MZG7jWEDb7NfC3R6F_zMKH1OJZa3Z_f9g==";
        String decrypt = encryptor.decrypt(encryptString);

        String plainString = "{\"dates\":[1672225641271]}";
        String encrypt = encryptor.encrypt(plainString);

        assertEquals(plainString, decrypt);
        assertEquals(encryptString, encrypt);
    }

    @Test
    void test() throws IOException {
        String filePath = "E:\\SvnWorkspace\\cooyocode\\fingerhockey\\tags\\AirHockey\\Encryptor\\src\\test\\resources\\test.txt";
        byte[] encrypt = encryptor.encrypt("test".getBytes(StandardCharsets.UTF_8));
        Files.write(new File(filePath).toPath(), encrypt, StandardOpenOption.CREATE);
        byte[] bytes = Files.readAllBytes(new File(filePath).toPath());
        byte[] decrypt = encryptor.decrypt(bytes);
        String s = new String(decrypt, StandardCharsets.UTF_8);
        System.out.println(s);

        String s1 = Files.readString(new File(filePath).toPath(), StandardCharsets.UTF_8);
        System.out.println(s1);
    }
}