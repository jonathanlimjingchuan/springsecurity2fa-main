package springsecurity.mfa.config;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class EncryptionConfig {

    private static final String AES = "AES";
    private static final int AES_KEY_SIZE = 256; // bits
    private static final int IV_SIZE = 12; // bytes for GCM
    private static final int TAG_LENGTH_BIT = 128;

    // Generate a new AES key
    public String generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(AES_KEY_SIZE, SecureRandom.getInstanceStrong());
        SecretKey secretKey = keyGenerator.generateKey();
        return encodeBase64(secretKey.getEncoded());
    }

    // Generate a new Initialization Vector (IV)
    public String generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return encodeBase64(iv);
    }

    // Encrypt plaintext using AES key and IV
    public String[] encrypt(String plaintext) throws Exception {
        String base64SecretKey = generateSecretKey();
        String base64IV = generateIV();
        SecretKey secretKey = decodeSecretKey(base64SecretKey);
        byte[] iv = decodeBase64(base64IV);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

        // Return the encrypted data, key, and IV
        return new String[]{
            encodeBase64(encryptedBytes),
            base64SecretKey,
            base64IV
        };
    }

    // Decrypt ciphertext using AES key and IV
    public String decrypt(String ciphertext, String base64SecretKey, String base64IV) throws Exception {
        SecretKey secretKey = decodeSecretKey(base64SecretKey);
        byte[] iv = decodeBase64(base64IV);
        byte[] encryptedBytes = decodeBase64(ciphertext);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    // Helper methods for Base64 encoding and decoding
    private String encodeBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decodeBase64(String data) {
        return Base64.getDecoder().decode(data);
    }

    private SecretKey decodeSecretKey(String base64Key) {
        byte[] decodedKey = decodeBase64(base64Key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, AES);
    }
}
