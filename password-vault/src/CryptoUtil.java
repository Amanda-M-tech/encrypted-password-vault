import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * All the cryptography lives here:
 *  - PBKDF2 turns the master password into a 256-bit AES key
 *  - AES-GCM encrypts the data AND detects tampering / wrong keys
 */
public class CryptoUtil {

    public static final int SALT_LENGTH = 16;        // bytes
    public static final int IV_LENGTH = 12;          // bytes (recommended for GCM)
    private static final int KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int PBKDF2_ITERATIONS = 210_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    /** Random bytes for salts and IVs. */
    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    /** Master password + salt -> AES key. Slow on purpose to hinder brute force. */
    public static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword(); // wipe the password copy from memory
        }
    }

    /** Encrypts data. A fresh IV is generated every time and prepended to the output. */
    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
        byte[] iv = randomBytes(IV_LENGTH);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }

    /**
     * Decrypts data produced by encrypt().
     * Throws AEADBadTagException if the key is wrong or the file was modified.
     */
    public static byte[] decrypt(byte[] ivAndCiphertext, SecretKey key) throws Exception {
        byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(ivAndCiphertext, IV_LENGTH, ivAndCiphertext.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(ciphertext);
    }
}
