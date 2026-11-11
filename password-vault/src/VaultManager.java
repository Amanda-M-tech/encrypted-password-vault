import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Handles the vault file.
 * File layout on disk:  [16-byte salt][12-byte IV][AES-GCM ciphertext + tag]
 *
 * We do NOT store the master password or its hash. If the password is wrong,
 * the key is wrong, and GCM's authentication tag check fails. That is how we
 * know the password is incorrect.
 */
public class VaultManager {

    private static final Path VAULT_FILE = Paths.get("vault.dat");
    private static final String CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";

    private final List<Entry> entries = new ArrayList<>();
    private byte[] salt;
    private SecretKey key;

    public boolean vaultExists() {
        return Files.exists(VAULT_FILE);
    }

    /** First run: set the master password and create an empty vault. */
    public void createVault(char[] masterPassword) throws Exception {
        salt = CryptoUtil.randomBytes(CryptoUtil.SALT_LENGTH);
        key = CryptoUtil.deriveKey(masterPassword, salt);
        entries.clear();
        save();
    }

    /** Returns true if the password was correct and the vault was loaded. */
    public boolean unlock(char[] masterPassword) throws Exception {
        byte[] fileBytes = Files.readAllBytes(VAULT_FILE);
        byte[] fileSalt = Arrays.copyOfRange(fileBytes, 0, CryptoUtil.SALT_LENGTH);
        byte[] encrypted = Arrays.copyOfRange(fileBytes, CryptoUtil.SALT_LENGTH, fileBytes.length);

        SecretKey attemptKey = CryptoUtil.deriveKey(masterPassword, fileSalt);
        try {
            byte[] plain = CryptoUtil.decrypt(encrypted, attemptKey);
            salt = fileSalt;
            key = attemptKey;
            deserialize(new String(plain, StandardCharsets.UTF_8));
            return true;
        } catch (AEADBadTagException e) {
            return false; // wrong password (or tampered file)
        }
    }

    public void addEntry(Entry entry) throws Exception {
        entries.add(entry);
        save();
    }

    public boolean deleteEntry(int index) throws Exception {
        if (index < 0 || index >= entries.size()) return false;
        entries.remove(index);
        save();
        return true;
    }

    public List<Entry> getEntries() {
        return entries;
    }

    /** Generates a random password using SecureRandom. */
    public static String generatePassword(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(CHARS.charAt(random.nextInt(CHARS.length())));
        }
        return sb.toString();
    }

    // ---------- private helpers ----------

    private void save() throws Exception {
        byte[] encrypted = CryptoUtil.encrypt(serialize().getBytes(StandardCharsets.UTF_8), key);
        byte[] out = new byte[salt.length + encrypted.length];
        System.arraycopy(salt, 0, out, 0, salt.length);
        System.arraycopy(encrypted, 0, out, salt.length, encrypted.length);
        Files.write(VAULT_FILE, out);
    }

    // One entry per line; each field is Base64 so special characters can't break the format.
    private String serialize() {
        Base64.Encoder enc = Base64.getEncoder();
        StringBuilder sb = new StringBuilder();
        for (Entry e : entries) {
            sb.append(enc.encodeToString(e.getSite().getBytes(StandardCharsets.UTF_8))).append(':')
              .append(enc.encodeToString(e.getUsername().getBytes(StandardCharsets.UTF_8))).append(':')
              .append(enc.encodeToString(e.getPassword().getBytes(StandardCharsets.UTF_8))).append('\n');
        }
        return sb.toString();
    }

    private void deserialize(String data) {
        entries.clear();
        Base64.Decoder dec = Base64.getDecoder();
        for (String line : data.split("\n")) {
            if (line.isBlank()) continue;
            String[] p = line.split(":");
            entries.add(new Entry(
                    new String(dec.decode(p[0]), StandardCharsets.UTF_8),
                    new String(dec.decode(p[1]), StandardCharsets.UTF_8),
                    new String(dec.decode(p[2]), StandardCharsets.UTF_8)));
        }
    }
}
