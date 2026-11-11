import java.io.Console;
import java.util.List;
import java.util.Scanner;

/** Command-line interface for the Encrypted Password Vault. */
public class Main {

    private static final int MAX_ATTEMPTS = 3;
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        System.out.println("=== Encrypted Password Vault ===");
        VaultManager vault = new VaultManager();

        try {
            if (!vault.vaultExists()) {
                setupNewVault(vault);
            } else if (!login(vault)) {
                System.out.println("Too many failed attempts. Locked out. Exiting.");
                return;
            }
            menuLoop(vault);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private static void setupNewVault(VaultManager vault) throws Exception {
        System.out.println("No vault found. Let's create one.");
        while (true) {
            char[] pw1 = readSecret("Create master password (min 8 chars): ");
            if (pw1.length < 8) {
                System.out.println("Too short. Try again.");
                continue;
            }
            char[] pw2 = readSecret("Confirm master password: ");
            if (!java.util.Arrays.equals(pw1, pw2)) {
                System.out.println("Passwords do not match. Try again.");
                continue;
            }
            vault.createVault(pw1);
            java.util.Arrays.fill(pw1, ' ');
            java.util.Arrays.fill(pw2, ' ');
            System.out.println("Vault created and encrypted.");
            return;
        }
    }

    private static boolean login(VaultManager vault) throws Exception {
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            char[] pw = readSecret("Master password (attempt " + attempt + "/" + MAX_ATTEMPTS + "): ");
            boolean ok = vault.unlock(pw);
            java.util.Arrays.fill(pw, ' ');
            if (ok) {
                System.out.println("Vault unlocked.");
                return true;
            }
            System.out.println("Wrong master password.");
        }
        return false;
    }

    private static void menuLoop(VaultManager vault) throws Exception {
        while (true) {
            System.out.println("\n1) Add entry  2) View entries  3) Delete entry  4) Generate password  5) Quit");
            System.out.print("Choose: ");
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    addEntry(vault);
                    break;
                case "2":
                    viewEntries(vault);
                    break;
                case "3":
                    deleteEntry(vault);
                    break;
                case "4":
                    System.out.println("Generated: " + VaultManager.generatePassword(16));
                    break;
                case "5":
                    System.out.println("Vault locked. Goodbye.");
                    return;
                default:
                    System.out.println("Invalid option.");
            }
        }
    }

    private static void addEntry(VaultManager vault) throws Exception {
        System.out.print("Site: ");
        String site = scanner.nextLine().trim();
        System.out.print("Username: ");
        String user = scanner.nextLine().trim();
        System.out.print("Password (leave blank to generate one): ");
        String pass = scanner.nextLine();
        if (pass.isEmpty()) {
            pass = VaultManager.generatePassword(16);
            System.out.println("Generated password: " + pass);
        }
        vault.addEntry(new Entry(site, user, pass));
        System.out.println("Saved (encrypted).");
    }

    private static void viewEntries(VaultManager vault) {
        List<Entry> entries = vault.getEntries();
        if (entries.isEmpty()) {
            System.out.println("Vault is empty.");
            return;
        }
        for (int i = 0; i < entries.size(); i++) {
            Entry e = entries.get(i);
            System.out.printf("%d) %s | %s | %s%n", i + 1, e.getSite(), e.getUsername(), e.getPassword());
        }
    }

    private static void deleteEntry(VaultManager vault) throws Exception {
        viewEntries(vault);
        if (vault.getEntries().isEmpty()) return;
        System.out.print("Number to delete: ");
        try {
            int n = Integer.parseInt(scanner.nextLine().trim());
            System.out.println(vault.deleteEntry(n - 1) ? "Deleted." : "No such entry.");
        } catch (NumberFormatException e) {
            System.out.println("Please enter a number.");
        }
    }

    /** Hides typing when run in a real terminal; falls back to Scanner in IDEs. */
    private static char[] readSecret(String prompt) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        }
        System.out.print(prompt);
        return scanner.nextLine().toCharArray();
    }
}
