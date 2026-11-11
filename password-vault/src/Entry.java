/** One saved login (site, username, password). */
public class Entry {
    private final String site;
    private final String username;
    private final String password;

    public Entry(String site, String username, String password) {
        this.site = site;
        this.username = username;
        this.password = password;
    }

    public String getSite() { return site; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
}
