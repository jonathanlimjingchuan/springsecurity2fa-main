package springsecurity.mfa.model;

import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String role = "USER";

    @Column(name = "two_factor_enabled", nullable = false)
    private boolean twoFactorEnabled = false;

    @Column(name = "two_factor_secret")
    private String twoFactorSecret;

    @Column(name = "two_factor_secret_key")
    private String twoFactorSecretKey;

    @Column(name = "two_factor_secret_iv")
    private String twoFactorSecretIV;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<RecoveryCode> recoveryCodes = new HashSet<>();

    public User() {}

    public User(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public boolean isTwoFactorEnabled() {
        return twoFactorEnabled;
    }

    public void setTwoFactorEnabled(boolean twoFactorEnabled) {
        this.twoFactorEnabled = twoFactorEnabled;
    }

    public String getTwoFactorSecret() {
        return twoFactorSecret;
    }

    public void setTwoFactorSecret(String twoFactorSecret) {
        this.twoFactorSecret = twoFactorSecret;
    }

    public String getTwoFactorSecretKey() {
        return twoFactorSecretKey;
    }

    public void setTwoFactorSecretKey(String twoFactorSecretKey) {
        this.twoFactorSecretKey = twoFactorSecretKey;
    }

    public String getTwoFactorSecretIV() {
        return twoFactorSecretIV;
    }

    public void setTwoFactorSecretIV(String twoFactorSecretIV) {
        this.twoFactorSecretIV = twoFactorSecretIV;
    }

    public Set<RecoveryCode> getRecoveryCodes() {
        return recoveryCodes;
    }

    public void setRecoveryCodes(Set<RecoveryCode> recoveryCodes) {
        this.recoveryCodes = recoveryCodes;
    }
}
