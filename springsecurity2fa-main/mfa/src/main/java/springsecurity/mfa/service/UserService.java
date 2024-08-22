package springsecurity.mfa.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import springsecurity.mfa.config.RecoveryCodeGenerator;
import springsecurity.mfa.model.User;
import springsecurity.mfa.repository.UserRepository;
import springsecurity.mfa.config.EncryptionConfig;

import java.util.Set;

@Service
public class UserService {

    // Injecting dependencies using Spring's @Autowired
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EncryptionConfig encryptionConfig;

    @Autowired
    private RecoveryCodeService recoveryCodeService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Saves a user to the database. If two-factor authentication is enabled and the user does not
     * have a two-factor secret key, this method will generate and encrypt the secret key, generate
     * recovery codes, and save them along with the user.
     *
     * @param user the user entity to be saved
     */
    public void save(User user) {
        // Check if two-factor authentication is enabled and if the secret key is not already set
        if (user.isTwoFactorEnabled() && user.getTwoFactorSecret() == null) {
            // Create a new Google Authenticator instance
            GoogleAuthenticator gAuth = new GoogleAuthenticator();
            // Generate a new secret key for two-factor authentication
            String twoFactorSecret = gAuth.createCredentials().getKey();

            try {
                // Encrypt the secret key using the EncryptionConfig class
                String[] encryptedData = encryptionConfig.encrypt(twoFactorSecret);
                
                // Store encrypted data in the user entity
                user.setTwoFactorSecret(encryptedData[0]);
                user.setTwoFactorSecretKey(encryptedData[1]);
                user.setTwoFactorSecretIV(encryptedData[2]);

            } catch (Exception e) {
                // Handle any exceptions during encryption (e.g., logging)
                e.printStackTrace();
            }

            // Generate recovery codes for the user
            Set<String> recoveryCodes = RecoveryCodeGenerator.generateRecoveryCodes(5);
            // Save the recovery codes to the database
            recoveryCodeService.saveRecoveryCodes(user, recoveryCodes);
        }

        // Encrypt the user's password before saving it to the database
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        // Save the user entity to the repository (database)
        userRepository.save(user);
    }

    /**
     * Finds a user in the database by their username.
     *
     * @param username the username to search for
     * @return the User object if found, otherwise null
     */
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Retrieves the currently authenticated user from the security context.
     *
     * @return the User object representing the currently authenticated user, or null if not authenticated
     */
    public User getCurrentUser() {
        // Get the current authentication object from the security context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;  // Return null if no user is authenticated
        }

        String username = null;
        Object principal = authentication.getPrincipal();
        // Determine the username from the principal object
        if (principal instanceof UserDetails) {
            username = ((UserDetails) principal).getUsername();
        } else {
            username = principal.toString();
        }

        // Find and return the User object based on the username
        return findByUsername(username);
    }
}
