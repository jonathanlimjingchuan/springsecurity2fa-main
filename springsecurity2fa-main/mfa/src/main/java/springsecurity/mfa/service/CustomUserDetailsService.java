package springsecurity.mfa.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import springsecurity.mfa.model.User;
import springsecurity.mfa.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    // Injecting the UserRepository dependency to interact with the database
    private final UserRepository userRepository;

    // Injecting the PasswordEncoder to handle password encoding
    @Autowired
    private PasswordEncoder passwordEncoder;

    // Constructor for dependency injection of UserRepository
    @Autowired
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    /**
     * Loads a user by their username. This method is called by Spring Security
     * during authentication to verify the user's credentials.
     *
     * @param username the username of the user trying to authenticate
     * @return UserDetails the security details of the authenticated user
     * @throws UsernameNotFoundException if the user is not found in the database
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Find the user by their username using the repository
        User user = userRepository.findByUsername(username);
        
        // If the user is not found, throw an exception
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        
        // Build and return a UserDetails object with the user's information
        // Spring Security uses this object for authentication and authorization
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())      // Set the username
                .password(user.getPassword())          // Set the (encoded) password
                .roles("USER")                         // Assign the "USER" role to the user
                .build();
    }

    /**
     * Saves a user in the database after encoding their password.
     * This method is used during user registration or password change.
     *
     * @param user the User object to be saved
     */
    public void saveUser(User user) {
        // Encode the user's password before saving it to the database
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        
        // Save the user to the database using the repository
        userRepository.save(user);
    }
}
