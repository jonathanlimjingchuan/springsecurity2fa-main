package springsecurity.mfa.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import springsecurity.mfa.model.RecoveryCode;
import springsecurity.mfa.model.User;
import springsecurity.mfa.repository.RecoveryCodeRepository;

import java.util.Set;

@Service
public class RecoveryCodeService {

    // Injecting the RecoveryCodeRepository to interact with the database
    private final RecoveryCodeRepository recoveryCodeRepository;

    // Initializing BCryptPasswordEncoder to hash and verify recovery codes
    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    // Constructor for dependency injection of RecoveryCodeRepository
    @Autowired
    public RecoveryCodeService(RecoveryCodeRepository recoveryCodeRepository) {
        this.recoveryCodeRepository = recoveryCodeRepository;
    }

    /**
     * Saves a set of recovery codes for a user. Each code is hashed before saving
     * to ensure that only the hashed version is stored in the database.
     *
     * @param user          the user to whom the recovery codes belong
     * @param recoveryCodes the set of recovery codes to be saved
     */
    public void saveRecoveryCodes(User user, Set<String> recoveryCodes) {
        // Iterate over each recovery code in the provided set
        for (String code : recoveryCodes) {
            RecoveryCode recoveryCode = new RecoveryCode();
            // Hash the code using BCryptPasswordEncoder before saving
            String hashedCode = bCryptPasswordEncoder.encode(code);
            recoveryCode.setCode(hashedCode);
            recoveryCode.setUser(user);
            // Save the hashed recovery code to the database
            recoveryCodeRepository.save(recoveryCode);
        }
    }

    /**
     * Finds a recovery code for a user by comparing the raw input code with the stored hashed codes.
     *
     * @param rawCode the raw recovery code input by the user
     * @param user    the user who owns the recovery codes
     * @return the matched RecoveryCode object, or null if no match is found
     */
    public RecoveryCode findByCodeAndUser(String rawCode, User user) {
        // Retrieve all recovery codes associated with the user
        Set<RecoveryCode> userRecoveryCodes = user.getRecoveryCodes();
        // Iterate over the user's recovery codes
        for (RecoveryCode recoveryCode : userRecoveryCodes) {
            // Compare the raw code with the hashed code using BCryptPasswordEncoder
            if (bCryptPasswordEncoder.matches(rawCode, recoveryCode.getCode())) {
                return recoveryCode;  // Return the matched recovery code if found
            }
        }
        return null;  // Return null if no match is found
    }

    /**
     * Deletes a recovery code from the database. This is typically done after a code has been used.
     *
     * @param code the RecoveryCode object to be deleted
     */
    @Transactional  // Ensures that the delete operation is handled within a transaction
    public void delete(RecoveryCode code) {
        if (code != null) {
            // Log the deletion of the recovery code for debugging purposes
            System.out.println("Deleting recovery code with ID: " + code.getId());
            // Delete the recovery code from the database using its ID
            recoveryCodeRepository.deleteById(code.getId());
        } else {
            // Log a message if the code to delete is null
            System.out.println("Recovery code is null, nothing to delete.");
        }
    }
}
