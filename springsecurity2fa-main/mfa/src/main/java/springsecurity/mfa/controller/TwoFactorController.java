package springsecurity.mfa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import com.warrenstrange.googleauth.GoogleAuthenticator;

import springsecurity.mfa.model.User;
import springsecurity.mfa.service.UserService;
import springsecurity.mfa.config.EncryptionConfig;

@Controller
public class TwoFactorController {

    @Autowired
    private UserService userService;

    @Autowired
    private EncryptionConfig encryptionConfig;

    // Display the 2FA verification page
    @GetMapping("/2fa-verify")
    public String show2faVerificationPage(Model model) {
        return "2fa-verify";
    }

    // Handle the 2FA verification process
    @PostMapping("/2fa-verify")
    public String verify2fa(String code, Model model) {
        // Get the authenticated user's username
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        // Retrieve the user by username
        User user = userService.findByUsername(username);
        if (user == null) {
            model.addAttribute("error", "User not found");
            return "2fa-verify";
        }

        try {
            // Decrypt the secret key before using it for verification
            String decryptedSecret = encryptionConfig.decrypt(user.getTwoFactorSecret(), user.getTwoFactorSecretKey(), user.getTwoFactorSecretIV());

            // Verify the code using GoogleAuthenticator
            GoogleAuthenticator gAuth = new GoogleAuthenticator();
            boolean isCodeValid = gAuth.authorize(decryptedSecret, Integer.parseInt(code));

            if (isCodeValid) {
                return "redirect:/hello"; // Redirect to the desired page on successful verification
            } else {
                model.addAttribute("error", "Invalid verification code");
                return "2fa-verify"; // Return to the same page with an error message
            }
        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "An error occurred during verification.");
            return "2fa-verify";
        }
    }
}
