package springsecurity.mfa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;

import springsecurity.mfa.config.EncryptionConfig;
import springsecurity.mfa.config.RecoveryCodeGenerator;
import springsecurity.mfa.model.User;
import springsecurity.mfa.service.UserService;
import springsecurity.mfa.service.RecoveryCodeService;

import java.util.Set;

@Controller
public class RegistrationController {

    @Autowired
    private UserService userService;

    @Autowired
    private RecoveryCodeService recoveryCodeService;

    @Autowired
    private EncryptionConfig encryptionConfig;

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        return "register"; 
    }

    @PostMapping("/register")
    public String registerUserAccount(@ModelAttribute("user") User user, Model model) {
        try {
            // Generate a secret key for the user
            GoogleAuthenticator gAuth = new GoogleAuthenticator();
            final GoogleAuthenticatorKey gAuthKey = gAuth.createCredentials();

            // Encrypt the secret key before saving it
            String[] encryptedData = encryptionConfig.encrypt(gAuthKey.getKey());
            user.setTwoFactorSecret(encryptedData[0]);
            user.setTwoFactorSecretKey(encryptedData[1]);
            user.setTwoFactorSecretIV(encryptedData[2]);

            // Set the user to have 2FA enabled
            user.setTwoFactorEnabled(true);

            // Save the user with 2FA enabled (before recovery codes)
            userService.save(user);
            
            // Generate recovery codes
            Set<String> recoveryCodes = RecoveryCodeGenerator.generateRecoveryCodes(5);
            recoveryCodeService.saveRecoveryCodes(user, recoveryCodes);
            
            // Generate the QR code URL
            String qrCodeUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL("MyApp", user.getUsername(), gAuthKey);
            model.addAttribute("qrCodeUrl", qrCodeUrl);
            model.addAttribute("twoFactorSecret", gAuthKey.getKey()); // This should still be the original key for display
            model.addAttribute("recoveryCodes", recoveryCodes);

            // Redirect to the 2FA setup page
            return "2fa-setup";

        } catch (Exception e) {
            e.printStackTrace();
            // Handle any exceptions
            model.addAttribute("error", "An error occurred during registration.");
            return "register";
        }
    }
}
