package springsecurity.mfa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import springsecurity.mfa.model.RecoveryCode;
import springsecurity.mfa.model.User;
import springsecurity.mfa.service.RecoveryCodeService;
import springsecurity.mfa.service.UserService;

@Controller
public class RecoveryCodeController {

    @Autowired
    private UserService userService;

    @Autowired
    private RecoveryCodeService recoveryCodeService;

    // GET method to display the recovery code page
    @GetMapping("/recovery-code")
    public String showRecoveryCodePage() {
        return "recovery-code";
    }

    // POST method to handle recovery code submission
    @PostMapping("/recovery-code")
    public String verifyRecoveryCode(String recoveryCode, Model model) {
        User user = userService.getCurrentUser();

        RecoveryCode code = recoveryCodeService.findByCodeAndUser(recoveryCode, user);
        if (code != null) {
            // Mark recovery code as used
            recoveryCodeService.delete(code);

            // Login the user
            return "redirect:/hello";
        } else {
            model.addAttribute("error", "Invalid recovery code");
            return "recovery-code";
        }
    }
}
