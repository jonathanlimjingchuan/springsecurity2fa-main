package springsecurity.mfa.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/home")
    public String home(Model model) {
        model.addAttribute("message", "Welcome to the home page!");
        return "home"; // This will render home.html
    }

    @GetMapping("/")
    public String root(Model model) {
        model.addAttribute("message", "Welcome to the root page!");
        return "home"; // Reusing the home.html template
    }
}
