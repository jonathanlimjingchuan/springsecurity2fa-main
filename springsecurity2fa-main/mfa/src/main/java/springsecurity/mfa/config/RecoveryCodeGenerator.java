package springsecurity.mfa.config;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

public class RecoveryCodeGenerator {

    public static Set<String> generateRecoveryCodes(int numberOfCodes) {
        SecureRandom random = new SecureRandom();
        Set<String> recoveryCodes = new HashSet<>();

        for (int i = 0; i < numberOfCodes; i++) {
            recoveryCodes.add(generateCode(random));
        }

        return recoveryCodes;
    }

    private static String generateCode(SecureRandom random) {
        int codeLength = 10;
        StringBuilder code = new StringBuilder();

        for (int i = 0; i < codeLength; i++) {
            int digit = random.nextInt(10);
            code.append(digit);
        }

        return code.toString();
    }
}
