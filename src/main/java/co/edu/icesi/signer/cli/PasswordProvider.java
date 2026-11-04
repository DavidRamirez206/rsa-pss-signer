package co.edu.icesi.signer.cli;

import java.io.IOException;

/** Source of passwords. A password is always a {@code char[]} and never a command-line argument. */
@FunctionalInterface
public interface PasswordProvider {

    /**
     * Reads a password. The caller owns the returned array and clears it after use.
     *
     * @throws IOException if no password can be read safely
     */
    char[] readPassword(String prompt) throws IOException;

    /**
     * Reads from the console without echo. Without a console (for example in an IDE)
     * it refuses, instead of falling back to input that would show the password.
     */
    static PasswordProvider console() {
        return prompt -> {
            java.io.Console console = System.console();
            if (console == null) {
                throw new IOException("No console available to read the password; run from a real terminal");
            }
            char[] password = console.readPassword("%s: ", prompt);
            if (password == null) {
                throw new IOException("No password was entered");
            }
            return password;
        };
    }
}
