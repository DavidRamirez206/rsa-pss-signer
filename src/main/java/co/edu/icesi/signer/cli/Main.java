package co.edu.icesi.signer.cli;

import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.policy.LocalState;
import java.time.Clock;

/** Program entry point. Anything unexpected ends in exit code 2, never in 0. */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        int exitCode;
        try {
            exitCode = new Cli(PasswordProvider.console(), System.out, System.err,
                    new PrivateKeyStore(), Clock.systemDefaultZone(), LocalState.fromEnvironment()).run(args);
        } catch (RuntimeException | Error e) {
            System.err.println("Unexpected error: " + e);
            exitCode = VerificationResult.ERROR.exitCode();
        }
        System.exit(exitCode);
    }
}
