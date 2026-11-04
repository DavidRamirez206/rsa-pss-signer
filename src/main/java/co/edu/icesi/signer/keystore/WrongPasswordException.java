package co.edu.icesi.signer.keystore;

/** The password does not open the private key file. Reported without a stack trace. */
public final class WrongPasswordException extends Exception {

    private static final long serialVersionUID = 1L;

    public WrongPasswordException() {
        super("Wrong password for the private key");
    }
}
