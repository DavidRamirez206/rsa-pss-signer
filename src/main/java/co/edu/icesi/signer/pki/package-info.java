/**
 * A minimal certificate authority: it signs X.509 certificates that bind a signer's name
 * to a public key, so the verifier trusts the authority instead of each key. Trust moves
 * to the authority: if it issues a false certificate, everything that relies on it falls.
 */
package co.edu.icesi.signer.pki;
