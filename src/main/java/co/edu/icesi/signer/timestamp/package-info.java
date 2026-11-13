/**
 * A toy time-stamping authority: a third party with its own key pair signs "this
 * signature existed at this time". The date is then no longer set by the signer alone,
 * but trust moves to the authority's clock and key. Real authorities follow RFC 3161.
 */
package co.edu.icesi.signer.timestamp;
