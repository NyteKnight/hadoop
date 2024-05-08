package org.apache.hadoop.security.token.delegation;

import org.apache.hadoop.security.token.Token;


/**
 * Interface for token identifiers that bundle information for additional tokens.
 * This works around an existing limitation in delegation token selectors, which
 * can only send one token to the service for authentication.
 */
public interface BundledTokenIdentifier {
  // Whether the token identifier contains information for additional tokens.
  boolean hasInnerTokens();
  
  // The number of additional tokens that the token identifier bundles.
  int getInnerTokensLength();
  
  // The password of the main token to use during SASL handshake.
  byte[] getMainPassword();
  
  // The bundled information for additional tokens.
  Token[] getInnerTokens();

  // The SPIFFE tokens
  Token[] getSPIFFETokens();
}
