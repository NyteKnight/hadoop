package org.apache.hadoop.security.token.loadtest;

import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;


/**
 * Class to associate a UGI for a test user with the tokens requested for
 * the same user. This is required given that tokens can only be renewed and
 * cancelled by the user allowed to do so when requesting tokens.
 */
public class UgiTokens {
  private final UserGroupInformation ugi;
  private Token<?>[] tokens;

  public UgiTokens(UserGroupInformation ugi) {
    this.ugi = ugi;
  }

  public void setTokens(Token<?>[] tokens) {
    this.tokens = tokens;
  }

  public Token<?>[] getTokens() {
    return this.tokens;
  }

  public UserGroupInformation getUgi() {
    return this.ugi;
  }
}
