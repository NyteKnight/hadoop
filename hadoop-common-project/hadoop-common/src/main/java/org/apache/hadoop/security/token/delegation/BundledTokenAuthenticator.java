package org.apache.hadoop.security.token.delegation;

import java.io.IOException;
import org.apache.hadoop.metrics2.annotation.Metric;
import org.apache.hadoop.metrics2.annotation.Metrics;
import org.apache.hadoop.metrics2.lib.DefaultMetricsSystem;
import org.apache.hadoop.metrics2.lib.MetricsRegistry;
import org.apache.hadoop.metrics2.lib.MutableRate;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.hadoop.util.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Token authenticator that evaluates innerTokens in a BundledTokenIdentifier. This
 * will iterate through the innerTokens until one is found in the secret manager
 * token store.
 * The client is responsible for listing the innerTokens in the optimal order. 
 */
public class BundledTokenAuthenticator {
  public static final Logger LOG = LoggerFactory.getLogger(BundledTokenAuthenticator.class);
  private static final BundledTokenAuthenticatorMetrics METRICS
      = BundledTokenAuthenticatorMetrics.create();
  private BundledTokenIdentifier bundledTokenIdentifier;
  private boolean hasInnerTokens;
  private TokenVerifierFunction verifyFunction;

  @FunctionalInterface
  public interface TokenVerifierFunction {
    void execute(TokenIdentifier innerToken, byte[] innerPassword) throws IOException;
  }
  
  public BundledTokenAuthenticator(TokenIdentifier tokenIdentifier, TokenVerifierFunction verifyFunction) {
    if (tokenIdentifier instanceof BundledTokenIdentifier) {
      this.bundledTokenIdentifier = (BundledTokenIdentifier) tokenIdentifier;
      this.hasInnerTokens = this.bundledTokenIdentifier.hasInnerTokens();
      this.verifyFunction = verifyFunction;
    }
  }

  /**
   * Evaluates whether any innerTokens were found in the BundledTokenIdentifier.
   * @return whether innerTokens were found in the BundledTokenIdentifier.
   */
  public boolean hasInnerTokens() {
    return this.hasInnerTokens;
  }

  /**
   * Gets the password for the main token in the BundledTokenIdentifier.
   * @return password as a byte array.
   */
  public byte[] getMainTokenPassword() {
    return this.bundledTokenIdentifier.getMainPassword();
  }

  /**
   * Evaluate the innerTokens in the BundledTokenIdentifier until one of them is
   * found in the secret manager token store. It will execute a user provided function
   * to evaluate the correctness of the found token (e.g. password match).
   * @return TokenIdentifier found in the secret manager token store, if passed the
   *                         verification function.
   * @throws IOException If none of the innerTokens are found in the secret manager token
   *                     store or if the found innerToken doesn't pass the verification
   *                      function. Only the first exception found will be thrown
   */
  public Token<?> extractMatchingInnerToken()
      throws IOException {
    long start = Time.monotonicNow();
    int attempts = 0;
    IOException firstExc = null;
    for (Token<?> innerToken : this.bundledTokenIdentifier.getInnerTokens()) {
      try {
        attempts++;
        TokenIdentifier tokenIdentifier = innerToken.decodeIdentifier();
        this.verifyFunction.execute(tokenIdentifier, innerToken.getPassword());
        
        LOG.info("Found inner token for service: {} after {} attempt(s)",
            innerToken.getService(), attempts);
        METRICS.trackInnerTokenFound(start);
        return innerToken;
      } catch (IOException it) {
        if (firstExc == null) {
          firstExc = it;
        }
      }
    }

    METRICS.trackInnerTokenNotFound(start);
    throw firstExc != null ? firstExc : new IOException("No innerTokens used for authentication");
  }

  @Metrics(about="Bundled token authenticator metrics", context="bundledtokenauth")
  static class BundledTokenAuthenticatorMetrics {
    private static final String METRICS_NAME = "BundledTokenAuthenticator";
    private final MetricsRegistry registry;

    @Metric("Found matching inner token")
    private MutableRate innerTokenFound;

    @Metric("Not found matching inner token")
    private MutableRate innerTokenNotFound;

    BundledTokenAuthenticatorMetrics() {
      this.registry = new MetricsRegistry(METRICS_NAME);
      LOG.debug(registry.info().toString());
    }

    static BundledTokenAuthenticatorMetrics create() {
      BundledTokenAuthenticatorMetrics metrics = new BundledTokenAuthenticatorMetrics();
      return DefaultMetricsSystem.instance().register(METRICS_NAME, null, metrics);
    }

    void trackInnerTokenFound(long start) {
      this.innerTokenFound.add(Time.monotonicNow() - start);
    }

    void trackInnerTokenNotFound(long start) {
      this.innerTokenNotFound.add(Time.monotonicNow() - start);
    }
  }
}
