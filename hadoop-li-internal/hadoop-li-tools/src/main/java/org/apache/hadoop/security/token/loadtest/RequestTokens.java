package org.apache.hadoop.security.token.loadtest;

import java.io.IOException;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.Random;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;


/**
 * Implementation of {@link TokenAction} to request
 * delegation tokens, using one of the available UGIs.
 */
public class RequestTokens extends TokenAction {
  private final Random random = new Random();
  private final URI fileSystemUri;
  private final UserGroupInformation[] proxyUgis;
  private final LinkedBlockingQueue<UgiTokens> tokensToRenew;
  private final AtomicLong totalRequests;

  public RequestTokens(URI fileSystemUri, double requestsPerSecond, UserGroupInformation[] proxyUgis,
      LinkedBlockingQueue<UgiTokens> tokensToRenew, AtomicLong totalRequests, AtomicBoolean shutdown) {
    super(requestsPerSecond, shutdown);
    this.fileSystemUri = fileSystemUri;
    this.proxyUgis = proxyUgis;
    this.tokensToRenew = tokensToRenew;
    this.totalRequests = totalRequests;
  }

  /**
   * Selects a random UGI for a test user.
   * @return UgiTokens object with the selected test UGI.
   */
  @Override
  UgiTokens selectUgiTokens() {
    int ugiIndex = random.nextInt(proxyUgis.length);
    UserGroupInformation proxyUgi = proxyUgis[ugiIndex];
    return new UgiTokens(proxyUgi);
  }

  /**
   * Requests delegation tokens for the selected UGI and
   * adds them to the UgiTokens object.
   * @param ugiTokens Object where tokens will be stored.
   */
  @Override
  PrivilegedExceptionAction<Void> getAction(UgiTokens ugiTokens) {
    return () -> {
      Token<?>[] tokens = addDelegationTokens(ugiTokens);
      tokensToRenew.add(ugiTokens);
      totalRequests.addAndGet(tokens.length);
      return null;
    };
  }

  protected Token<?>[] addDelegationTokens(UgiTokens ugiTokens) throws IOException {
    try (FileSystem fs = FileSystem.newInstance(fileSystemUri, config)) {
      String renewer = ugiTokens.getUgi().getUserName();
      Token<?>[] tokens = fs.addDelegationTokens(renewer, new Credentials());
      ugiTokens.setTokens(tokens);
      return tokens;
    }
  }
}
