package org.apache.hadoop.security.token.loadtest;

import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.hadoop.security.UserGroupInformation;


/**
 * Implementation of {@link TokenAction} to request delegation tokens
 * and make them available to the {@link CancelTokens} action.
 */
public class PreloadTokens extends RequestTokens {
  private final LinkedBlockingQueue<UgiTokens> tokensToCancel;
  private final int tokensToCancelSize;

  public PreloadTokens(URI fileSystemUri, UserGroupInformation[] proxyUgis, int tokensToCancelSize,
      LinkedBlockingQueue<UgiTokens> tokensToRenew, LinkedBlockingQueue<UgiTokens> tokensToCancel) {
    super(fileSystemUri, Double.MAX_VALUE, proxyUgis, tokensToRenew, new AtomicLong(), new AtomicBoolean());
    this.tokensToCancelSize = tokensToCancelSize;
    this.tokensToCancel = tokensToCancel;
  }

  /**
   * Requests delegation tokens for the selected UGI and
   * adds them to the UgiTokens object, until the expected
   * amount of delegation tokens have been obtained.
   * @param ugiTokens Object where tokens will be stored.
   */
  @Override
  PrivilegedExceptionAction<Void> getAction(UgiTokens ugiTokens) {
    return () -> {
      if (tokensToCancel.size() >= tokensToCancelSize) {
        markComplete();
      } else {
        addDelegationTokens(ugiTokens);
        tokensToCancel.add(ugiTokens);
      }
      return null;
    };
  }
}
