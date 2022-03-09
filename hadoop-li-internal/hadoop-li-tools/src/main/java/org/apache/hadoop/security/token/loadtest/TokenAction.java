package org.apache.hadoop.security.token.loadtest;

import java.security.PrivilegedExceptionAction;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.util.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Base class for each of the possible TokenActions (request, renew, cancel).
 * There are two operations that need to be defined for each of its implementations:
 * 1. What UGI will be used to request, renew or cancel tokens.
 * 2. How will tokens be requested, renewed or cancelled.
 */
public abstract class TokenAction implements Runnable {
  public static final Logger LOG = LoggerFactory.getLogger(TokenAction.class);

  protected final Configuration config = new Configuration();
  private final AtomicBoolean isComplete;
  private final long sleep;

  public TokenAction(double transactionsPerSecond, AtomicBoolean isComplete) {
    if (transactionsPerSecond <= 0) {
      this.sleep = 0;
      this.isComplete = new AtomicBoolean(true);
    } else {
      this.sleep = (long) (DateUtils.MILLIS_PER_SECOND / transactionsPerSecond);
      this.isComplete = isComplete;
    }
  }

  /**
   * Marks an execution as complete so the thread can exit safely.
   */
  public void markComplete() {
    this.isComplete.set(true);
  }

  @Override
  public void run() {
    try {
      while (!isComplete.get()) {
        long start = Time.monotonicNow();

        UgiTokens ugiTokens = selectUgiTokens();
        if (ugiTokens != null) {
          ugiTokens.getUgi().doAs(getAction(ugiTokens));
        }

        // Calculate the actual sleep time based on the duration of
        // the current call.
        long duration = Time.monotonicNow() - start;
        Thread.sleep(Math.max(sleep - duration, 1));
      }
    } catch (Exception ex) {
      LOG.info("TokenAction failed: " + ex.getMessage());
    }
  }

  abstract UgiTokens selectUgiTokens() throws InterruptedException;
  abstract PrivilegedExceptionAction<Void> getAction(UgiTokens ugiTokens);
}
