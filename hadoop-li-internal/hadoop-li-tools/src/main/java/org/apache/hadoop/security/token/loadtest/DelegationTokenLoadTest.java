package org.apache.hadoop.security.token.loadtest;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Class to generate requests for delegation tokens as part of a load test.
 * Usage from [user]-hadoop-exec-0:
 * hadoop jar hadoop-li-tools-*.jar org.apache.hadoop.security.token.loadtest.DelegationTokenLoadTest \
 * -keytabPrincipal hdfsqa -keytabPath /export/home/hdfsqa/hdfsqa.headless.keytab \
 * -fileSystemUri hdfs://[user]-hadoop/ -requestsPerSecond 250 -renewalsPerSecond 20 -cancellationsPerSecond 50
 */
public class DelegationTokenLoadTest {
  public static final Logger LOG = LoggerFactory.getLogger(DelegationTokenLoadTest.class);

  public static final Option KEYTAB_PRINCIPAL = createOption("keytabPrincipal", true,
      "The principal of the provided keytab");
  public static final Option KEYTAB_PATH = createOption("keytabPath", true,
      "Path to the keytab to login with");
  public static final Option FILESYSTEM_URI = createOption("fileSystemUri", true,
      "URI of the FileSystem to request delegation tokens from");
  public static final Option TOKEN_REQUESTS_PER_SECOND = createOption("requestsPerSecond", true,
      "Number of delegation token requests to execute per second");
  public static final Option TOKEN_RENEWALS_PER_SECOND = createOption("renewalsPerSecond", true,
      "Number of delegation token renewals to execute per second");
  public static final Option TOKEN_CANCELLATIONS_PER_SECOND = createOption("cancellationsPerSecond", true,
      "Number of delegation token renewals to execute per second");

  public static final Option USERS = new Option("users", false,
      "Number of users for which delegation tokens can be requested");
  public static final Option DURATION_IN_SECONDS = createOption("duration", false,
      "Duration in seconds of the load test run");
  public static final Option WARMUP_TOKENS_TO_CANCEL = createOption("warmupTokens", false,
      "Number of delegation tokens to request before the load test");
  public static final Option CONCURRENCY = createOption("concurrency", false,
      "Number of threads executing a specific action concurrently");

  private final static Options OPTIONS = new Options().addOption(KEYTAB_PRINCIPAL).addOption(KEYTAB_PATH)
      .addOption(FILESYSTEM_URI).addOption(TOKEN_REQUESTS_PER_SECOND).addOption(TOKEN_RENEWALS_PER_SECOND)
      .addOption(TOKEN_CANCELLATIONS_PER_SECOND).addOption(USERS).addOption(DURATION_IN_SECONDS)
      .addOption(WARMUP_TOKENS_TO_CANCEL).addOption(CONCURRENCY);

  public static void main(String[] args) throws IOException, InterruptedException {
    try {
      CommandLineParser parser = new BasicParser();
      CommandLine commandLine = parser.parse(OPTIONS, args, false);

      DelegationTokenLoadTest loadTest = new DelegationTokenLoadTest(commandLine);
      loadTest.run();
    } catch (ParseException ex) {
      HelpFormatter formatter = new HelpFormatter();
      formatter.printHelp("DelegationTokenLoadTest", OPTIONS);
    }
  }

  private static Option createOption(String opt, boolean required, String description) {
    return OptionBuilder.hasArg(true)
        .withDescription(description)
        .isRequired(required)
        .create(opt);
  }

  private final String keytabPrincipal;
  private final String keytabPath;
  private final URI fileSystemUri;
  private final double requestsPerSecondPerThread;
  private final double renewalsPerSecondPerThread;
  private final double cancellationsPerSecondPerThread;
  private final LinkedBlockingQueue<UgiTokens> tokensToRenew;
  private final LinkedBlockingQueue<UgiTokens> tokensToCancel;
  private final long durationInSeconds;
  private final int users;
  private final int warmupTokensToCancel;
  private final int concurrency;

  public DelegationTokenLoadTest(CommandLine commandLine) {
    this.keytabPrincipal = commandLine.getOptionValue(KEYTAB_PRINCIPAL.getOpt());
    this.keytabPath = commandLine.getOptionValue(KEYTAB_PATH.getOpt());
    this.fileSystemUri = URI.create(commandLine.getOptionValue(FILESYSTEM_URI.getOpt()));

    this.durationInSeconds = Long.parseLong(commandLine.getOptionValue(DURATION_IN_SECONDS.getOpt(), "10"));
    this.users = Integer.parseInt(commandLine.getOptionValue(USERS.getOpt(), "10"));
    this.warmupTokensToCancel = Integer.parseInt(commandLine.getOptionValue(WARMUP_TOKENS_TO_CANCEL.getOpt(), "100"));
    this.concurrency = Integer.parseInt(commandLine.getOptionValue(CONCURRENCY.getOpt(), "20"));

    this.requestsPerSecondPerThread = getTransactionsPerSecondPerThread(commandLine, TOKEN_REQUESTS_PER_SECOND);
    this.renewalsPerSecondPerThread = getTransactionsPerSecondPerThread(commandLine, TOKEN_RENEWALS_PER_SECOND);
    this.cancellationsPerSecondPerThread = getTransactionsPerSecondPerThread(commandLine, TOKEN_CANCELLATIONS_PER_SECOND);

    this.tokensToRenew = new LinkedBlockingQueue<>();
    this.tokensToCancel = new LinkedBlockingQueue<>();
  }

  /**
   * Prepares and starts a test load for delegation tokens, which consists of the following flow:
   * 1. Create UGIs for test users.
   * 2. Pre-generate delegation tokens so they can be used by the {@link CancelTokens} action
   *    from the beginning of the test. This allows to generate a high number of cancellations
   *    without new requests impacting the test.
   * 3. Start background threads that generate load for the following actions:
   *    a. Request new delegation tokens for a test user and add the resulting tokens to a queue that is
   *       only available to the {@link RenewTokens} action. This will allow the new tokens to be renewed.
   *    b. Renew delegation tokens generated in step 3a, using the UGI of the user that requested them
   *       originally. Once the tokens have been renewed once, they are added to a queue that is only available
   *       to the {@link CancelTokens} action. This will allow the renewed tokens to be cancelled.
   *    c. Cancel delegation tokens that were pre-generated in step 2 or already renewed in step 3b, using the
   *       UGI of the user that requested them. Once the tokens are cancelled, they will not be used anymore.
   * @throws IOException
   * @throws InterruptedException
   */
  public void run() throws IOException, InterruptedException {
    // Create UGIs for every test user that can request delegation tokens
    UserGroupInformation[] proxyUgis = createUsers();

    // Pre-generate delegation tokens that can be cancelled from the start of the test
    warmup(proxyUgis);

    // Start the actual load test
    runLoadTest(proxyUgis);
  }

  private UserGroupInformation[] createUsers() throws IOException {
    UserGroupInformation superUserUgi = UserGroupInformation.loginUserFromKeytabAndReturnUGI(keytabPrincipal, keytabPath);

    UserGroupInformation[] proxyUgis = new UserGroupInformation[users];
    for (int i = 0; i < users; i++) {
      proxyUgis[i] = UserGroupInformation.createProxyUser("user" + i, superUserUgi);
    }

    return proxyUgis;
  }

  private void warmup(UserGroupInformation[] proxyUgis) throws InterruptedException {
    LOG.info("Starting warmup");
    ExecutorService executorService = Executors.newFixedThreadPool(concurrency);

    long start = System.currentTimeMillis();
    for (int thread = 0; thread < concurrency; thread++) {
      executorService.submit(new PreloadTokens(fileSystemUri, proxyUgis, warmupTokensToCancel, tokensToRenew, tokensToCancel));
    }

    executorService.shutdown();
    executorService.awaitTermination(5, TimeUnit.MINUTES);

    LOG.info("Completed warmup in " + (System.currentTimeMillis() - start) + " ms");
    LOG.info("Generated " + tokensToCancel.size() + " tokens during warmup");
  }

  private void runLoadTest(UserGroupInformation[] proxyUgis) throws InterruptedException {
    LOG.info("Starting execution");
    ExecutorService executorService = Executors.newFixedThreadPool(concurrency * 3);

    AtomicLong totalRequests = new AtomicLong();
    AtomicLong totalRenewals = new AtomicLong();
    AtomicLong totalCancellations = new AtomicLong();
    AtomicBoolean shutdown = new AtomicBoolean();

    long start = System.currentTimeMillis();
    for (int thread = 0; thread < concurrency; thread++) {
      executorService.submit(new RequestTokens(fileSystemUri, requestsPerSecondPerThread, proxyUgis, tokensToRenew, totalRequests, shutdown));
      executorService.submit(new RenewTokens(renewalsPerSecondPerThread, tokensToRenew, tokensToCancel, totalRenewals, shutdown));
      executorService.submit(new CancelTokens(cancellationsPerSecondPerThread, tokensToCancel, totalCancellations, shutdown));
    }

    // Execution will wait here and continue if all threads fail or when the
    // given timeout is reached.
    executorService.shutdown();
    executorService.awaitTermination(durationInSeconds, TimeUnit.SECONDS);

    // Signal for every TokenAction to finish execution
    shutdown.set(true);

    LOG.info("Completed execution in  " + (System.currentTimeMillis() - start) + " ms");
    LOG.info("Total requests: " + totalRequests.get());
    LOG.info("Total renewals: " + totalRenewals.get());
    LOG.info("Total cancellations: " + totalCancellations.get());
  }

  private double getTransactionsPerSecondPerThread(CommandLine commandLine, Option option) {
    int transactionsPerSecond = Integer.parseInt(commandLine.getOptionValue(option.getOpt()));
    double transactionsPerSecondPerThread = transactionsPerSecond / (double) this.concurrency;

    if (transactionsPerSecondPerThread > DateUtils.MILLIS_PER_SECOND) {
      throw new IllegalArgumentException(String.format("Cannot generate more than 1000 transactions per second in a "
          + "single thread for option '%s'. Consider using the 'concurrency' option to increase the number of threads",
          option.getOpt()));
    }

    return transactionsPerSecondPerThread;
  }
}
