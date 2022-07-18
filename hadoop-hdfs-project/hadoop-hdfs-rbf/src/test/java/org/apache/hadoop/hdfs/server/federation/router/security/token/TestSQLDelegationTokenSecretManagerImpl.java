package org.apache.hadoop.hdfs.server.federation.router.security.token;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.delegation.AbstractDelegationTokenIdentifier;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenManager;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestSQLDelegationTokenSecretManagerImpl {
  private static final String CONNECTION_URL = "jdbc:derby:memory:TokenStore";

  @Before
  public void init() throws SQLException {
    createTestDBTables();
  }

  @After
  public void cleanup() throws SQLException {
    dropTestDBTables();
  }

  @BeforeClass
  public static void initDatabase() throws SQLException {
    DriverManager.getConnection(CONNECTION_URL + ";create=true");
  }

  @AfterClass
  public static void cleanupDatabase() {
    try {
      DriverManager.getConnection(CONNECTION_URL + ";drop=true");
    } catch (SQLException e) {
      // SQLException expected when database is dropped
      if (!e.getMessage().contains("dropped")) {
        throw new RuntimeException(e);
      }
    }
  }

  @Test
  public void testSequenceNumAllocation() throws Exception {
    int tokensPerManager = SQLDelegationTokenSecretManagerImpl.DEFAULT_SEQ_NUM_BATCH_SIZE * 5;
    Set<Integer> sequenceNums1 = new HashSet<>();
    Set<Integer> sequenceNums2 = new HashSet<>();
    Set<Integer> sequenceNums3 = new HashSet<>();
    Set<Integer> sequenceNums = new HashSet<>();
    DelegationTokenManager tokenManager1 = createTokenManager();
    DelegationTokenManager tokenManager2 = createTokenManager();
    DelegationTokenManager tokenManager3 = createTokenManager();

    for (int i = 0; i < tokensPerManager; i++) {
      allocateSequenceNum(tokenManager1, sequenceNums1);
      allocateSequenceNum(tokenManager2, sequenceNums2);
      allocateSequenceNum(tokenManager3, sequenceNums3);
      sequenceNums.addAll(sequenceNums1);
      sequenceNums.addAll(sequenceNums2);
      sequenceNums.addAll(sequenceNums3);
    }

    Assert.assertEquals("Verify that all tokens were created with unique sequence numbers",
        tokensPerManager * 3, sequenceNums.size());
    Assert.assertEquals("Verify that tokenManager1 generated unique sequence numbers",
        tokensPerManager, sequenceNums1.size());
    Assert.assertEquals("Verify that tokenManager2 generated unique sequence number",
        tokensPerManager, sequenceNums2.size());
    Assert.assertEquals("Verify that tokenManager3 generated unique sequence numbers",
        tokensPerManager, sequenceNums3.size());

    // Validate sequence number batches allocated in order to each token manager
    int batchSize = SQLDelegationTokenSecretManagerImpl.DEFAULT_SEQ_NUM_BATCH_SIZE;
    for (int seqNum = 1; seqNum < tokensPerManager;) {
      // First batch allocated tokenManager1
      for (int i = 0; i < batchSize; i++, seqNum++) {
        Assert.assertTrue(sequenceNums1.contains(seqNum));
      }
      // Second batch allocated tokenManager2
      for (int i = 0; i < batchSize; i++, seqNum++) {
        Assert.assertTrue(sequenceNums2.contains(seqNum));
      }
      // Third batch allocated tokenManager3
      for (int i = 0; i < batchSize; i++, seqNum++) {
        Assert.assertTrue(sequenceNums3.contains(seqNum));
      }
    }

    TestDTSM secretManager = (TestDTSM) tokenManager1.getDelegationTokenSecretManager();
    Assert.assertEquals("Verify that the counter is set to the highest sequence number",
        tokensPerManager * 3, secretManager.getDelegationTokenSeqNum());
  }

  @Test
  public void testSequenceNumRollover() throws Exception {
    int tokenBatch = SQLDelegationTokenSecretManagerImpl.DEFAULT_SEQ_NUM_BATCH_SIZE;
    Set<Integer> sequenceNums = new HashSet<>();

    DelegationTokenManager tokenManager = createTokenManager();
    TestDTSM secretManager = (TestDTSM) tokenManager.getDelegationTokenSecretManager();
    secretManager.setDelegationTokenSeqNum(Integer.MAX_VALUE - tokenBatch);

    // Allocate sequence numbers before they are rolled over
    for (int seqNum = Integer.MAX_VALUE - tokenBatch; seqNum < Integer.MAX_VALUE; seqNum++) {
      allocateSequenceNum(tokenManager, sequenceNums);
      Assert.assertTrue(sequenceNums.contains(seqNum + 1));
    }

    // Allocate sequence numbers after they are rolled over
    for (int seqNum = 0; seqNum < tokenBatch; seqNum++) {
      allocateSequenceNum(tokenManager, sequenceNums);
      Assert.assertTrue(sequenceNums.contains(seqNum + 1));
    }
  }

  @Test
  public void testDelegationKeyAllocation() throws Exception {
    DelegationTokenManager tokenManager1 = createTokenManager();
    TestDTSM secretManager1 = (TestDTSM) tokenManager1.getDelegationTokenSecretManager();
    // Prevent delegation keys to roll for the rest of the test to avoid race conditions
    // between the keys generated and the active keys in the database.
    secretManager1.stopKeyRoll();
    int keyId1 = secretManager1.getCurrentKeyId();

    // Validate that latest key1 is assigned to tokenManager1 tokens
    Token token1 = tokenManager1.createToken(UserGroupInformation.getCurrentUser(), "foo");
    validateKeyId(token1, keyId1);

    DelegationTokenManager tokenManager2 = createTokenManager();
    TestDTSM secretManager2 = (TestDTSM) tokenManager2.getDelegationTokenSecretManager();
    // Prevent delegation keys to roll for the rest of the test
    secretManager2.stopKeyRoll();
    int keyId2 = secretManager2.getCurrentKeyId();

    Assert.assertNotEquals("Each secret manager has its own key", keyId1, keyId2);

    // Validate that latest key2 is assigned to tokenManager2 tokens
    Token token2 = tokenManager2.createToken(UserGroupInformation.getCurrentUser(), "foo");
    validateKeyId(token2, keyId2);

    // Validate that key1 is still assigned to tokenManager1 tokens
    token1 = tokenManager1.createToken(UserGroupInformation.getCurrentUser(), "foo");
    validateKeyId(token1, keyId1);

    // Validate that key2 is still assigned to tokenManager2 tokens
    token2 = tokenManager2.createToken(UserGroupInformation.getCurrentUser(), "foo");
    validateKeyId(token2, keyId2);
  }

  private DelegationTokenManager createTokenManager() {
    DelegationTokenManager tokenManager = new DelegationTokenManager(new Configuration(), null);
    tokenManager.setExternalDelegationTokenSecretManager(new TestDTSM());
    return tokenManager;
  }

  private void allocateSequenceNum(DelegationTokenManager tokenManager, Set<Integer> sequenceNums) throws IOException {
    Token token = tokenManager.createToken(UserGroupInformation.getCurrentUser(), "foo");
    AbstractDelegationTokenIdentifier tokenIdentifier = (AbstractDelegationTokenIdentifier) token.decodeIdentifier();
    Assert.assertFalse("Verify sequence number is unique", sequenceNums.contains(tokenIdentifier.getSequenceNumber()));

    sequenceNums.add(tokenIdentifier.getSequenceNumber());
  }

  private void validateKeyId(Token token, int expectedKeyiD) throws IOException {
    AbstractDelegationTokenIdentifier tokenIdentifier = (AbstractDelegationTokenIdentifier) token.decodeIdentifier();
    Assert.assertEquals("Verify that keyId is assigned to token", tokenIdentifier.getMasterKeyId(), expectedKeyiD);
  }

  private static Connection getTestDBConnection() {
    try {
      return DriverManager.getConnection(CONNECTION_URL);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static void createTestDBTables() throws SQLException {
    execute("CREATE TABLE LastSequenceNum (sequenceNum INT NOT NULL)");
    execute("INSERT INTO LastSequenceNum VALUES (0)");
    execute("CREATE TABLE LastDelegationKeyId (keyId INT NOT NULL)");
    execute("INSERT INTO LastDelegationKeyId VALUES (0)");
  }

  private static void dropTestDBTables() throws SQLException {
    execute("DROP TABLE LastSequenceNum");
    execute("DROP TABLE LastDelegationKeyId");
  }

  private static void execute(String statement) throws SQLException {
    try (Connection connection = getTestDBConnection()) {
      connection.createStatement().execute(statement);
    }
  }

  static class TestDTSM extends SQLDelegationTokenSecretManagerImpl {
    private Lock keyRollLock = new ReentrantLock();

    public TestDTSM() {
      super(new Configuration(), new TestConnectionFactory());
    }

    // Tests can call this method to prevent delegation keys from
    // being rolled in the middle of a test to prevent race conditions
    public void stopKeyRoll() {
      keyRollLock.lock();
    }

    @Override
    protected void rollMasterKey() throws IOException {
      try {
        keyRollLock.lock();
        super.rollMasterKey();
      } finally {
        keyRollLock.unlock();
      }
    }
  }

  static class TestConnectionFactory implements SQLConnectionFactory {
    @Override
    public Connection getConnection() {
      return getTestDBConnection();
    }
  }
}
