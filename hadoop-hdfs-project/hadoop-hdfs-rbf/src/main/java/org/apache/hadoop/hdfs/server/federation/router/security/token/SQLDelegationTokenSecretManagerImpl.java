package org.apache.hadoop.hdfs.server.federation.router.security.token;

import java.io.IOException;
import java.sql.SQLException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.security.token.delegation.DelegationTokenIdentifier;
import org.apache.hadoop.security.token.delegation.AbstractDelegationTokenIdentifier;
import org.apache.hadoop.security.token.delegation.SQLDelegationTokenSecretManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An implementation of {@link SQLDelegationTokenSecretManager} that
 * persists TokenIdentifiers and DelegationKeys in a SQL database.
 * This implementation relies on the Datanucleus JDO PersistenceManager, which
 * can be configured with datanucleus.* configuration properties.
 */
public class SQLDelegationTokenSecretManagerImpl
    extends SQLDelegationTokenSecretManager<AbstractDelegationTokenIdentifier> {

  private static final Logger LOG =
      LoggerFactory.getLogger(SQLDelegationTokenSecretManagerImpl.class);
  private static final String SEQ_NUM_COUNTER_FIELD = "sequenceNum";
  private static final String SEQ_NUM_COUNTER_TABLE = "LastSequenceNum";
  private static final String KEY_ID_COUNTER_FIELD = "keyId";
  private static final String KEY_ID_COUNTER_TABLE = "LastDelegationKeyId";

  private final DistributedSQLCounter sequenceNumCounter;
  private final DistributedSQLCounter delegationKeyIdCounter;

  public SQLDelegationTokenSecretManagerImpl(Configuration conf) {
    this(conf, new MysqlDataSourceConnectionFactory(conf));
  }

  public SQLDelegationTokenSecretManagerImpl(Configuration conf,
      SQLConnectionFactory connectionFactory) {
    super(conf);

    this.sequenceNumCounter = new DistributedSQLCounter(SEQ_NUM_COUNTER_FIELD,
        SEQ_NUM_COUNTER_TABLE, connectionFactory);
    this.delegationKeyIdCounter = new DistributedSQLCounter(KEY_ID_COUNTER_FIELD,
        KEY_ID_COUNTER_TABLE, connectionFactory);

    try {
      super.startThreads();
    } catch (IOException e) {
      throw new RuntimeException("Error starting threads for MySQL secret manager", e);
    }

    LOG.info("MySQL delegation token secret manager instantiated");
  }

  @Override
  public DelegationTokenIdentifier createIdentifier() {
    return new DelegationTokenIdentifier();
  }

  @Override
  protected int selectSequenceNum() throws SQLException {
    return sequenceNumCounter.selectCounterValue();
  }

  @Override
  protected void updateSequenceNum(int value) throws SQLException {
    sequenceNumCounter.updateCounterValue(value);
  }

  @Override
  protected int incrementSequenceNum(int amount) throws SQLException {
    return sequenceNumCounter.incrementCounterValue(amount);
  }

  @Override
  protected int selectKeyId() throws SQLException {
    return delegationKeyIdCounter.selectCounterValue();
  }

  @Override
  protected void updateKeyId(int value) throws SQLException {
    delegationKeyIdCounter.updateCounterValue(value);
  }

  @Override
  protected int incrementKeyId(int amount) throws SQLException {
    return delegationKeyIdCounter.incrementCounterValue(amount);
  }
}
