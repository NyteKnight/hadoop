package org.apache.hadoop.security.token.delegation;

import java.sql.SQLException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenManager;


/**
 * An implementation of {@link AbstractDelegationTokenSecretManager} that
 * persists TokenIdentifiers and DelegationKeys in an existing SQL database.
 */
public abstract class SQLDelegationTokenSecretManager<TokenIdent
    extends AbstractDelegationTokenIdentifier>
    extends AbstractDelegationTokenSecretManager<TokenIdent> {

  public static final String SQL_DTSM_CONF_PREFIX = "sql-dt-secret-manager.";
  private static final String SQL_DTSM_TOKEN_SEQNUM_BATCH_SIZE = SQL_DTSM_CONF_PREFIX
      + "token.seqnum.batch.size";
  public static final int DEFAULT_SEQ_NUM_BATCH_SIZE = 10;

  // Batch of sequence numbers that will be requested by the sequenceNumCounter.
  // A new batch is requested once the sequenceNums available to a secret manager are
  // exhausted, including during initialization.
  private final int seqNumBatchSize;

  // Last sequenceNum in the current batch that has been allocated to a token.
  private int currentSeqNum;

  // Max sequenceNum in the current batch that can be allocated to a token.
  // Unused sequenceNums in the current batch cannot be reused by other routers.
  private int currentMaxSeqNum;

  public SQLDelegationTokenSecretManager(Configuration conf) {
    super(conf.getLong(DelegationTokenManager.UPDATE_INTERVAL,
            DelegationTokenManager.UPDATE_INTERVAL_DEFAULT) * 1000,
        conf.getLong(DelegationTokenManager.MAX_LIFETIME,
            DelegationTokenManager.MAX_LIFETIME_DEFAULT) * 1000,
        conf.getLong(DelegationTokenManager.RENEW_INTERVAL,
            DelegationTokenManager.RENEW_INTERVAL_DEFAULT) * 1000,
        conf.getLong(DelegationTokenManager.REMOVAL_SCAN_INTERVAL,
            DelegationTokenManager.REMOVAL_SCAN_INTERVAL_DEFAULT) * 1000);

    this.seqNumBatchSize = conf.getInt(SQL_DTSM_TOKEN_SEQNUM_BATCH_SIZE,
        DEFAULT_SEQ_NUM_BATCH_SIZE);
  }

  /**
   * Obtains the value of the last reserved sequence number.
   * @return Last reserved sequence number.
   */
  @Override
  public int getDelegationTokenSeqNum() {
    try {
      return selectSequenceNum();
    } catch (SQLException e) {
      throw new RuntimeException(
          "Failed to get token sequence number in SQL secret manager", e);
    }
  }

  /**
   * Updates the value of the last reserved sequence number.
   * @param seqNum Value to update the sequence number to.
   */
  @Override
  public void setDelegationTokenSeqNum(int seqNum) {
    try {
      updateSequenceNum(seqNum);
    } catch (SQLException e) {
      throw new RuntimeException(
          "Failed to update token sequence number in SQL secret manager", e);
    }
  }

  /**
   * Obtains the next available sequence number that can be allocated to a Token.
   * Sequence numbers need to be reserved using the shared sequenceNumberCounter once
   * the local batch has been exhausted, which handles sequenceNumber allocation
   * concurrently with other secret managers.
   * This method ensures that sequence numbers are incremental in a single secret manager,
   * but not across secret managers.
   * @return Next available sequence number.
   */
  @Override
  public synchronized int incrementDelegationTokenSeqNum() {
    if (currentSeqNum >= currentMaxSeqNum) {
      try {
        // Request a new batch of sequence numbers and use the
        // lowest one available.
        currentSeqNum = incrementSequenceNum(seqNumBatchSize);
        currentMaxSeqNum = currentSeqNum + seqNumBatchSize;
      } catch (SQLException e) {
        throw new RuntimeException(
            "Failed to increment token sequence number in SQL secret manager", e);
      }
    }

    return ++currentSeqNum;
  }

  /**
   * Obtains the value of the last delegation key id.
   * @return Last delegation key id.
   */
  @Override
  public int getCurrentKeyId() {
    try {
      return selectKeyId();
    } catch (SQLException e) {
      throw new RuntimeException(
          "Failed to get delegation key id in SQL secret manager", e);
    }
  }

  /**
   * Updates the value of the last delegation key id.
   * @param keyId Value to update the delegation key id to.
   */
  @Override
  public void setCurrentKeyId(int keyId) {
    try {
      updateKeyId(keyId);
    } catch (SQLException e) {
      throw new RuntimeException(
          "Failed to set delegation key id in SQL secret manager", e);
    }
  }

  /**
   * Obtains the next available delegation key id that can be allocated to a DelegationKey.
   * Delegation key id need to be reserved using the shared delegationKeyIdCounter,
   * which handles keyId allocation concurrently with other secret managers.
   * @return Next available delegation key id.
   */
  @Override
  public int incrementCurrentKeyId() {
    try {
      return incrementKeyId(1) + 1;
    } catch (SQLException e) {
      throw new RuntimeException(
          "Failed to increment delegation key id in SQL secret manager", e);
    }
  }

  // Counter operations in SQL database
  protected abstract int selectSequenceNum() throws SQLException;
  protected abstract void updateSequenceNum(int value) throws SQLException;
  protected abstract int incrementSequenceNum(int amount) throws SQLException;
  protected abstract int selectKeyId() throws SQLException;
  protected abstract void updateKeyId(int value) throws SQLException;
  protected abstract int incrementKeyId(int amount) throws SQLException;
}
