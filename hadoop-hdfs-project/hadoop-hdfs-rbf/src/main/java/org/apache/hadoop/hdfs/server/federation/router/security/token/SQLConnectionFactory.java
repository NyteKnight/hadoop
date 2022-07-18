package org.apache.hadoop.hdfs.server.federation.router.security.token;

import com.mysql.cj.jdbc.MysqlDataSource;
import java.sql.Connection;
import java.sql.SQLException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.token.delegation.SQLDelegationTokenSecretManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Interface to provide SQL connections to the {@link SQLDelegationTokenSecretManagerImpl}
 */
public interface SQLConnectionFactory {
  Connection getConnection() throws SQLException;
}

/**
 * Class that relies on a MysqlDataSource to provide SQL connections.
 */
class MysqlDataSourceConnectionFactory implements SQLConnectionFactory {
  public final static String CONNECTION_URL =
      SQLDelegationTokenSecretManager.SQL_DTSM_CONF_PREFIX + "connection.url";
  public final static String CONNECTION_USERNAME =
      SQLDelegationTokenSecretManager.SQL_DTSM_CONF_PREFIX + "connection.username";
  public final static String CONNECTION_PASSWORD =
      SQLDelegationTokenSecretManager.SQL_DTSM_CONF_PREFIX + "connection.password";

  private final MysqlDataSource dataSource;

  public MysqlDataSourceConnectionFactory(Configuration conf) {
    this.dataSource = new MysqlDataSource();
    this.dataSource.setUrl(conf.get(CONNECTION_URL));
    this.dataSource.setUser(conf.get(CONNECTION_USERNAME));
    this.dataSource.setPassword(conf.get(CONNECTION_PASSWORD));
  }

  @Override
  public Connection getConnection() throws SQLException {
    return dataSource.getConnection();
  }
}
