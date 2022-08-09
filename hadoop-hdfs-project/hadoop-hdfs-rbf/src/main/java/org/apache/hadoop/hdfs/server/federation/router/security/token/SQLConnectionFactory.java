package org.apache.hadoop.hdfs.server.federation.router.security.token;

import com.mysql.cj.jdbc.MysqlDataSource;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.SQLException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.token.delegation.SQLDelegationTokenSecretManager;


/**
 * Interface to provide SQL connections to the {@link SQLDelegationTokenSecretManagerImpl}
 */
public interface SQLConnectionFactory {
  String CONNECTION_URL = SQLDelegationTokenSecretManager.SQL_DTSM_CONF_PREFIX
      + "connection.url";
  String CONNECTION_USERNAME = SQLDelegationTokenSecretManager.SQL_DTSM_CONF_PREFIX
      + "connection.username";
  String CONNECTION_PASSWORD = SQLDelegationTokenSecretManager.SQL_DTSM_CONF_PREFIX
      + "connection.password";
  String CONNECTION_DRIVER = SQLDelegationTokenSecretManager.SQL_DTSM_CONF_PREFIX
      + "connection.driver";

  Connection getConnection() throws SQLException;

  default Connection getConnection(boolean autocommit) throws SQLException {
    Connection connection = getConnection();
    connection.setAutoCommit(autocommit);
    return connection;
  }
}

/**
 * Class that relies on a MysqlDataSource to provide SQL connections.
 */
class MysqlDataSourceConnectionFactory implements SQLConnectionFactory {
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

/**
 * Class that relies on a HikariDataSource to provide SQL connections.
 */
class HikariDataSourceConnectionFactory implements SQLConnectionFactory {
  private final HikariDataSource dataSource;

  public HikariDataSourceConnectionFactory(Configuration conf) {
    this.dataSource = new HikariDataSource();
    this.dataSource.setJdbcUrl(conf.get(CONNECTION_URL));
    this.dataSource.setUsername(conf.get(CONNECTION_USERNAME));
    this.dataSource.setPassword(conf.get(CONNECTION_PASSWORD));
    this.dataSource.setDriverClassName(conf.get(CONNECTION_DRIVER));
  }

  @Override
  public Connection getConnection() throws SQLException {
    return dataSource.getConnection();
  }
}
