package org.apache.hadoop.hdfs.security.token.delegation;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.Objects;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.WritableUtils;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.TokenIdentifier;


/**
 * A {@link TokenIdentifier} for the SPIFFE-based auth tokens.
 * This is essentially a wrapper for the actual SPIFFE token which follows
 * the JWT format.
 * This API could evolve to contain additional metadata fields associated
 * with the underlying identity of the SPIFFE token.
 */
public class SPIFFEDelegationTokenIdentifier extends TokenIdentifier {

  private static final byte VERSION = 0;

  public static final Text SPIFFE_DELEGATION_KIND =
      new Text("SPIFFE_DELEGATION_TOKEN");

  // The version of the token
  private byte version;

  // The raw base64url-encoded String header of the SPIFFE JWT.
  private String spiffeTokenHeader;

  // The raw base64url-encoded String payload of the SPIFFE JWT.
  private String spiffeTokenPayload;

  public SPIFFEDelegationTokenIdentifier() {

  }

  public SPIFFEDelegationTokenIdentifier(
      String spiffeTokenHeader,
      String spiffeTokenPayload) {
    this.version = VERSION;
    this.spiffeTokenHeader = spiffeTokenHeader;
    this.spiffeTokenPayload = spiffeTokenPayload;
  }

  /**
   * The raw Base 64 URL encoded string of the SPIFFE JWT header.
   */
  public String getSpiffeTokenHeader() {
    return spiffeTokenHeader;
  }

  /**
   * The raw Base 64 URL encoded string of the SPIFFE JWT payload.
   */
  public String getSpiffeTokenPayload() {
    return spiffeTokenPayload;
  }

  @Override
  public void write(DataOutput out) throws IOException {
    out.writeByte(VERSION);
    WritableUtils.writeString(out, this.spiffeTokenHeader);
    WritableUtils.writeString(out, this.spiffeTokenPayload);
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    this.version = in.readByte();
    this.spiffeTokenHeader = WritableUtils.readString(in);
    this.spiffeTokenPayload = WritableUtils.readString(in);
  }

  @Override
  public Text getKind() {
    return SPIFFE_DELEGATION_KIND;
  }

  // SPIFFE Delegation Tokens are not real Hadoop Delegation Tokens
  // so there is no associated UGI with it.
  @Override
  public UserGroupInformation getUser() {
    return null;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj instanceof SPIFFEDelegationTokenIdentifier) {
      SPIFFEDelegationTokenIdentifier that = (SPIFFEDelegationTokenIdentifier) obj;
      return isEqual(this.spiffeTokenHeader, that.spiffeTokenHeader)
          && isEqual(this.spiffeTokenPayload, that.spiffeTokenPayload);
    }
    return false;
  }
  @Override
  public int hashCode() {
    return Objects.hash(spiffeTokenHeader, spiffeTokenPayload);
  }

  protected static boolean isEqual(Object a, Object b) {
    return a == null ? b == null : a.equals(b);
  }
}
