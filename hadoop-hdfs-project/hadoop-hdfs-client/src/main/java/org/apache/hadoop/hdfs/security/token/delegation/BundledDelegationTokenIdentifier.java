package org.apache.hadoop.hdfs.security.token.delegation;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.WritableUtils;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.delegation.AbstractDelegationTokenIdentifier;
import org.apache.hadoop.security.token.delegation.BundledTokenIdentifier;


/**
 * BundledTokenIdentifier to use for HDFS delegation tokens.
 * The attributes inherited from the DelegationTokenIdentifier class have the same behavior as
 * before.
 * The attributes introduced in this class are only used by servers that know how to handle them.
 * This class is fully compatible with DelegationTokenIdentifiers, such that a client creating
 * DelegationTokenIdentifiers can interact with a server that validates BundledTokenIdentifiers
 * and vice-versa.
 */
public class BundledDelegationTokenIdentifier extends DelegationTokenIdentifier
    implements BundledTokenIdentifier {

  // The current VERSION of the token.
  private static final byte VERSION = 0;

  // The designated main password.
  // This will be empty (byte[0]) if deserialization fails to read any content
  // for the main password.
  private byte[] mainPassword;

  // The length of all inner tokens.
  // This will be 0 if deserialization fails to read any content for the
  // inner tokens.
  private int innerTokensLength;

  // The list of all inner tokens including the main token as well.
  // This will be empty (Token[0]) if deserialization fails to read any content
  // for the inner tokens.
  private Token[] innerTokens;

  // The version of the BundledDelegationTokenIdentifier found for this token.
  // This will be set to BASE_VERSION if deserialization fails to read any
  // content for the tokenVersion.
  private byte tokenVersion;

  // The original serde implementation of this identifier was un-versioned.
  // This denotes the default version for un-versioned tokens.
  private static final byte BASE_VERSION = 0;

  public BundledDelegationTokenIdentifier() {
    super();
  }

  public BundledDelegationTokenIdentifier(Token<?> mainToken,
      Token<AbstractDelegationTokenIdentifier>[] tokens) throws IOException {
    this((AbstractDelegationTokenIdentifier) mainToken.decodeIdentifier(),
        mainToken.getPassword(), tokens);
  }

  public BundledDelegationTokenIdentifier(AbstractDelegationTokenIdentifier mainTokenId,
      byte[] mainPassword, Token<AbstractDelegationTokenIdentifier>[] tokens) throws IOException {
    super(mainTokenId.getOwner(), mainTokenId.getRenewer(), mainTokenId.getRealUser());
    // Set the attributes from the main tokenIdentifier, which are expected by the
    // DelegationTokenIdentifier class.
    this.setIssueDate(mainTokenId.getIssueDate());
    this.setMaxDate(mainTokenId.getMaxDate());
    this.setSequenceNumber(mainTokenId.getSequenceNumber());
    this.setMasterKeyId(mainTokenId.getMasterKeyId());

    // Set password of the main token, used during SASL handshake.
    this.mainPassword = mainPassword;

    if (tokens == null) {
      tokens = new Token[0];
    }

    // Set information for all bundled tokens.
    this.innerTokensLength = tokens.length;
    this.innerTokens = tokens;

    this.tokenVersion = VERSION;
  }

  @Override
  public void write(DataOutput out) throws IOException {
    super.write(out);

    // Serialize bundled token information.
    WritableUtils.writeCompressedByteArray(out, this.mainPassword);
    WritableUtils.writeVInt(out, this.innerTokensLength);

    for (Token innerToken : this.innerTokens) {
      innerToken.decodeIdentifier().write(out);
      WritableUtils.writeCompressedByteArray(out, innerToken.getPassword());
      innerToken.getService().write(out);
    }

    out.writeByte(tokenVersion);
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    super.readFields(in);

    // Deserialize bundled token information if present.
    try {
      this.mainPassword = WritableUtils.readCompressedByteArray(in);
      this.innerTokensLength = WritableUtils.readVInt(in);

      this.innerTokens = new Token[innerTokensLength];
      for (int i = 0; i < innerTokensLength; i++) {
        DelegationTokenIdentifier id = new DelegationTokenIdentifier();
        id.readFields(in);

        byte[] password = WritableUtils.readCompressedByteArray(in);

        Text service = new Text();
        service.readFields(in);

        this.innerTokens[i] = new Token(id.getBytes(), password, HDFS_DELEGATION_KIND, service);
      }

      try {
        // In the first iteration of the BundledDelegationTokenIdentifier,
        // there was no versioning, so this field might be missing.
        this.tokenVersion = in.readByte();
      } catch (IOException ex) {
        this.tokenVersion = BASE_VERSION;
      }

    } catch (IOException ex) {
      // This is expected to happen if the tokenIdentifier has no bundled tokens. The error
      // suggests that we reached end of input as there is no more information received.
      this.mainPassword = new byte[0];
      this.innerTokensLength = 0;
      this.innerTokens = new Token[0];
      this.tokenVersion = BASE_VERSION;
    }
  }

  @Override
  public boolean hasInnerTokens() {
    return this.innerTokensLength > 0;
  }

  @Override
  public int getInnerTokensLength() {
    return this.innerTokensLength;
  }

  @Override
  public byte[] getMainPassword() {
    return this.mainPassword;
  }

  @Override
  public Token[] getInnerTokens() {
    return this.innerTokens;
  }
}
