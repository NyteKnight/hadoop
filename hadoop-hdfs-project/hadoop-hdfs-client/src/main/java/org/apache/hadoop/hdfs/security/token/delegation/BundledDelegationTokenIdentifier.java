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
  private byte[] mainPassword;
  private int innerTokensLength;
  private Token[] innerTokens;

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

    // Set information for all bundled tokens.
    if (tokens != null) {
      this.innerTokensLength = tokens.length;
      this.innerTokens = tokens;
    }
  }

  @Override
  public void write(DataOutput out) throws IOException {
    super.write(out);

    // Serialize bundled token information.
    if (this.hasInnerTokens()) {
      WritableUtils.writeCompressedByteArray(out, this.mainPassword);
      WritableUtils.writeVInt(out, this.innerTokensLength);

      for (Token innerToken : this.innerTokens) {
        innerToken.decodeIdentifier().write(out);
        WritableUtils.writeCompressedByteArray(out, innerToken.getPassword());
        innerToken.getService().write(out);
      }
    }
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
    } catch (IOException ex) {
      // This is expected to happen if the tokenIdentifier has no bundled tokens. The error
      // suggests that we reached end of input as there is no more information received.
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
