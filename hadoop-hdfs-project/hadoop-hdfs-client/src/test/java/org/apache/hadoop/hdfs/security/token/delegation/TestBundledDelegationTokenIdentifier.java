package org.apache.hadoop.hdfs.security.token.delegation;

import java.io.IOException;
import org.apache.hadoop.io.DataInputBuffer;
import org.apache.hadoop.io.DataOutputBuffer;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.delegation.AbstractDelegationTokenIdentifier;
import org.apache.hadoop.util.Time;
import org.junit.Test;

import static org.junit.Assert.*;


public class TestBundledDelegationTokenIdentifier {
  @Test
  public void testBundledTokenSerialization() throws Exception {
    // Create tokenIdentifier with bundled tokens and write to stream.
    BundledDelegationTokenIdentifier bundledTokenId1 = createTestBundledTokenId();
    DataOutputBuffer out = new DataOutputBuffer();
    bundledTokenId1.write(out);

    // Read as bundledTokenIdentifier from stream.
    BundledDelegationTokenIdentifier bundledTokenId2 = new BundledDelegationTokenIdentifier();
    readDelegationTokenIdentifier(bundledTokenId2, out);

    // Validate that DelegationTokenInformation attributes are deserialized correctly.
    assertEquals(bundledTokenId1, bundledTokenId2);

    Token[] innerTokens1 = bundledTokenId1.getInnerTokens();
    Token[] innerTokens2 = bundledTokenId2.getInnerTokens();

    // Validate that bundled token information was deserialized correctly. 
    assertEquals(innerTokens1.length, innerTokens2.length);
    for (int i = 0; i < innerTokens1.length; i++) {
      assertEquals(innerTokens1[i].decodeIdentifier(), innerTokens2[i].decodeIdentifier());
      assertArrayEquals(innerTokens1[i].getPassword(), innerTokens2[i].getPassword());
      assertEquals(innerTokens1[i].getService(), innerTokens2[i].getService());
    }
  }

  @Test
  public void testBundledTokenBackwardsCompatible() throws Exception {
    // Create tokenIdentifier with no bundled tokens and write to stream.
    Token<AbstractDelegationTokenIdentifier> token1 = createTestToken(0);
    AbstractDelegationTokenIdentifier tokenId1 = token1.decodeIdentifier();
    DataOutputBuffer out = new DataOutputBuffer();
    tokenId1.write(out);

    // Read as bundledTokenIdentifier from stream.
    BundledDelegationTokenIdentifier bundledTokenId2 = new BundledDelegationTokenIdentifier();
    readDelegationTokenIdentifier(bundledTokenId2, out);

    // Validate that DelegationTokenInformation attributes are deserialized correctly.
    assertEquals(tokenId1, bundledTokenId2);
    
    // Validate that no bundled information was found during deserialization.
    assertFalse(bundledTokenId2.hasInnerTokens());
  }

  @Test
  public void testBundledTokenForwardsCompatible() throws Exception {
    // Create tokenIdentifier with bundled tokens and write to stream.
    BundledDelegationTokenIdentifier bundledTokenId1 = createTestBundledTokenId();
    DataOutputBuffer out = new DataOutputBuffer();
    bundledTokenId1.write(out);

    // Read as tokenIdentifier with no bundled tokens from stream.
    DelegationTokenIdentifier tokenId2 = new DelegationTokenIdentifier();
    readDelegationTokenIdentifier(tokenId2, out);

    // Validate that DelegationTokenInformation attributes are deserialized correctly.
    assertEquals(bundledTokenId1, tokenId2);
  }

  private BundledDelegationTokenIdentifier createTestBundledTokenId() throws IOException {
    int tokensLength = 3;
    Token<AbstractDelegationTokenIdentifier>[] allTokens = new Token[tokensLength];
    for (int i = 0; i < tokensLength; i++) {
      Token<AbstractDelegationTokenIdentifier> token1 = createTestToken(i + 1);
      allTokens[i] = token1;
    }

    return new BundledDelegationTokenIdentifier(allTokens[0], allTokens);
  }

  private Token<AbstractDelegationTokenIdentifier> createTestToken(int id) {
    DelegationTokenIdentifier tokenId = new DelegationTokenIdentifier();
    tokenId.setOwner(new Text("owner_" + id));
    tokenId.setRenewer(new Text("renewer_" + id));
    tokenId.setRealUser(new Text("realuser_" + id));
    tokenId.setIssueDate(Time.now());
    tokenId.setMaxDate(Time.now() + 10000);
    tokenId.setSequenceNumber(id);
    tokenId.setMasterKeyId(id);

    return new Token<>(tokenId.getBytes(), ("password_" + id).getBytes(),
        new Text("HDFS_DELEGATION_TOKEN"), new Text("service_" + id));
  }

  private void readDelegationTokenIdentifier(DelegationTokenIdentifier tokenId,
      DataOutputBuffer out) throws IOException {
    DataInputBuffer in = new DataInputBuffer();
    in.reset(out.getData(), out.getLength());
    tokenId.readFields(in);
  }
}
