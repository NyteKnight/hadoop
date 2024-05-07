package org.apache.hadoop.hdfs.security.token.delegation;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import org.apache.hadoop.io.DataInputBuffer;
import org.apache.hadoop.io.DataOutputBuffer;
import org.junit.Assert;
import org.junit.Test;


public class TestSPIFFEDelegationTokenIdentifier {

  @Test
  public void testSerde() throws IOException {
    final String expectedHeader = "header";
    final String expectedPayload = "payload";

    // Create new base token
    final SPIFFEDelegationTokenIdentifier initialSpiffeIdentifier =
        new SPIFFEDelegationTokenIdentifier(expectedHeader, expectedPayload);

    Assert.assertEquals(expectedHeader, initialSpiffeIdentifier.getSpiffeTokenHeader());
    Assert.assertEquals(expectedPayload, initialSpiffeIdentifier.getSpiffeTokenPayload());

    // Serialize and deserialize it
    DataOutputBuffer initialDataOutput = new DataOutputBuffer();
    initialSpiffeIdentifier.write(initialDataOutput);

    DataInputBuffer deserializationDataInput = new DataInputBuffer();
    deserializationDataInput.reset(initialDataOutput.getData(), initialDataOutput.getLength());

    // Ensure the deserialized token was correctly serialized and deserialized
    final SPIFFEDelegationTokenIdentifier deserializedSpiffeIdentifier =
        new SPIFFEDelegationTokenIdentifier();
    deserializedSpiffeIdentifier.readFields(deserializationDataInput);

    Assert.assertEquals(expectedHeader, deserializedSpiffeIdentifier.getSpiffeTokenHeader());
    Assert.assertEquals(expectedPayload, deserializedSpiffeIdentifier.getSpiffeTokenPayload());

    Assert.assertEquals(initialSpiffeIdentifier, deserializedSpiffeIdentifier);
  }

}
