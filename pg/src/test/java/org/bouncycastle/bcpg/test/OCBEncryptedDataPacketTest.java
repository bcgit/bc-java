package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class OCBEncryptedDataPacketTest extends AbstractPacketTest {
    @Override
    public String getName() {
        return "OCBEncryptedDataPacketTest";
    }

    @Override
    public void performTest() throws Exception {
        parseTestVector();
        parseUnsupportedPacketVersion();
    }

    private void parseTestVector() throws IOException {
        String testVector = "" +
                "d45301090210c265ff63a61ed8af00fa" +
                "43866be8eb9eef77241518a3d60e387b" +
                "1e283bdd90e2233d17a937a595686024" +
                "1d13ddfaccd2b724a491167631d1cd3e" +
                "a74fe5d9e617f1f267d891fd338fddb2" +
                "c66c025cde";

        ByteArrayInputStream bIn = new ByteArrayInputStream(Hex.decode(testVector));
        BCPGInputStream pIn = new BCPGInputStream(bIn);

        AEADEncDataPacket p = (AEADEncDataPacket) pIn.readPacket();
        isTrue("Packet length encoding format mismatch", p.hasNewPacketFormat());
        isEquals("Packet version mismatch", 1, p.getVersion());
        isEquals("Symmetric algorithm mitmatch", SymmetricKeyAlgorithmTags.AES_256, p.getAlgorithm());
        isEquals("AEAD encryption algorithm mismatch", AEADAlgorithmTags.OCB, p.getAEADAlgorithm());
        isEquals("Chunk size mismatch", 16, p.getChunkSize());
        isEncodingEqual("IV mismatch", Hex.decode("C265FF63A61ED8AF00FA43866BE8EB"), p.getIV());
    }

    private void parseUnsupportedPacketVersion() throws IOException {
        // Test vector with modified packet version 99
        String testVector = "" +
                "d45399090210c265ff63a61ed8af00fa" +
                "43866be8eb9eef77241518a3d60e387b" +
                "1e283bdd90e2233d17a937a595686024" +
                "1d13ddfaccd2b724a491167631d1cd3e" +
                "a74fe5d9e617f1f267d891fd338fddb2" +
                "c66c025cde";

        ByteArrayInputStream bIn = new ByteArrayInputStream(Hex.decode(testVector));
        BCPGInputStream pIn = new BCPGInputStream(bIn);

        try
        {
            pIn.readPacket();
            fail("Expected UnsupportedPacketVersionException for unsupported version 99");
        }
        catch (UnsupportedPacketVersionException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        runTest(new OCBEncryptedDataPacketTest());
    }
}
