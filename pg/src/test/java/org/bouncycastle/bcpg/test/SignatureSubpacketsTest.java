package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.LibrePGPPreferredEncryptionModes;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SignatureSubpacketsTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "SignatureSubpacketsTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testLibrePGPPreferredEncryptionModesSubpacket();
    }

    private void testLibrePGPPreferredEncryptionModesSubpacket()
            throws IOException
    {
        int[] algorithms = new int[] {AEADAlgorithmTags.EAX, AEADAlgorithmTags.OCB};
        LibrePGPPreferredEncryptionModes encModes = new LibrePGPPreferredEncryptionModes(
                false, algorithms);

        isTrue("Encryption Modes encoding mismatch",
                Arrays.areEqual(algorithms, encModes.getPreferences()));
        isFalse("Mismatch in critical flag", encModes.isCritical());

        // encode to byte array and check correctness
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        encModes.encode(bOut);

        isEncodingEqual("Packet encoding mismatch", new byte[]{
                3, // length
                SignatureSubpacketTags.LIBREPGP_PREFERRED_ENCRYPTION_MODES,
                AEADAlgorithmTags.EAX,
                AEADAlgorithmTags.OCB
        }, bOut.toByteArray());
    }

    public static void main(String[] args)
    {
        runTest(new SignatureSubpacketsTest());
    }
}
