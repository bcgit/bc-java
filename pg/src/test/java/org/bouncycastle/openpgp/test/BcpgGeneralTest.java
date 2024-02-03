package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketInputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

public class BcpgGeneralTest
    extends SimpleTest
{
    @Override
    public String getName()
    {
        return "BcpgGeneralTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        // Tests for PreferredAEADCiphersuites
        testPreferredAEADCiphersuites();
    }

    public void testPreferredAEADCiphersuites()
        throws Exception
    {
        PreferredAEADCiphersuites preferences = new PreferredAEADCiphersuites(false, new PreferredAEADCiphersuites.Combination[]
            {
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB),
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.GCM),
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.CAMELLIA_256, AEADAlgorithmTags.OCB)
            });

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream bcpgOut = new BCPGOutputStream(bOut);

        preferences.encode(bcpgOut);

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        SignatureSubpacketInputStream subpacketIn = new SignatureSubpacketInputStream(bIn);
        SignatureSubpacket subpacket = subpacketIn.readPacket();
        assert subpacket != null;
        assert subpacket instanceof PreferredAEADCiphersuites;

        PreferredAEADCiphersuites parsed = (PreferredAEADCiphersuites)subpacket;
        isTrue(Arrays.areEqual(preferences.getAlgorithms(), parsed.getAlgorithms()));
        PreferredAEADCiphersuites.Combination[] preferencesCombinations = preferences.getAlgorithms();
        PreferredAEADCiphersuites.Combination[] parsedCombinations = parsed.getAlgorithms();
        isTrue(!preferencesCombinations[0].equals(null));
        isTrue(!preferencesCombinations[0].equals(new Object()));
        isTrue(preferencesCombinations[0].equals(preferencesCombinations[0]));
        isTrue(!preferencesCombinations[0].equals(preferencesCombinations[1]));
        isTrue(!preferencesCombinations[0].equals(preferencesCombinations[2]));
        isTrue(preferencesCombinations[0].equals(parsedCombinations[0]));
        isTrue(preferences.isSupported(new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.CAMELLIA_256, AEADAlgorithmTags.OCB)));
        isTrue(!preferences.isSupported(new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB)));
        isTrue(preferencesCombinations[0].hashCode() == parsedCombinations[0].hashCode());
    }
}
