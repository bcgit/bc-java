package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketInputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPKdfParameters;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

public class BcpgGeneralTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new BcpgGeneralTest());
    }

    @Override
    public String getName()
    {
        return "BcpgGeneralTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testECDHPublicBCPGKey();
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

    public void testECDHPublicBCPGKey()
        throws Exception
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

        final X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(random));
        testException("Symmetric key algorithm must be AES-128 or stronger.", "IllegalStateException", () ->
            new BcPGPKeyPair(PGPPublicKey.ECDH, new PGPKdfParameters(8, SymmetricKeyAlgorithmTags.CAMELLIA_256), gen.generateKeyPair(), new Date()));
        testException("Hash algorithm must be SHA-256 or stronger.", "IllegalStateException", () ->
            new BcPGPKeyPair(PGPPublicKey.ECDH, new PGPKdfParameters(HashAlgorithmTags.SHA1, 7), gen.generateKeyPair(), new Date()));

        BcPGPKeyPair kp = new BcPGPKeyPair(PGPPublicKey.ECDH, gen.generateKeyPair(), new Date());

        ECDHPublicBCPGKey publicBCPGKey = (ECDHPublicBCPGKey)kp.getPublicKey().getPublicKeyPacket().getKey();
        isTrue(publicBCPGKey.getReserved() == 1);
        isTrue(publicBCPGKey.getFormat().equals("PGP"));

        ECSecretBCPGKey secretBCPGKey = (ECSecretBCPGKey)kp.getPrivateKey().getPrivateKeyDataPacket();
        isTrue(secretBCPGKey.getFormat().equals("PGP"));
        isTrue(Arrays.areEqual(publicBCPGKey.getEncoded(), kp.getPrivateKey().getPublicKeyPacket().getKey().getEncoded()));


    }
}
