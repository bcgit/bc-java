package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

public class PGPKeyRingGeneratorTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "PGPKeyRingGeneratorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        generateMinimalV6Key();
    }

    private void generateMinimalV6Key()
            throws PGPException, IOException
    {
        Date creationTime = currentTimeRounded();
        Ed25519KeyPairGenerator edGen = new Ed25519KeyPairGenerator();
        edGen.init(new Ed25519KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom()));
        AsymmetricCipherKeyPair edKp = edGen.generateKeyPair();
        PGPKeyPair primaryKp = new BcPGPKeyPair(PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.Ed25519, edKp, creationTime);

        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setIssuerFingerprint(true, primaryKp.getPublicKey());
        hashed.setSignatureCreationTime(true, creationTime);
        hashed.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        hashed.setFeature(true, (byte) (Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2));
        hashed.setPreferredHashAlgorithms(false, new int[] {
                HashAlgorithmTags.SHA3_512, HashAlgorithmTags.SHA3_256,
                HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256
        });
        hashed.setPreferredSymmetricAlgorithms(false, new int[] {
                SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128
        });
        hashed.setPreferredAEADCiphersuites(false, new PreferredAEADCiphersuites.Combination[] {
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB),
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_192, AEADAlgorithmTags.OCB),
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB)
        });

        PGPKeyRingGenerator gen = new PGPKeyRingGenerator(
                primaryKp,
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                hashed.generate(),
                null,
                new BcPGPContentSignerBuilder(primaryKp.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA3_512),
                null);

        X25519KeyPairGenerator xGen = new X25519KeyPairGenerator();
        xGen.init(new X25519KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom()));
        AsymmetricCipherKeyPair xKp = xGen.generateKeyPair();
        PGPKeyPair subKp = new BcPGPKeyPair(PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.X25519, xKp, creationTime);

        hashed = new PGPSignatureSubpacketGenerator();
        hashed.setKeyFlags(false, KeyFlags.ENCRYPT_STORAGE | KeyFlags.ENCRYPT_COMMS);
        hashed.setSignatureCreationTime(true, creationTime);
        hashed.setIssuerFingerprint(true, primaryKp.getPublicKey());

        gen.addSubKey(subKp, hashed.generate(), null, null);

        PGPPublicKeyRing certificate = gen.generatePublicKeyRing();
        PGPSecretKeyRing secretKey = gen.generateSecretKeyRing();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        secretKey.encode(pOut);
        pOut.close();
        aOut.close();
        System.out.println(bOut);
    }

    public static void main(String[] args)
    {
        runTest(new PGPKeyRingGeneratorTest());
    }
}
