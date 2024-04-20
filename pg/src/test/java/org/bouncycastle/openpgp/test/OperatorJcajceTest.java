package org.bouncycastle.openpgp.test;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.spec.HybridValueParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class OperatorJcajceTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OperatorJcajceTest());
    }

    @Override
    public String getName()
    {
        return "OperatorJcajceTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testCreateDigest();
        testX25519HKDF();
        testJcePBESecretKeyEncryptorBuilder();
        testJcaPGPContentVerifierBuilderProvider();
        testJcaPGPDigestCalculatorProviderBuilder();
        testJcePGPDataEncryptorBuilder();
        testJcaKeyFingerprintCalculator();
        testStandardDigests();
    }

    private void testStandardDigests()
        throws Exception
    {
        PGPDigestCalculatorProvider digCalcBldr =
            new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build();

        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.MD5), Hex.decode("900150983cd24fb0d6963f7d28e17f72"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA1), Hex.decode("a9993e364706816aba3e25717850c26c9cd0d89d"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.RIPEMD160), Hex.decode("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA256), Hex.decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA384), Hex.decode("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA512), Hex.decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA224), Hex.decode("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA3_256), Hex.decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA3_512), Hex.decode("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
    }

    private void testDigestCalc(PGPDigestCalculator digCalc, byte[] expected)
        throws IOException
    {
        OutputStream dOut = digCalc.getOutputStream();

        dOut.write(Strings.toByteArray("abc"));

        dOut.close();

        byte[] res = digCalc.getDigest();

        isTrue(Arrays.areEqual(res, expected));
    }

    public void testJcaKeyFingerprintCalculator()
        throws Exception
    {
        final JcaKeyFingerprintCalculator calculator = new JcaKeyFingerprintCalculator().setProvider(new NullProvider());
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024);
        KeyPair kp = kpGen.generateKeyPair();

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        final PGPPublicKey pubKey = converter.getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, kp.getPublic(), new Date());

        testException("can't find MD5", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                calculator.calculateFingerprint(new PublicKeyPacket(3, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey()));
            }
        });
        testException("can't find SHA1", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                calculator.calculateFingerprint(new PublicKeyPacket(4, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey()));
            }
        });
        testException("can't find SHA-256", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                calculator.calculateFingerprint(new PublicKeyPacket(6, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey()));
            }
        });
        //JcaKeyFingerprintCalculator calculator2 = new JcaKeyFingerprintCalculator().setProvider("BC");
        JcaKeyFingerprintCalculator calculator2 = calculator.setProvider("BC");
        PublicKeyPacket pubKeyPacket = new PublicKeyPacket(6, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey());
        byte[] output = calculator2.calculateFingerprint(new PublicKeyPacket(6, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey()));
        byte[] kBytes = pubKeyPacket.getEncodedContents();
        SHA256Digest digest = new SHA256Digest();

        digest.update((byte)0x9b);

        digest.update((byte)(kBytes.length >> 24));
        digest.update((byte)(kBytes.length >> 16));
        digest.update((byte)(kBytes.length >> 8));
        digest.update((byte)kBytes.length);

        digest.update(kBytes, 0, kBytes.length);
        byte[] digBuf = new byte[digest.getDigestSize()];

        digest.doFinal(digBuf, 0);
        isTrue(areEqual(output, digBuf));

        testException("Unsupported PGP key version: ", "UnsupportedPacketVersionException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                calculator.calculateFingerprint(new PublicKeyPacket(7, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey()));
            }
        });
    }

    public void testJcePGPDataEncryptorBuilder()
        throws Exception
    {
        testException("null cipher specified", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.NULL);
            }
        });

        //testException("AEAD algorithms can only be used with AES", "IllegalStateException", () -> new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.IDEA).setWithAEAD(AEADAlgorithmTags.OCB, 6));

        testException("minimum chunkSize is 6", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithAEAD(AEADAlgorithmTags.OCB, 5);
            }
        });

        isEquals(16, new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setProvider(new BouncyCastleProvider()).setWithAEAD(AEADAlgorithmTags.OCB, 6).build(new byte[32]).getBlockSize());
    }

    public void testJcaPGPDigestCalculatorProviderBuilder()
        throws Exception
    {

        PGPDigestCalculatorProvider digCalcBldr = new JcaPGPDigestCalculatorProviderBuilder().setProvider(new NonDashProvider()).build();
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA256), Hex.decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

        PGPDigestCalculatorProvider digCalcBldr2 = new JcaPGPDigestCalculatorProviderBuilder().setProvider(new DashProvider()).build();
        testDigestCalc(digCalcBldr2.get(HashAlgorithmTags.SHA256), Hex.decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

        PGPDigestCalculatorProvider digCalcBldr3 = new JcaPGPDigestCalculatorProviderBuilder().setProvider(new NonDashProvider()).build();
        testDigestCalc(digCalcBldr3.get(HashAlgorithmTags.SHA1), Hex.decode("a9993e364706816aba3e25717850c26c9cd0d89d"));

        PGPDigestCalculatorProvider digCalcBldr4 = new JcaPGPDigestCalculatorProviderBuilder().setProvider(new DashProvider()).build();
        testDigestCalc(digCalcBldr4.get(HashAlgorithmTags.SHA1), Hex.decode("a9993e364706816aba3e25717850c26c9cd0d89d"));


        final PGPDigestCalculatorProvider provider = new JcaPGPDigestCalculatorProviderBuilder().setProvider(new NullProvider()).build();
        testException("exception on setup: ", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                provider.get(SymmetricKeyAlgorithmTags.AES_256);
            }
        });
    }

    public void testJcaPGPContentVerifierBuilderProvider()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024);
        KeyPair kp = kpGen.generateKeyPair();

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        final PGPPublicKey pubKey = converter.getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, kp.getPublic(), new Date());
        PGPContentVerifier verifier = new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider()).get(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA256).build(pubKey);
        isTrue(verifier.getHashAlgorithm() == HashAlgorithmTags.SHA256);
        isTrue(verifier.getKeyAlgorithm() == PublicKeyAlgorithmTags.RSA_GENERAL);
        isTrue(verifier.getKeyID() == pubKey.getKeyID());
    }

    public void testJcePBESecretKeyEncryptorBuilder()
        throws Exception
    {
        final PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        testException("s2KCount value outside of range 0 to 255.", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc, -1);
            }
        });
    }

    public void testCreateDigest()
        throws Exception
    {
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1).getAlgorithm(), HashAlgorithmTags.SHA1);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.MD2).getAlgorithm(), HashAlgorithmTags.MD2);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.MD5).getAlgorithm(), HashAlgorithmTags.MD5);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.RIPEMD160).getAlgorithm(), HashAlgorithmTags.RIPEMD160);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA256).getAlgorithm(), HashAlgorithmTags.SHA256);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA224).getAlgorithm(), HashAlgorithmTags.SHA224);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA384).getAlgorithm(), HashAlgorithmTags.SHA384);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA512).getAlgorithm(), HashAlgorithmTags.SHA512);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA3_256).getAlgorithm(), HashAlgorithmTags.SHA3_256);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA3_224).getAlgorithm(), HashAlgorithmTags.SHA3_224);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA3_384).getAlgorithm(), HashAlgorithmTags.SHA3_384);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA3_512).getAlgorithm(), HashAlgorithmTags.SHA3_512);
        isEquals(new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.TIGER_192).getAlgorithm(), HashAlgorithmTags.TIGER_192);
    }

    public void testX25519HKDF()
        throws Exception
    {
        byte[] ephmeralKey = Hex.decode("87cf18d5f1b53f817cce5a004cf393cc8958bddc065f25f84af509b17dd36764");
        byte[] ephmeralSecretKey = Hex.decode("af1e43c0d123efe893a7d4d390f3a761e3fac33dfc7f3edaa830c9011352c779");
        byte[] publicKey = Hex.decode("8693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435");
        byte[] expectedHKDF = Hex.decode("f66dadcff64592239b254539b64ff607");
        byte[] keyEnc = Hex.decode("dea355437956617901e06957fbca8a6a47a5b5153e8d3ab7");
        byte[] expectedDecryptedSessionKey = Hex.decode("dd708f6fa1ed65114d68d2343e7c2f1d");
        X25519PrivateKeyParameters ephmeralprivateKeyParameters = new X25519PrivateKeyParameters(ephmeralSecretKey);
        X25519PublicKeyParameters publicKeyParameters = new X25519PublicKeyParameters(publicKey);
        KeyFactory keyfact = KeyFactory.getInstance("X25519", "BC");
        PrivateKey privKey = keyfact.generatePrivate(new PKCS8EncodedKeySpec(PrivateKeyInfoFactory.createPrivateKeyInfo(ephmeralprivateKeyParameters).getEncoded()));
        PublicKey pubKey = keyfact.generatePublic(new X509EncodedKeySpec(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParameters).getEncoded()));
        KeyAgreement agreement = KeyAgreement.getInstance("X25519withSHA256HKDF", "BC");
        agreement.init(privKey, new HybridValueParameterSpec(Arrays.concatenate(ephmeralKey, publicKey), true, new UserKeyingMaterialSpec(Strings.toByteArray("OpenPGP X25519"))));
        agreement.doPhase(pubKey, true);
        Key secretKey = agreement.generateSecret(NISTObjectIdentifiers.id_aes128_wrap.getId());

//        agreement.init(ephmeralprivateKeyParameters);
//        byte[] secret = new byte[agreement.getAgreementSize()];
//        agreement.calculateAgreement(publicKeyParameters, secret, 0);
        byte[] output2 = secretKey.getEncoded();

//        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
//        hkdf.init(new HKDFParameters(Arrays.concatenate(ephmeralKey, publicKey, secret), null, "OpenPGP X25519".getBytes()));
//        hkdf.generateBytes(output2, 0, 16);
//
        isTrue("hkdf failed", Arrays.areEqual(output2, expectedHKDF));
//        Wrapper c = new RFC3394WrapEngine(AESEngine.newInstance());
//        c.init(false, new KeyParameter(output2));
//        byte[] output = c.unwrap(keyEnc, 0, keyEnc.length);
        //isTrue(Arrays.areEqual(output, expectedDecryptedSessionKey));
    }

    private class NullProvider
        extends Provider
    {
        NullProvider()
        {
             super("NULL", 0.0, "Null Provider");
        }
    }

    private class NonDashProvider
        extends Provider
    {
        NonDashProvider()
        {
            super("NonDash", 0.0, "NonDash Provider");
            putService(new Provider.Service(this, "MessageDigest", "SHA256", "org.bouncycastle.openpgp.test.SHA256", null, null));
            putService(new Provider.Service(this, "MessageDigest", "SHA1", "org.bouncycastle.openpgp.test.SHA1", null, null));
        }
    }

    private class DashProvider
        extends Provider
    {
        DashProvider()
        {
            super("Dash", 0.0, "Dash Provider");
            putService(new Service(this, "MessageDigest", "SHA-256", "org.bouncycastle.openpgp.test.SHA256", null, null));
            putService(new Service(this, "MessageDigest", "SHA-1", "org.bouncycastle.openpgp.test.SHA1", null, null));
        }
    }

}
