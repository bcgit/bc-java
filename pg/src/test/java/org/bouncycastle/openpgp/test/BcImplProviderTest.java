package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.EdSecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPPrivateKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

public class BcImplProviderTest
    extends SimpleTest
{
    @Override
    public String getName()
    {
        return "BcImplProviderTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testBcImplProvider();
    }

    public void testBcImplProvider()
        throws Exception
    {
        //createDigest
        final BcPGPDigestCalculatorProvider provider = new BcPGPDigestCalculatorProvider();
        testCreateDigest(provider, HashAlgorithmTags.SHA1, new SHA1Digest());
        testCreateDigest(provider, HashAlgorithmTags.SHA224, new SHA224Digest());
        testCreateDigest(provider, HashAlgorithmTags.SHA256, new SHA256Digest());
        testCreateDigest(provider, HashAlgorithmTags.SHA384, new SHA384Digest());
        testCreateDigest(provider, HashAlgorithmTags.SHA512, new SHA512Digest());
        testCreateDigest(provider, HashAlgorithmTags.SHA3_224, new SHA3Digest(224));
        testCreateDigest(provider, HashAlgorithmTags.SHA3_256, new SHA3Digest(256));
        testCreateDigest(provider, HashAlgorithmTags.SHA3_384, new SHA3Digest(384));
        testCreateDigest(provider, HashAlgorithmTags.SHA3_512, new SHA3Digest(512));
        testCreateDigest(provider, HashAlgorithmTags.MD2, new MD2Digest());
        testCreateDigest(provider, HashAlgorithmTags.MD5, new MD5Digest());
        testCreateDigest(provider, HashAlgorithmTags.RIPEMD160, new RIPEMD160Digest());
        testCreateDigest(provider, HashAlgorithmTags.TIGER_192, new TigerDigest());
        testException("cannot recognise digest", "PGPException", () -> provider.get(HashAlgorithmTags.SM3));

        //createSigner
        testCreateSigner(PublicKeyAlgorithmTags.DSA, new DSADigestSigner(new DSASigner(), new SHA1Digest()), "DSA",
            (pub, privKey) -> new DSASecretBCPGKey(((DSAPrivateKey)privKey).getX()));
        testCreateSigner(PublicKeyAlgorithmTags.RSA_GENERAL, new RSADigestSigner(new SHA1Digest()), "RSA",
            (pub, privKey) -> {
                RSAPrivateCrtKey rsK = (RSAPrivateCrtKey)privKey;
                return new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
            });
        testCreateSigner(PublicKeyAlgorithmTags.ECDSA, new DSADigestSigner(new ECDSASigner(), new SHA1Digest()), "ECDSA",
            (pub, privKey) -> new ECSecretBCPGKey(((ECPrivateKey)privKey).getS()));
//        testCreateSigner(PublicKeyAlgorithmTags.EDDSA_LEGACY, new EdDsaSigner(new Ed448Signer(new byte[0]), new SHA1Digest()), "EdDSA",
//            (pub, privKey) -> {
//                PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());
//                return new EdSecretBCPGKey(
//                    new BigInteger(1, ASN1OctetString.getInstance(pInfo.parsePrivateKey()).getOctets()));
//            });
    }

    private void testCreateDigest(BcPGPDigestCalculatorProvider provider, int algorithm, Digest digest)
        throws PGPException
    {
        PGPDigestCalculator calculator = provider.get(algorithm);
        isEquals(calculator.getAlgorithm(), algorithm);
        byte[] d = new byte[digest.getDigestSize()];
        digest.doFinal(d, 0);
        isTrue(Arrays.areEqual(d, calculator.getDigest()));
        calculator.reset();
    }

    private interface Operation
    {
        BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
            throws IOException;
    }

    private void testCreateSigner(int keyAlgorithm, Signer signer, String name, Operation operation)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(name, "BC");


        if (keyAlgorithm == PublicKeyAlgorithmTags.ECDSA)
        {
            kpGen.initialize(new ECGenParameterSpec("P-256"));
        }
        else if (keyAlgorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY)
        {
            kpGen.initialize(new ECNamedCurveGenParameterSpec("Ed25519"));
        }
        else
        {
            kpGen.initialize(1024);
        }

        KeyPair kp = kpGen.generateKeyPair();

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter();
        PGPPublicKey pubKey;
        if (keyAlgorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY)
        {
            pubKey = converter.getPGPPublicKey(PGPPublicKey.ECDH, kp.getPublic(), new Date());
        }
        else
        {
            pubKey = converter.getPGPPublicKey(keyAlgorithm, kp.getPublic(), new Date());
        }
        PGPPrivateKey privKey = new PGPPrivateKey(pubKey.getKeyID(), pubKey.getPublicKeyPacket(), operation.getPrivateBCPGKey(pubKey, kp.getPrivate()));


        byte[] source = new byte[1024];
        SecureRandom r1 = new SecureRandom();
        r1.nextBytes(source);
        SecureRandom random = new FixedSecureRandom(source);
        final BcPGPContentSignerBuilder builder = new BcPGPContentSignerBuilder(keyAlgorithm, HashAlgorithmTags.SHA1).setSecureRandom(random);
        PGPContentSigner contentSigner = builder.build(PGPSignature.BINARY_DOCUMENT, privKey);
        //
        BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();
        AsymmetricKeyParameter privKeyParam = keyConverter.getPrivateKey(privKey);
        signer.init(true, new ParametersWithRandom(privKeyParam, new FixedSecureRandom(source)));
        isTrue(contentSigner.getKeyAlgorithm() == keyAlgorithm);
        //isTrue(areEqual(contentSigner.getSignature(), signer.generateSignature()));

    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new BcImplProviderTest());
    }

    private static class EdDsaSigner
        implements Signer
    {
        private final Signer signer;
        private final Digest digest;
        private final byte[] digBuf;

        EdDsaSigner(Signer signer, Digest digest)
        {
            this.signer = signer;
            this.digest = digest;
            this.digBuf = new byte[digest.getDigestSize()];
        }

        public void init(boolean forSigning, CipherParameters param)
        {
            this.signer.init(forSigning, param);
            this.digest.reset();
        }

        public void update(byte b)
        {
            this.digest.update(b);
        }

        public void update(byte[] in, int off, int len)
        {
            this.digest.update(in, off, len);
        }

        public byte[] generateSignature()
            throws CryptoException, DataLengthException
        {
            digest.doFinal(digBuf, 0);

            signer.update(digBuf, 0, digBuf.length);

            return signer.generateSignature();
        }

        public boolean verifySignature(byte[] signature)
        {
            digest.doFinal(digBuf, 0);

            signer.update(digBuf, 0, digBuf.length);

            return signer.verifySignature(signature);
        }

        public void reset()
        {
            Arrays.clear(digBuf);
            signer.reset();
            digest.reset();
        }
    }
}
