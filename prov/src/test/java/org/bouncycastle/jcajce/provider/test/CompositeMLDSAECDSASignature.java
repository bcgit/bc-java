package org.bouncycastle.jcajce.provider.test;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class CompositeMLDSAECDSASignature
{

    // Constants
    private static final String PREFIX_STRING = "CompositeAlgorithmSignatures2025";
    private static final byte[] PREFIX = PREFIX_STRING.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] DOMAIN_SEPARATOR = Hex.decode("060B6086480186FA6B50080167");//060B6086480186FA6B50080153
    private static final byte[] HASH_OID_SHA256 = Hex.decode("0609608648016503040201");
    private static final int ML_DSA_SIG_SIZE = 2420; // For ML-DSA-44
    private static final int RANDOMIZER_SIZE = 32;

    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static class CompositeKeyPair
    {
        private final CompositePublicKey publicKey;
        private final CompositePrivateKey privateKey;

        public CompositeKeyPair(CompositePublicKey publicKey, CompositePrivateKey privateKey)
        {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public CompositePublicKey getPublicKey()
        {
            return publicKey;
        }

        public CompositePrivateKey getPrivateKey()
        {
            return privateKey;
        }
    }

    public static class CompositePublicKey
    {
        private final byte[] mlDsaPubKey;
        private final byte[] ecPubKey;

        public CompositePublicKey(byte[] mlDsaPubKey, byte[] ecPubKey)
        {
            this.mlDsaPubKey = mlDsaPubKey;
            this.ecPubKey = ecPubKey;
        }

        public byte[] getMlDsaPubKey()
        {
            return mlDsaPubKey;
        }

        public byte[] getEcPubKey()
        {
            return ecPubKey;
        }

        public byte[] getEncoded()
        {
            return Arrays.concatenate(mlDsaPubKey, ecPubKey);
        }
    }

    public static class CompositePrivateKey
    {
        private final byte[] mlDsaSeed;
        private final byte[] ecPrivKey;

        public CompositePrivateKey(byte[] mlDsaSeed, byte[] ecPrivKey)
        {
            this.mlDsaSeed = mlDsaSeed;
            this.ecPrivKey = ecPrivKey;
        }

        public byte[] getMlDsaSeed()
        {
            return mlDsaSeed;
        }

        public byte[] getEcPrivKey()
        {
            return ecPrivKey;
        }

        public byte[] getEncoded()
        {
            return Arrays.concatenate(mlDsaSeed, ecPrivKey);
        }
    }

    public static CompositeKeyPair generateKeyPair()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        // Generate ML-DSA key pair
        MLDSAKeyPairGenerator mlDsaKpg = new MLDSAKeyPairGenerator();
        mlDsaKpg.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_44));
        AsymmetricCipherKeyPair mlDsaKeyPair = mlDsaKpg.generateKeyPair();
        MLDSAPublicKeyParameters mlDsaPub = (MLDSAPublicKeyParameters)mlDsaKeyPair.getPublic();
        MLDSAPrivateKeyParameters mlDsaPriv = (MLDSAPrivateKeyParameters)mlDsaKeyPair.getPrivate();

        // Generate ECDSA key pair
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"), random);
        KeyPair ecKeyPair = ecKpg.generateKeyPair();
        BCECPublicKey ecPub = (BCECPublicKey)ecKeyPair.getPublic();
        BCECPrivateKey ecPriv = (BCECPrivateKey)ecKeyPair.getPrivate();

        // Create composite keys
        CompositePublicKey pubKey = new CompositePublicKey(
            mlDsaPub.getEncoded(),
            ecPub.getQ().getEncoded(false)
        );

        CompositePrivateKey privKey = new CompositePrivateKey(
            mlDsaPriv.getEncoded(), // Note: This contains more than just seed
            ecPriv.getD().toByteArray()
        );

        return new CompositeKeyPair(pubKey, privKey);
    }

    public static byte[] sign(CompositePrivateKey privateKey, byte[] message, byte[] ctx)
        throws Exception
    {
        if (ctx.length > 255)
        {
            throw new IllegalArgumentException("Context too long");
        }

        SecureRandom random = new SecureRandom();

        // Step 1: Generate randomizer r (32 bytes)
        byte[] r = new byte[RANDOMIZER_SIZE];
        random.nextBytes(r);

        // Step 2: Compute PH = SHA256(r || M)
        MessageDigest digest = MessageDigest.getInstance("SHA256");
        digest.update(r);
        digest.update(message);
        byte[] ph = digest.digest();

        // Step 3: Build M'
        ByteArrayOutputStream mPrimeStream = new ByteArrayOutputStream();
        mPrimeStream.write(PREFIX);
        mPrimeStream.write(DOMAIN_SEPARATOR);
        mPrimeStream.write(ctx.length);
        mPrimeStream.write(ctx);
        mPrimeStream.write(r);
        mPrimeStream.write(HASH_OID_SHA256);
        mPrimeStream.write(ph);
        byte[] mPrime = mPrimeStream.toByteArray();

        // Step 4: Sign M' with ML-DSA
        MLDSASigner mlDsaSigner = new MLDSASigner();
        mlDsaSigner.init(true, recreateMlDsaPrivateKey(privateKey.getMlDsaSeed()));
        mlDsaSigner.update(mPrime, 0, mPrime.length);
        byte[] mlDsaSig = mlDsaSigner.generateSignature();

        // Step 5: Sign M' with ECDSA
        ECDSASigner ecdsaSigner = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
//        ecdsaSigner.init(true, new ECPrivateKeyParameters(
//            new BigInteger(1, privateKey.getEcPrivKey()),
//            new ECNamedDomainParameters(ECNamedCurveTable.getParameterSpec("secp256r1"))
//        ));
        BigInteger[] ecSig = ecdsaSigner.generateSignature(mPrime);
        byte[] ecDerSig = derEncodeECSignature(ecSig[0], ecSig[1]);

        // Step 6: Serialize composite signature
        ByteArrayOutputStream sigStream = new ByteArrayOutputStream();
        sigStream.write(r);
        sigStream.write(mlDsaSig);
        sigStream.write(ecDerSig);

        return sigStream.toByteArray();
    }

    public static boolean verify(CompositePublicKey publicKey, byte[] message, byte[] ctx, byte[] signature)
        throws Exception
    {
        if (ctx != null && ctx.length > 255)
        {
            throw new IllegalArgumentException("Context too long");
        }

        // Split signature
        if (signature.length < RANDOMIZER_SIZE + ML_DSA_SIG_SIZE)
        {
            return false;
        }
        byte[] r = Arrays.copyOfRange(signature, 0, RANDOMIZER_SIZE);
        byte[] mlDsaSig = Arrays.copyOfRange(signature, RANDOMIZER_SIZE, RANDOMIZER_SIZE + ML_DSA_SIG_SIZE);
        byte[] ecDerSig = Arrays.copyOfRange(signature, RANDOMIZER_SIZE + ML_DSA_SIG_SIZE, signature.length);

        // Step 1: Compute PH = SHA256(r || M)
        MessageDigest digest = MessageDigest.getInstance("SHA256");
        digest.update(r);
        digest.update(message);
        byte[] ph = digest.digest();

        // Step 2: Build M'
        ByteArrayOutputStream mPrimeStream = new ByteArrayOutputStream();
        mPrimeStream.write(PREFIX);
        mPrimeStream.write(DOMAIN_SEPARATOR);
        if (ctx != null)
        {
            mPrimeStream.write(ctx.length);
            mPrimeStream.write(ctx);
        }
        else
        {
            mPrimeStream.write(0);
        }
        mPrimeStream.write(r);
        mPrimeStream.write(HASH_OID_SHA256);
        mPrimeStream.write(ph);
        byte[] mPrime = mPrimeStream.toByteArray();

        // Step 3: Verify ML-DSA signature
        MLDSASigner mlDsaVerifier = new MLDSASigner();
        mlDsaVerifier.init(false, recreateMlDsaPublicKey(publicKey.getMlDsaPubKey()));
        mlDsaVerifier.update(mPrime, 0, mPrime.length);
        boolean mlDsaValid = mlDsaVerifier.verifySignature(mlDsaSig);

        // Step 4: Verify ECDSA signature
        BigInteger[] ecSig = derDecodeECSignature(ecDerSig);
        ECDSASigner ecdsaVerifier = new ECDSASigner();
        ecdsaVerifier.init(false, recreateEcPublicKey(publicKey.getEcPubKey()));
        boolean ecValid = ecdsaVerifier.verifySignature(mPrime, ecSig[0], ecSig[1]);

        return mlDsaValid && ecValid;
    }

    // Helper methods
    private static MLDSAPrivateKeyParameters recreateMlDsaPrivateKey(byte[] encoded)
    {
        return new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, encoded);
    }

    private static MLDSAPublicKeyParameters recreateMlDsaPublicKey(byte[] encoded)
    {
        return new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, encoded);
    }

    private static ECPublicKeyParameters recreateEcPublicKey(byte[] encoded)
    {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        return new ECPublicKeyParameters(
            spec.getCurve().decodePoint(encoded),
            new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH())
        );
    }

    private static byte[] derEncodeECSignature(BigInteger r, BigInteger s)
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded();
    }

    private static BigInteger[] derDecodeECSignature(byte[] der)
        throws IOException
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        return new BigInteger[]{
            ASN1Integer.getInstance(seq.getObjectAt(0)).getValue(),
            ASN1Integer.getInstance(seq.getObjectAt(1)).getValue()
        };
    }

    public static void main(String[] args)
        throws Exception
    {
        // Example usage
        CompositeKeyPair keyPair = generateKeyPair();
        byte[] message = "Hello, Composite Signatures!".getBytes();
        byte[] ctx = "example-context".getBytes();

        byte[] signature = sign(keyPair.getPrivateKey(), message, ctx);
        boolean isValid = verify(keyPair.getPublicKey(), message, ctx, signature);

        System.out.println("Signature valid: " + isValid);
    }
}