package org.bouncycastle.bcpg.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MLDSACompositePublicBCPGKey;
import org.bouncycastle.bcpg.MLDSACompositeSecretBCPGKey;
import org.bouncycastle.bcpg.MLKEMCompositePublicBCPGKey;
import org.bouncycastle.bcpg.MLKEMCompositeSecretBCPGKey;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.SLHDSAPublicBCPGKey;
import org.bouncycastle.bcpg.SLHDSASecretBCPGKey;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.util.Arrays;

/**
 * Packet-level tests of the RFC 9980 key material, PKESK and signature packet layouts: the fixed component
 * lengths of the key classes, encode/parse round trips of public and subkey packets, PKESK packets and
 * signature packets, the key-version binding of sec. 3.5, and the rejection of truncated or oversized
 * material.
 */
public class PQCKeyPacketTest
    extends AbstractPacketTest
{
    private static final int[] SIGNATURE_ALGORITHMS = {
        PublicKeyAlgorithmTags.MLDSA65_Ed25519, PublicKeyAlgorithmTags.MLDSA87_Ed448,
        PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s, PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f, PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s
    };
    private static final int[] KEM_ALGORITHMS = {
        PublicKeyAlgorithmTags.MLKEM768_X25519, PublicKeyAlgorithmTags.MLKEM1024_X448
    };

    private final SecureRandom random = new SecureRandom();

    @Override
    public String getName()
    {
        return "PQCKeyPacketTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testArtifactLengths();
        testPredicates();
        testKeyVersionBinding();
        testMLKEMCompositeKeyRoundTrip();
        testMLDSACompositeKeyRoundTrip();
        testSLHDSAKeyRoundTrip();
        testComponentLengthChecks();
        testTruncatedKeyMaterialIsRejected();
        testPKESKRoundTrip();
        testSignaturePacketRoundTrip();
        testTruncatedSignatureIsRejected();
    }

    /**
     * The artifact lengths of RFC 9980 Tables 3, 4, 6, 7 and 8.
     */
    private void testArtifactLengths()
    {
        isEquals(32, MLKEMCompositePublicBCPGKey.getECDHPublicKeyLength(PublicKeyAlgorithmTags.MLKEM768_X25519));
        isEquals(56, MLKEMCompositePublicBCPGKey.getECDHPublicKeyLength(PublicKeyAlgorithmTags.MLKEM1024_X448));
        isEquals(1184, MLKEMCompositePublicBCPGKey.getMLKEMPublicKeyLength(PublicKeyAlgorithmTags.MLKEM768_X25519));
        isEquals(1568, MLKEMCompositePublicBCPGKey.getMLKEMPublicKeyLength(PublicKeyAlgorithmTags.MLKEM1024_X448));
        isEquals(1088, MLKEMCompositePublicBCPGKey.getMLKEMCiphertextLength(PublicKeyAlgorithmTags.MLKEM768_X25519));
        isEquals(1568, MLKEMCompositePublicBCPGKey.getMLKEMCiphertextLength(PublicKeyAlgorithmTags.MLKEM1024_X448));
        isEquals(32 + 64, MLKEMCompositeSecretBCPGKey.getLength(PublicKeyAlgorithmTags.MLKEM768_X25519));
        isEquals(56 + 64, MLKEMCompositeSecretBCPGKey.getLength(PublicKeyAlgorithmTags.MLKEM1024_X448));

        isEquals(32, MLDSACompositePublicBCPGKey.getEdDSAPublicKeyLength(PublicKeyAlgorithmTags.MLDSA65_Ed25519));
        isEquals(57, MLDSACompositePublicBCPGKey.getEdDSAPublicKeyLength(PublicKeyAlgorithmTags.MLDSA87_Ed448));
        isEquals(1952, MLDSACompositePublicBCPGKey.getMLDSAPublicKeyLength(PublicKeyAlgorithmTags.MLDSA65_Ed25519));
        isEquals(2592, MLDSACompositePublicBCPGKey.getMLDSAPublicKeyLength(PublicKeyAlgorithmTags.MLDSA87_Ed448));
        isEquals(64 + 3309, MLDSACompositePublicBCPGKey.getSignatureLength(PublicKeyAlgorithmTags.MLDSA65_Ed25519));
        isEquals(114 + 4627, MLDSACompositePublicBCPGKey.getSignatureLength(PublicKeyAlgorithmTags.MLDSA87_Ed448));
        isEquals(32 + 32, MLDSACompositeSecretBCPGKey.getLength(PublicKeyAlgorithmTags.MLDSA65_Ed25519));
        isEquals(57 + 32, MLDSACompositeSecretBCPGKey.getLength(PublicKeyAlgorithmTags.MLDSA87_Ed448));

        isEquals(32, SLHDSAPublicBCPGKey.getLength(PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s));
        isEquals(32, SLHDSAPublicBCPGKey.getLength(PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f));
        isEquals(64, SLHDSAPublicBCPGKey.getLength(PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s));
        isEquals(64, SLHDSASecretBCPGKey.getLength(PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s));
        isEquals(128, SLHDSASecretBCPGKey.getLength(PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s));
        isEquals(7856, SLHDSAPublicBCPGKey.getSignatureLength(PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s));
        isEquals(17088, SLHDSAPublicBCPGKey.getSignatureLength(PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f));
        isEquals(29792, SLHDSAPublicBCPGKey.getSignatureLength(PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s));

        try
        {
            MLKEMCompositePublicBCPGKey.getLength(PublicKeyAlgorithmTags.X25519);
            fail("X25519 is not an ML-KEM composite algorithm");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void testPredicates()
    {
        for (int i = 0; i != SIGNATURE_ALGORITHMS.length; i++)
        {
            int alg = SIGNATURE_ALGORITHMS[i];
            isTrue(PublicKeyUtils.isPQCAlgorithm(alg));
            isTrue(PublicKeyUtils.isSigningAlgorithm(alg));
            isFalse(PublicKeyUtils.isEncryptionAlgorithm(alg));
            isFalse(PublicKeyUtils.isMLKEMCompositeAlgorithm(alg));
        }
        for (int i = 0; i != KEM_ALGORITHMS.length; i++)
        {
            int alg = KEM_ALGORITHMS[i];
            isTrue(PublicKeyUtils.isPQCAlgorithm(alg));
            isTrue(PublicKeyUtils.isEncryptionAlgorithm(alg));
            isFalse(PublicKeyUtils.isSigningAlgorithm(alg));
            isTrue(PublicKeyUtils.isMLKEMCompositeAlgorithm(alg));
        }
        isTrue(PublicKeyUtils.isMLDSACompositeAlgorithm(PublicKeyAlgorithmTags.MLDSA65_Ed25519));
        isTrue(PublicKeyUtils.isMLDSACompositeAlgorithm(PublicKeyAlgorithmTags.MLDSA87_Ed448));
        isFalse(PublicKeyUtils.isMLDSACompositeAlgorithm(PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s));
        isTrue(PublicKeyUtils.isSLHDSAAlgorithm(PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s));
        isFalse(PublicKeyUtils.isPQCAlgorithm(PublicKeyAlgorithmTags.Ed25519));
        isFalse(PublicKeyUtils.isPQCAlgorithm(PublicKeyAlgorithmTags.X448));
        isFalse(PublicKeyUtils.isPQCAlgorithm(29));
        isFalse(PublicKeyUtils.isPQCAlgorithm(37));
    }

    /**
     * RFC 9980 sec. 3.5: v6 only, except ML-KEM-768+X25519 which is also allowed in v4 keys.
     */
    private void testKeyVersionBinding()
    {
        for (int i = 0; i != SIGNATURE_ALGORITHMS.length; i++)
        {
            isTrue(PublicKeyUtils.isAlgorithmAllowedForKeyVersion(SIGNATURE_ALGORITHMS[i], PublicKeyPacket.VERSION_6));
            isFalse(PublicKeyUtils.isAlgorithmAllowedForKeyVersion(SIGNATURE_ALGORITHMS[i], PublicKeyPacket.VERSION_4));
            isFalse(PublicKeyUtils.isAlgorithmAllowedForKeyVersion(SIGNATURE_ALGORITHMS[i], PublicKeyPacket.LIBREPGP_5));
        }
        isTrue(PublicKeyUtils.isAlgorithmAllowedForKeyVersion(PublicKeyAlgorithmTags.MLKEM768_X25519, PublicKeyPacket.VERSION_6));
        isTrue(PublicKeyUtils.isAlgorithmAllowedForKeyVersion(PublicKeyAlgorithmTags.MLKEM768_X25519, PublicKeyPacket.VERSION_4));
        isFalse(PublicKeyUtils.isAlgorithmAllowedForKeyVersion(PublicKeyAlgorithmTags.MLKEM768_X25519, PublicKeyPacket.VERSION_3));
        isTrue(PublicKeyUtils.isAlgorithmAllowedForKeyVersion(PublicKeyAlgorithmTags.MLKEM1024_X448, PublicKeyPacket.VERSION_6));
        isFalse(PublicKeyUtils.isAlgorithmAllowedForKeyVersion(PublicKeyAlgorithmTags.MLKEM1024_X448, PublicKeyPacket.VERSION_4));
        // no opinion on the traditional algorithms
        isTrue(PublicKeyUtils.isAlgorithmAllowedForKeyVersion(PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyPacket.VERSION_3));

        // the generating constructor enforces the rule
        byte[] ecdh = new byte[32];
        byte[] mlkem = new byte[1184];
        new PublicKeyPacket(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.MLKEM768_X25519, new Date(),
            new MLKEMCompositePublicBCPGKey(PublicKeyAlgorithmTags.MLKEM768_X25519, ecdh, mlkem));
        try
        {
            new PublicKeyPacket(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.MLDSA65_Ed25519, new Date(),
                new MLDSACompositePublicBCPGKey(PublicKeyAlgorithmTags.MLDSA65_Ed25519, new byte[32], new byte[1952]));
            fail("v4 ML-DSA-65+Ed25519 key MUST be rejected");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage().indexOf("RFC 9980 sec. 3.5") >= 0);
        }
        try
        {
            new PublicSubkeyPacket(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.MLKEM1024_X448, new Date(),
                new MLKEMCompositePublicBCPGKey(PublicKeyAlgorithmTags.MLKEM1024_X448, new byte[56], new byte[1568]));
            fail("v4 ML-KEM-1024+X448 subkey MUST be rejected");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage().indexOf("RFC 9980 sec. 3.5") >= 0);
        }
    }

    private byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        random.nextBytes(b);
        return b;
    }

    private void testMLKEMCompositeKeyRoundTrip()
        throws IOException
    {
        for (int i = 0; i != KEM_ALGORITHMS.length; i++)
        {
            int alg = KEM_ALGORITHMS[i];
            byte[] ecdh = randomBytes(MLKEMCompositePublicBCPGKey.getECDHPublicKeyLength(alg));
            byte[] mlkem = randomBytes(MLKEMCompositePublicBCPGKey.getMLKEMPublicKeyLength(alg));
            MLKEMCompositePublicBCPGKey pub = new MLKEMCompositePublicBCPGKey(alg, ecdh, mlkem);
            isEquals(alg, pub.getAlgorithm());
            isEncodingEqual(ecdh, pub.getECDHPublicKey());
            isEncodingEqual(mlkem, pub.getMLKEMPublicKey());
            isEncodingEqual(Arrays.concatenate(ecdh, mlkem), pub.getEncoded());

            PublicKeyPacket packet = new PublicKeyPacket(PublicKeyPacket.VERSION_6, alg, new Date(1000000L * 1000), pub);
            byte[] encoded = packet.getEncoded(PacketFormat.CURRENT);
            // v6 key packets carry the octet count of the key material (RFC 9580 sec. 5.5.2): the fixed total
            int keyOctets = ((encoded[encoded.length - pub.getEncoded().length - 4] & 0xff) << 24)
                | ((encoded[encoded.length - pub.getEncoded().length - 3] & 0xff) << 16)
                | ((encoded[encoded.length - pub.getEncoded().length - 2] & 0xff) << 8)
                | (encoded[encoded.length - pub.getEncoded().length - 1] & 0xff);
            isEquals(MLKEMCompositePublicBCPGKey.getLength(alg), keyOctets);

            PublicKeyPacket parsed = (PublicKeyPacket)new BCPGInputStream(new ByteArrayInputStream(encoded)).readPacket();
            isEquals(alg, parsed.getAlgorithm());
            isTrue(parsed.getKey() instanceof MLKEMCompositePublicBCPGKey);
            MLKEMCompositePublicBCPGKey parsedKey = (MLKEMCompositePublicBCPGKey)parsed.getKey();
            isEncodingEqual(ecdh, parsedKey.getECDHPublicKey());
            isEncodingEqual(mlkem, parsedKey.getMLKEMPublicKey());
            isEncodingEqual(packet.getEncoded(PacketFormat.CURRENT), parsed.getEncoded(PacketFormat.CURRENT));

            // subkey packet too
            PublicSubkeyPacket subkey = new PublicSubkeyPacket(PublicKeyPacket.VERSION_6, alg, new Date(1000000L * 1000), pub);
            PublicKeyPacket parsedSub = (PublicKeyPacket)new BCPGInputStream(new ByteArrayInputStream(subkey.getEncoded(PacketFormat.CURRENT))).readPacket();
            isTrue(parsedSub instanceof PublicSubkeyPacket);
            isEncodingEqual(pub.getEncoded(), parsedSub.getKey().getEncoded());

            // secret key
            byte[] ecdhSec = randomBytes(MLKEMCompositeSecretBCPGKey.getECDHSecretKeyLength(alg));
            byte[] seed = randomBytes(MLKEMCompositeSecretBCPGKey.MLKEM_SEED_LENGTH);
            MLKEMCompositeSecretBCPGKey sec = new MLKEMCompositeSecretBCPGKey(alg, ecdhSec, seed);
            isEncodingEqual(ecdhSec, sec.getECDHSecretKey());
            isEncodingEqual(seed, sec.getMLKEMSeed());
            MLKEMCompositeSecretBCPGKey parsedSec = new MLKEMCompositeSecretBCPGKey(alg, new BCPGInputStream(new ByteArrayInputStream(sec.getEncoded())));
            isEncodingEqual(sec.getEncoded(), parsedSec.getEncoded());
        }
    }

    private void testMLDSACompositeKeyRoundTrip()
        throws IOException
    {
        int[] algs = { PublicKeyAlgorithmTags.MLDSA65_Ed25519, PublicKeyAlgorithmTags.MLDSA87_Ed448 };
        for (int i = 0; i != algs.length; i++)
        {
            int alg = algs[i];
            byte[] eddsa = randomBytes(MLDSACompositePublicBCPGKey.getEdDSAPublicKeyLength(alg));
            byte[] mldsa = randomBytes(MLDSACompositePublicBCPGKey.getMLDSAPublicKeyLength(alg));
            MLDSACompositePublicBCPGKey pub = new MLDSACompositePublicBCPGKey(alg, eddsa, mldsa);
            isEncodingEqual(eddsa, pub.getEdDSAPublicKey());
            isEncodingEqual(mldsa, pub.getMLDSAPublicKey());

            PublicKeyPacket packet = new PublicKeyPacket(PublicKeyPacket.VERSION_6, alg, new Date(1000000L * 1000), pub);
            PublicKeyPacket parsed = (PublicKeyPacket)new BCPGInputStream(new ByteArrayInputStream(packet.getEncoded(PacketFormat.CURRENT))).readPacket();
            isTrue(parsed.getKey() instanceof MLDSACompositePublicBCPGKey);
            isEncodingEqual(eddsa, ((MLDSACompositePublicBCPGKey)parsed.getKey()).getEdDSAPublicKey());
            isEncodingEqual(mldsa, ((MLDSACompositePublicBCPGKey)parsed.getKey()).getMLDSAPublicKey());
            isEncodingEqual(packet.getEncoded(PacketFormat.CURRENT), parsed.getEncoded(PacketFormat.CURRENT));

            byte[] eddsaSec = randomBytes(MLDSACompositeSecretBCPGKey.getEdDSASecretKeyLength(alg));
            byte[] seed = randomBytes(MLDSACompositeSecretBCPGKey.MLDSA_SEED_LENGTH);
            MLDSACompositeSecretBCPGKey sec = new MLDSACompositeSecretBCPGKey(alg, eddsaSec, seed);
            isEncodingEqual(eddsaSec, sec.getEdDSASecretKey());
            isEncodingEqual(seed, sec.getMLDSASeed());
            MLDSACompositeSecretBCPGKey parsedSec = new MLDSACompositeSecretBCPGKey(alg, new BCPGInputStream(new ByteArrayInputStream(sec.getEncoded())));
            isEncodingEqual(sec.getEncoded(), parsedSec.getEncoded());
        }
    }

    private void testSLHDSAKeyRoundTrip()
        throws IOException
    {
        int[] algs = { PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s, PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f, PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s };
        for (int i = 0; i != algs.length; i++)
        {
            int alg = algs[i];
            byte[] pk = randomBytes(SLHDSAPublicBCPGKey.getLength(alg));
            SLHDSAPublicBCPGKey pub = new SLHDSAPublicBCPGKey(alg, pk);
            isEquals(alg, pub.getAlgorithm());
            isEncodingEqual(pk, pub.getKey());

            PublicKeyPacket packet = new PublicKeyPacket(PublicKeyPacket.VERSION_6, alg, new Date(1000000L * 1000), pub);
            PublicKeyPacket parsed = (PublicKeyPacket)new BCPGInputStream(new ByteArrayInputStream(packet.getEncoded(PacketFormat.CURRENT))).readPacket();
            isTrue(parsed.getKey() instanceof SLHDSAPublicBCPGKey);
            isEncodingEqual(pk, parsed.getKey().getEncoded());
            isEncodingEqual(packet.getEncoded(PacketFormat.CURRENT), parsed.getEncoded(PacketFormat.CURRENT));

            byte[] sk = randomBytes(SLHDSASecretBCPGKey.getLength(alg));
            SLHDSASecretBCPGKey sec = new SLHDSASecretBCPGKey(alg, sk);
            SLHDSASecretBCPGKey parsedSec = new SLHDSASecretBCPGKey(alg, new BCPGInputStream(new ByteArrayInputStream(sk)));
            isEncodingEqual(sec.getEncoded(), parsedSec.getEncoded());
        }
    }

    private void testComponentLengthChecks()
    {
        try
        {
            new MLKEMCompositePublicBCPGKey(PublicKeyAlgorithmTags.MLKEM768_X25519, new byte[56], new byte[1184]);
            fail("X448-sized ECDH key with ML-KEM-768+X25519 MUST be rejected");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("ECDH public key") >= 0);
        }
        try
        {
            new MLKEMCompositePublicBCPGKey(PublicKeyAlgorithmTags.MLKEM768_X25519, new byte[32], new byte[1568]);
            fail("ML-KEM-1024-sized key with ML-KEM-768+X25519 MUST be rejected");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("ML-KEM public key") >= 0);
        }
        try
        {
            new MLKEMCompositeSecretBCPGKey(PublicKeyAlgorithmTags.MLKEM768_X25519, new byte[32], new byte[32]);
            fail("32 octet ML-KEM seed MUST be rejected");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("ML-KEM seed") >= 0);
        }
        try
        {
            new MLDSACompositePublicBCPGKey(PublicKeyAlgorithmTags.MLDSA87_Ed448, new byte[32], new byte[2592]);
            fail("Ed25519-sized key with ML-DSA-87+Ed448 MUST be rejected");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("EdDSA public key") >= 0);
        }
        try
        {
            new MLDSACompositeSecretBCPGKey(PublicKeyAlgorithmTags.MLDSA65_Ed25519, new byte[32], new byte[64]);
            fail("64 octet ML-DSA seed MUST be rejected");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("ML-DSA seed") >= 0);
        }
        try
        {
            new SLHDSAPublicBCPGKey(PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s, new byte[32]);
            fail("32 octet SLH-DSA-SHAKE-256s public key MUST be rejected");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void testTruncatedKeyMaterialIsRejected()
        throws IOException
    {
        int[] algs = { PublicKeyAlgorithmTags.MLKEM768_X25519, PublicKeyAlgorithmTags.MLDSA65_Ed25519, PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s };
        for (int i = 0; i != algs.length; i++)
        {
            int alg = algs[i];
            PublicKeyPacket packet;
            if (alg == PublicKeyAlgorithmTags.MLKEM768_X25519)
            {
                packet = new PublicKeyPacket(PublicKeyPacket.VERSION_6, alg, new Date(), new MLKEMCompositePublicBCPGKey(alg, randomBytes(32), randomBytes(1184)));
            }
            else if (alg == PublicKeyAlgorithmTags.MLDSA65_Ed25519)
            {
                packet = new PublicKeyPacket(PublicKeyPacket.VERSION_6, alg, new Date(), new MLDSACompositePublicBCPGKey(alg, randomBytes(32), randomBytes(1952)));
            }
            else
            {
                packet = new PublicKeyPacket(PublicKeyPacket.VERSION_6, alg, new Date(), new SLHDSAPublicBCPGKey(alg, randomBytes(32)));
            }
            // drop the last octet of the key material and re-frame: a body one octet short of the fixed length
            byte[] body = packet.getEncodedContents();
            byte[] shortBody = Arrays.copyOf(body, body.length - 1);
            try
            {
                new BCPGInputStream(new ByteArrayInputStream(framePacket(packet.getPacketTag(), shortBody))).readPacket();
                fail("truncated key material MUST be rejected for algorithm " + alg);
            }
            catch (IOException e)
            {
                // expected: EOF inside the fixed-length key or a malformed packet
            }
        }
    }

    private void testPKESKRoundTrip()
        throws IOException
    {
        for (int i = 0; i != KEM_ALGORITHMS.length; i++)
        {
            int alg = KEM_ALGORITHMS[i];
            int ecdhLen = MLKEMCompositePublicBCPGKey.getECDHPublicKeyLength(alg);
            int ctLen = MLKEMCompositePublicBCPGKey.getMLKEMCiphertextLength(alg);
            byte[] wrapped = randomBytes(40);
            // v6 PKESK: ecdhCT || mlkemCT || len || C
            byte[] v6Data = Arrays.concatenate(randomBytes(ecdhLen), randomBytes(ctLen), new byte[]{ (byte)wrapped.length }, wrapped);
            PublicKeyEncSessionPacket v6 = PublicKeyEncSessionPacket.createV6PKESKPacket(6, randomBytes(32), alg, new byte[][]{ v6Data });
            PublicKeyEncSessionPacket parsed = (PublicKeyEncSessionPacket)new BCPGInputStream(new ByteArrayInputStream(v6.getEncoded(PacketFormat.CURRENT))).readPacket();
            isEquals(PublicKeyEncSessionPacket.VERSION_6, parsed.getVersion());
            isEquals(alg, parsed.getAlgorithm());
            isEquals(1, parsed.getEncSessionKey().length);
            isEncodingEqual(v6Data, parsed.getEncSessionKey()[0]);

            // v3 PKESK: ecdhCT || mlkemCT || len || symAlg || C
            byte[] v3Data = Arrays.concatenate(randomBytes(ecdhLen), randomBytes(ctLen), new byte[]{ (byte)(wrapped.length + 1), 9 }, wrapped);
            PublicKeyEncSessionPacket v3 = PublicKeyEncSessionPacket.createV3PKESKPacket(0x1122334455667788L, alg, new byte[][]{ v3Data });
            parsed = (PublicKeyEncSessionPacket)new BCPGInputStream(new ByteArrayInputStream(v3.getEncoded(PacketFormat.LEGACY))).readPacket();
            isEquals(PublicKeyEncSessionPacket.VERSION_3, parsed.getVersion());
            isEquals(0x1122334455667788L, parsed.getKeyID());
            isEncodingEqual(v3Data, parsed.getEncSessionKey()[0]);
        }
    }

    private SignaturePacket signaturePacket(int alg, byte[] signature)
    {
        return new SignaturePacket(SignaturePacket.VERSION_6, 0x00 /* binary document */, 0L, alg, HashAlgorithmTags.SHA256,
            new SignatureSubpacket[]{ new SignatureCreationTime(true, new Date(1000000L * 1000)) }, new SignatureSubpacket[0],
            new byte[]{ 1, 2 }, signature, randomBytes(16));
    }

    private void testSignaturePacketRoundTrip()
        throws IOException
    {
        for (int i = 0; i != SIGNATURE_ALGORITHMS.length; i++)
        {
            int alg = SIGNATURE_ALGORITHMS[i];
            int sigLen = PublicKeyUtils.isMLDSACompositeAlgorithm(alg)
                ? MLDSACompositePublicBCPGKey.getSignatureLength(alg) : SLHDSAPublicBCPGKey.getSignatureLength(alg);
            byte[] signature = randomBytes(sigLen);
            SignaturePacket packet = signaturePacket(alg, signature);
            SignaturePacket parsed = (SignaturePacket)new BCPGInputStream(new ByteArrayInputStream(packet.getEncoded(PacketFormat.CURRENT))).readPacket();
            isEquals(alg, parsed.getKeyAlgorithm());
            isNull("RFC 9980 signatures are raw octet strings, not MPIs", parsed.getSignature());
            isEncodingEqual(signature, parsed.getSignatureBytes());
            isEncodingEqual(packet.getEncoded(PacketFormat.CURRENT), parsed.getEncoded(PacketFormat.CURRENT));
        }
    }

    private void testTruncatedSignatureIsRejected()
        throws IOException
    {
        for (int i = 0; i != SIGNATURE_ALGORITHMS.length; i++)
        {
            int alg = SIGNATURE_ALGORITHMS[i];
            int sigLen = PublicKeyUtils.isMLDSACompositeAlgorithm(alg)
                ? MLDSACompositePublicBCPGKey.getSignatureLength(alg) : SLHDSAPublicBCPGKey.getSignatureLength(alg);
            SignaturePacket packet = signaturePacket(alg, randomBytes(sigLen));
            byte[] encoded = packet.getEncoded(PacketFormat.CURRENT);
            // shorten the body by the final octet of the signature and re-frame it
            byte[] contents = Arrays.copyOfRange(encoded, encoded.length - bodyLength(encoded), encoded.length);
            byte[] shortContents = Arrays.copyOf(contents, contents.length - 1);
            try
            {
                new BCPGInputStream(new ByteArrayInputStream(framePacket(packet.getPacketTag(), shortContents))).readPacket();
                fail("truncated signature MUST be rejected for algorithm " + alg);
            }
            catch (IOException e)
            {
                // expected
            }
        }
    }

    /**
     * Frame a packet body in the new packet format with a five-octet length header (RFC 9580 sec. 4.2.1.3).
     */
    private static byte[] framePacket(int tag, byte[] body)
    {
        byte[] header = {
            (byte)(0xc0 | tag), (byte)0xff,
            (byte)(body.length >>> 24), (byte)(body.length >>> 16), (byte)(body.length >>> 8), (byte)body.length
        };
        return Arrays.concatenate(header, body);
    }

    /**
     * Length of the body of a new-format packet, read from its length header.
     */
    private int bodyLength(byte[] encoded)
    {
        int hdr = encoded[0] & 0xff;
        isTrue("new packet format expected", (hdr & 0xc0) == 0xc0);
        int first = encoded[1] & 0xff;
        if (first < 192)
        {
            return first;
        }
        if (first < 224)
        {
            return ((first - 192) << 8) + (encoded[2] & 0xff) + 192;
        }
        return ((encoded[2] & 0xff) << 24) | ((encoded[3] & 0xff) << 16) | ((encoded[4] & 0xff) << 8) | (encoded[5] & 0xff);
    }

    public static void main(String[] args)
    {
        runTest(new PQCKeyPacketTest());
    }
}
