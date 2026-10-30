package org.bouncycastle.mls.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.crypto.bc.BcMlsAead;
import org.bouncycastle.mls.crypto.bc.BcMlsKdf;
import org.bouncycastle.mls.crypto.bc.BcMlsSigner;

public class MlsCipherSuite
{
    public static class GenericContent
        implements MLSOutputStream.Writable
    {

        private byte[] label;
        private byte[] content;

        public GenericContent(String label, byte[] content)
        {
            this.label = ("MLS 1.0 " + label).getBytes(StandardCharsets.UTF_8);
            this.content = content;
        }

        @Override
        public void writeTo(MLSOutputStream stream)
            throws IOException
        {
            stream.writeOpaque(label);
            stream.writeOpaque(content);
        }
    }

    public static class RefHash
        implements MLSOutputStream.Writable
    {

        public byte[] label;
        public byte[] value;

        public RefHash(byte[] label, byte[] value)
        {
            this.label = label;
            this.value = value;
        }

        @Override
        public void writeTo(MLSOutputStream stream)
            throws IOException
        {
            stream.writeOpaque(label);
            stream.writeOpaque(value);
        }
    }


    public static final short MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001;
    public static final short MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002;
    public static final short MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003;
    public static final short MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004;
    public static final short MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005;
    public static final short MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006;
    public static final short MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007;

    public static final MlsCipherSuite BCMLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = new MlsCipherSuite(MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, new BcMlsSigner(MlsSigner.ed25519), new BcMlsKdf(new SHA256Digest()), new BcMlsAead(HPKE.aead_AES_GCM128), new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128));
    public static final MlsCipherSuite BCMLS_128_DHKEMP256_AES128GCM_SHA256_P256 = new MlsCipherSuite(MLS_128_DHKEMP256_AES128GCM_SHA256_P256, new BcMlsSigner(MlsSigner.ecdsa_secp256r1_sha256), new BcMlsKdf(new SHA256Digest()), new BcMlsAead(HPKE.aead_AES_GCM128), new HPKE(HPKE.mode_base, HPKE.kem_P256_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128));
    public static final MlsCipherSuite BCMLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = new MlsCipherSuite(MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, new BcMlsSigner(MlsSigner.ed25519), new BcMlsKdf(new SHA256Digest()), new BcMlsAead(HPKE.aead_CHACHA20_POLY1305), new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_CHACHA20_POLY1305));
    public static final MlsCipherSuite BCMLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = new MlsCipherSuite(MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448, new BcMlsSigner(MlsSigner.ed448), new BcMlsKdf(new SHA512Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_X448_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_AES_GCM256));
    public static final MlsCipherSuite BCMLS_256_DHKEMP521_AES256GCM_SHA512_P521 = new MlsCipherSuite(MLS_256_DHKEMP521_AES256GCM_SHA512_P521, new BcMlsSigner(MlsSigner.ecdsa_secp521r1_sha512), new BcMlsKdf(new SHA512Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_P521_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_AES_GCM256));
    public static final MlsCipherSuite BCMLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = new MlsCipherSuite(MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448, new BcMlsSigner(MlsSigner.ed448), new BcMlsKdf(new SHA512Digest()), new BcMlsAead(HPKE.aead_CHACHA20_POLY1305), new HPKE(HPKE.mode_base, HPKE.kem_X448_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_CHACHA20_POLY1305));
    public static final MlsCipherSuite BCMLS_256_DHKEMP384_AES256GCM_SHA384_P384 = new MlsCipherSuite(MLS_256_DHKEMP384_AES256GCM_SHA384_P384, new BcMlsSigner(MlsSigner.ecdsa_secp384r1_sha384), new BcMlsKdf(new SHA384Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_P384_SHA384, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256));

    /*
     * The post-quantum cipher suites of draft-ietf-mls-pq-ciphersuites-06, in the draft's TBD1 to TBD11
     * order. IANA has not assigned their code points yet: the values below are placeholders in the
     * RFC 9420 private use range (0xF000-0xFFFF), will change to the assigned values when the RFC is
     * published, and only interoperate with other implementations using the same placeholders. The
     * KEMs are those of draft-ietf-hpke-pq (MLKEM768X25519 is X-Wing), the KDF is HKDF with the suite's
     * hash, and the ML-DSA suites sign with pure ML-DSA and the empty context per draft-ietf-tls-mldsa.
     */
    public static final short MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519 = (short)0xF001;
    public static final short MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519 = (short)0xF002;
    public static final short MLS_128_MLKEM768P256_AES128GCM_SHA256_P256 = (short)0xF003;
    public static final short MLS_128_MLKEM768P256_AES256GCM_SHA384_P256 = (short)0xF004;
    public static final short MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384 = (short)0xF005;
    public static final short MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519 = (short)0xF006;
    public static final short MLS_128_MLKEM768_AES256GCM_SHA384_P256 = (short)0xF007;
    public static final short MLS_192_MLKEM1024_AES256GCM_SHA384_P384 = (short)0xF008;
    public static final short MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44 = (short)0xF009;
    public static final short MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65 = (short)0xF00A;
    public static final short MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 = (short)0xF00B;

    public static final MlsCipherSuite BCMLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519 = new MlsCipherSuite(MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519, new BcMlsSigner(MlsSigner.ed25519), new BcMlsKdf(new SHA256Digest()), new BcMlsAead(HPKE.aead_AES_GCM128), new HPKE(HPKE.mode_base, HPKE.kem_MLKEM768_X25519, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128));
    public static final MlsCipherSuite BCMLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519 = new MlsCipherSuite(MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519, new BcMlsSigner(MlsSigner.ed25519), new BcMlsKdf(new SHA384Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_MLKEM768_X25519, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256));
    public static final MlsCipherSuite BCMLS_128_MLKEM768P256_AES128GCM_SHA256_P256 = new MlsCipherSuite(MLS_128_MLKEM768P256_AES128GCM_SHA256_P256, new BcMlsSigner(MlsSigner.ecdsa_secp256r1_sha256), new BcMlsKdf(new SHA256Digest()), new BcMlsAead(HPKE.aead_AES_GCM128), new HPKE(HPKE.mode_base, HPKE.kem_MLKEM768_P256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128));
    public static final MlsCipherSuite BCMLS_128_MLKEM768P256_AES256GCM_SHA384_P256 = new MlsCipherSuite(MLS_128_MLKEM768P256_AES256GCM_SHA384_P256, new BcMlsSigner(MlsSigner.ecdsa_secp256r1_sha256), new BcMlsKdf(new SHA384Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_MLKEM768_P256, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256));
    public static final MlsCipherSuite BCMLS_192_MLKEM1024P384_AES256GCM_SHA384_P384 = new MlsCipherSuite(MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384, new BcMlsSigner(MlsSigner.ecdsa_secp384r1_sha384), new BcMlsKdf(new SHA384Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_MLKEM1024_P384, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256));
    public static final MlsCipherSuite BCMLS_128_MLKEM768_AES256GCM_SHA384_Ed25519 = new MlsCipherSuite(MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519, new BcMlsSigner(MlsSigner.ed25519), new BcMlsKdf(new SHA384Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_ML_KEM_768, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256));
    public static final MlsCipherSuite BCMLS_128_MLKEM768_AES256GCM_SHA384_P256 = new MlsCipherSuite(MLS_128_MLKEM768_AES256GCM_SHA384_P256, new BcMlsSigner(MlsSigner.ecdsa_secp256r1_sha256), new BcMlsKdf(new SHA384Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_ML_KEM_768, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256));
    public static final MlsCipherSuite BCMLS_192_MLKEM1024_AES256GCM_SHA384_P384 = new MlsCipherSuite(MLS_192_MLKEM1024_AES256GCM_SHA384_P384, new BcMlsSigner(MlsSigner.ecdsa_secp384r1_sha384), new BcMlsKdf(new SHA384Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_ML_KEM_1024, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256));
    public static final MlsCipherSuite BCMLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44 = new MlsCipherSuite(MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44, new BcMlsSigner(MlsSigner.mldsa44), new BcMlsKdf(new SHA384Digest()), new BcMlsAead(HPKE.aead_CHACHA20_POLY1305), new HPKE(HPKE.mode_base, HPKE.kem_MLKEM768_X25519, HPKE.kdf_HKDF_SHA384, HPKE.aead_CHACHA20_POLY1305));
    public static final MlsCipherSuite BCMLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65 = new MlsCipherSuite(MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65, new BcMlsSigner(MlsSigner.mldsa65), new BcMlsKdf(new SHA384Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_ML_KEM_768, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256));
    public static final MlsCipherSuite BCMLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 = new MlsCipherSuite(MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87, new BcMlsSigner(MlsSigner.mldsa87), new BcMlsKdf(new SHA384Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_ML_KEM_1024, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256));

    /**
     * The RFC 9420 cipher suites; these are the suites a default {@code Capabilities} advertises.
     */
    public static final short[] ALL_SUPPORTED_SUITES = {
        MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
        MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
        MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
        MLS_256_DHKEMP384_AES256GCM_SHA384_P384
    };

    /**
     * The post-quantum cipher suites of draft-ietf-mls-pq-ciphersuites, under placeholder code points
     * (see the note on the constants). They are not in {@link #ALL_SUPPORTED_SUITES}, so a client
     * that wants to offer them adds them to its {@code Capabilities} explicitly.
     */
    public static final short[] PQ_SUITES = {
        MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
        MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
        MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
        MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
        MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
        MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519,
        MLS_128_MLKEM768_AES256GCM_SHA384_P256,
        MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
        MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44,
        MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
        MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87
    };

    private final short suiteID;
    private final MlsSigner signer;
    private final MlsKdf kdf;
    private final MlsAead aead;
    private final Digest digest;
    private final HPKE hpke;

    public MlsCipherSuite(short id, MlsSigner signer, MlsKdf kdf, MlsAead aead, HPKE hpke)
    {
        this.suiteID = id;
        this.signer = signer;
        this.kdf = kdf;
        this.aead = aead;
        this.digest = kdf.getDigest();
        this.hpke = hpke;
    }

    public static MlsCipherSuite getSuite(short id)
        throws Exception
    {
        switch (id)
        {
        case MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
            return BCMLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        case MLS_128_DHKEMP256_AES128GCM_SHA256_P256:
            return BCMLS_128_DHKEMP256_AES128GCM_SHA256_P256;
        case MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
            return BCMLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        case MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
            return BCMLS_256_DHKEMX448_AES256GCM_SHA512_Ed448;
        case MLS_256_DHKEMP521_AES256GCM_SHA512_P521:
            return BCMLS_256_DHKEMP521_AES256GCM_SHA512_P521;
        case MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
            return BCMLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448;
        case MLS_256_DHKEMP384_AES256GCM_SHA384_P384:
            return BCMLS_256_DHKEMP384_AES256GCM_SHA384_P384;
        case MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519:
            return BCMLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;
        case MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519:
            return BCMLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519;
        case MLS_128_MLKEM768P256_AES128GCM_SHA256_P256:
            return BCMLS_128_MLKEM768P256_AES128GCM_SHA256_P256;
        case MLS_128_MLKEM768P256_AES256GCM_SHA384_P256:
            return BCMLS_128_MLKEM768P256_AES256GCM_SHA384_P256;
        case MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384:
            return BCMLS_192_MLKEM1024P384_AES256GCM_SHA384_P384;
        case MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519:
            return BCMLS_128_MLKEM768_AES256GCM_SHA384_Ed25519;
        case MLS_128_MLKEM768_AES256GCM_SHA384_P256:
            return BCMLS_128_MLKEM768_AES256GCM_SHA384_P256;
        case MLS_192_MLKEM1024_AES256GCM_SHA384_P384:
            return BCMLS_192_MLKEM1024_AES256GCM_SHA384_P384;
        case MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44:
            return BCMLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44;
        case MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65:
            return BCMLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65;
        case MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87:
            return BCMLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;
        default:
            throw new Exception("Unkown ciphersuite id");
        }
    }

    public short getSuiteID()
    {
        return suiteID;
    }

    public AsymmetricCipherKeyPair generateSignatureKeyPair()
    {
        return signer.generateSignatureKeyPair();
    }

    public byte[] serializeSignaturePublicKey(AsymmetricKeyParameter key)
    {
        return signer.serializePublicKey(key);
    }

    public byte[] serializeSignaturePrivateKey(AsymmetricKeyParameter key)
    {
        return signer.serializePrivateKey(key);
    }

    public AsymmetricCipherKeyPair deserializeSignaturePrivateKey(byte[] priv)
    {
        return signer.deserializePrivateKey(priv);
    }

    public byte[] signWithLabel(byte[] priv, String label, byte[] content)
        throws IOException, CryptoException
    {
        return signer.signWithLabel(priv, label, content);
    }

    public boolean verifyWithLabel(byte[] pub, String label, byte[] content, byte[] signature)
        throws IOException
    {
        return signer.verifyWithLabel(pub, label, content, signature);
    }

    public byte[] refHash(byte[] value, String label)
        throws IOException
    {
        RefHash refhash = new MlsCipherSuite.RefHash(label.getBytes(StandardCharsets.UTF_8), value);
        byte[] refhashBytes = MLSOutputStream.encode(refhash);
//            return expand(out, getHashLength());
        byte[] out = new byte[kdf.getHashLength()];
        digest.update(refhashBytes, 0, refhashBytes.length);
        digest.doFinal(out, 0);
        return out;
    }

    public byte[] hash(byte[] value)
        throws IOException
    {
        byte[] out = new byte[kdf.getHashLength()];
        digest.update(value, 0, value.length);
        digest.doFinal(out, 0);
        return out;
    }

    public byte[] decryptWithLabel(byte[] priv, String label, byte[] context, byte[] kem_output, byte[] ciphertext)
        throws IOException, InvalidCipherTextException
    {
        GenericContent encryptContext = new GenericContent(label, context);
        byte[] encryptContextBytes = MLSOutputStream.encode(encryptContext);

        AsymmetricCipherKeyPair kp = hpke.deserializePrivateKey(priv, null);
        return hpke.open(kem_output, kp, encryptContextBytes, "".getBytes(), ciphertext, null, null, null);
    }

    public byte[][] encryptWithLabel(byte[] pub, String label, byte[] context, byte[] plaintext)
        throws IOException, InvalidCipherTextException
    {
        GenericContent encryptContext = new GenericContent(label, context);
        byte[] encryptContextBytes = MLSOutputStream.encode(encryptContext);

        // the key is an HPKE (KEM) public key, so it is the HPKE deserialization that applies
        AsymmetricKeyParameter pubKey = hpke.deserializePublicKey(pub);

        return hpke.seal(pubKey, encryptContextBytes, "".getBytes(), plaintext, null, null, null);
    }

    public HPKE getHPKE()
    {
        return hpke;
    }

    public MlsKdf getKDF()
    {
        return kdf;
    }

    public MlsAead getAEAD()
    {
        return aead;
    }
}
