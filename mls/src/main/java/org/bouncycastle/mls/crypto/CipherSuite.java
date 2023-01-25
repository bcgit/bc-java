package org.bouncycastle.mls.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

public class CipherSuite {
    public static final short MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519  = 0x0001 ;
    public static final short MLS_128_DHKEMP256_AES128GCM_SHA256_P256  = 0x0002 ;
    public static final short MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519  = 0x0003 ;
    public static final short MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448  = 0x0004 ;
    public static final short MLS_256_DHKEMP521_AES256GCM_SHA512_P521  = 0x0005 ;
    public static final short MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448  = 0x0006 ;
    public static final short MLS_256_DHKEMP384_AES256GCM_SHA384_P384  = 0x0007 ;

    public interface KDF {
        int hashLength();
        byte[] extract(byte[] salt, byte[] ikm);
        byte[] expand(byte [] prk, byte[] info, int length);
    }

    static class HKDF implements KDF {
        private final HKDFBytesGenerator kdf;

        HKDF(Digest digest) {
            kdf = new HKDFBytesGenerator(digest);
        }

        @Override
        public int hashLength() {
            return kdf.getDigest().getDigestSize();
        }

        @Override
        public byte[] extract(byte[] salt, byte[] ikm) {
            return kdf.extractPRK(salt, ikm);
        }

        @Override
        public byte[] expand(byte[] prk, byte[] info, int length) {
            byte[] okm = new byte[length];
            kdf.init(HKDFParameters.skipExtractParameters(prk, info));
            kdf.generateBytes(okm, 0, okm.length);
            return okm;
        }
    }

    KDF kdf;

    public CipherSuite(short suite) {
        // TODO Configure digest
        // TODO Configure KEM
        // TODO Configure AEAD
        // TODO Configure Signature
        switch (suite) {
            case MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
            case MLS_128_DHKEMP256_AES128GCM_SHA256_P256:
            case MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
                kdf = new HKDF(new SHA256Digest());
                break;

            case MLS_256_DHKEMP384_AES256GCM_SHA384_P384:
                kdf = new HKDF(new SHA384Digest());
                break;

            case MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
            case MLS_256_DHKEMP521_AES256GCM_SHA512_P521:
            case MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
                kdf = new HKDF(new SHA512Digest());
                break;

            default:
                throw new IllegalArgumentException("Unsupported ciphersuite: " + suite);
        }
    }

    public KDF getKDF() {
        return kdf;
    }
}
