package org.bouncycastle.mls.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.hpke.HPKE;
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
        int getHashLength();
        byte[] extract(byte[] salt, byte[] ikm);
        byte[] expand(byte [] prk, byte[] info, int length);
    }

    public interface AEAD {
        int getKeySize();
        int getNonceSize();
    }

    static class HKDF implements KDF {
        private final HKDFBytesGenerator kdf;

        HKDF(Digest digest) {
            kdf = new HKDFBytesGenerator(digest);
        }

        @Override
        public int getHashLength() {
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

    static class AES128GCM implements AEAD {

        @Override
        public int getKeySize() {
            return 16;
        }

        @Override
        public int getNonceSize() {
            return 12;
        }
    }

    static class AES256GCM implements AEAD {

        @Override
        public int getKeySize() {
            return 32;
        }

        @Override
        public int getNonceSize() {
            return 12;
        }
    }

    static class ChaCha20Poly1305 implements AEAD {

        @Override
        public int getKeySize() {
            return 32;
        }

        @Override
        public int getNonceSize() {
            return 12;
        }
    }

    final KDF kdf;
    final AEAD aead;
    final HPKE hpke;

    public CipherSuite(short suite) {
        // TODO Configure digest
        // TODO Configure KEM
        // TODO Configure Signature
        switch (suite) {
            case MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
                kdf = new HKDF(new SHA256Digest());
                aead = new AES128GCM();
                hpke = new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);
                break;

            case MLS_128_DHKEMP256_AES128GCM_SHA256_P256:
                kdf = new HKDF(new SHA256Digest());
                aead = new AES128GCM();
                hpke = new HPKE(HPKE.mode_base, HPKE.kem_P256_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);
                break;

            case MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
                kdf = new HKDF(new SHA256Digest());
                aead = new ChaCha20Poly1305();
                hpke = new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_CHACHA20_POLY1305);
                break;

            case MLS_256_DHKEMP384_AES256GCM_SHA384_P384:
                kdf = new HKDF(new SHA384Digest());
                aead = new AES256GCM();
                hpke = new HPKE(HPKE.mode_base, HPKE.kem_P384_SHA348, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256);
                break;

            case MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
                kdf = new HKDF(new SHA512Digest());
                aead = new AES256GCM();
                hpke = new HPKE(HPKE.mode_base, HPKE.kem_X448_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_AES_GCM256);
                break;

            case MLS_256_DHKEMP521_AES256GCM_SHA512_P521:
                kdf = new HKDF(new SHA512Digest());
                aead = new AES256GCM();
                hpke = new HPKE(HPKE.mode_base, HPKE.kem_P521_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_AES_GCM256);
                break;

            case MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
                kdf = new HKDF(new SHA512Digest());
                aead = new ChaCha20Poly1305();
                hpke = new HPKE(HPKE.mode_base, HPKE.kem_X448_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_CHACHA20_POLY1305);
                break;

            default:
                throw new IllegalArgumentException("Unsupported ciphersuite: " + suite);
        }
    }

    public KDF getKDF() {
        return kdf;
    }

    public AEAD getAEAD() { return aead; }

    public HPKE getHPKE() { return hpke; }
}
