package org.bouncycastle.openpgp.operator.bc;

import java.security.SecureRandom;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MLDSACompositePublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SLHDSAPublicBCPGKey;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.Wrapper;
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
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.IDEAEngine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.MLDSAKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SLHDSAKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.Arrays;

class BcImplProvider
{
    static Digest createDigest(int algorithm)
        throws PGPException
    {
        switch (algorithm)
        {
        case HashAlgorithmTags.SHA1:
            return new SHA1Digest();
        case HashAlgorithmTags.SHA224:
            return new SHA224Digest();
        case HashAlgorithmTags.SHA256:
            return new SHA256Digest();
        case HashAlgorithmTags.SHA384:
            return new SHA384Digest();
        case HashAlgorithmTags.SHA512:
            return new SHA512Digest();
        case HashAlgorithmTags.SHA3_224:
            return new SHA3Digest(224);
        case HashAlgorithmTags.SHA3_256:
        case HashAlgorithmTags.SHA3_256_OLD:
            return new SHA3Digest(256);
        case HashAlgorithmTags.SHA3_384:
            return new SHA3Digest(384);
        case HashAlgorithmTags.SHA3_512:
        case HashAlgorithmTags.SHA3_512_OLD:
            return new SHA3Digest(512);
        case HashAlgorithmTags.MD2:
            return new MD2Digest();
        case HashAlgorithmTags.MD5:
            return new MD5Digest();
        case HashAlgorithmTags.RIPEMD160:
            return new RIPEMD160Digest();
        case HashAlgorithmTags.TIGER_192:
            return new TigerDigest();
        default:
            throw new PGPException("cannot recognise digest");
        }
    }

    static Signer createSigner(int keyAlgorithm, int hashAlgorithm, CipherParameters keyParam)
        throws PGPException
    {
        switch (keyAlgorithm)
        {
        case PublicKeyAlgorithmTags.RSA_GENERAL:
        case PublicKeyAlgorithmTags.RSA_SIGN:
            return new RSADigestSigner(createDigest(hashAlgorithm));
        case PublicKeyAlgorithmTags.DSA:
            return new DSADigestSigner(new DSASigner(), createDigest(hashAlgorithm));
        case PublicKeyAlgorithmTags.ECDSA:
            return new DSADigestSigner(new ECDSASigner(), createDigest(hashAlgorithm));
        case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            if (keyParam instanceof Ed25519PrivateKeyParameters || keyParam instanceof Ed25519PublicKeyParameters)
            {
                return new EdDsaSigner(new Ed25519Signer(), createDigest(hashAlgorithm));
            }
            return new EdDsaSigner(new Ed448Signer(new byte[0]), createDigest(hashAlgorithm));
        case PublicKeyAlgorithmTags.Ed25519:
            return new EdDsaSigner(new Ed25519Signer(), createDigest(hashAlgorithm));
        case PublicKeyAlgorithmTags.Ed448:
            return new EdDsaSigner(new Ed448Signer(new byte[0]), createDigest(hashAlgorithm));
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            return new MLDSACompositeSigner(keyAlgorithm, createPQCSignatureDigest(keyAlgorithm, hashAlgorithm));
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
            return new SLHDSADigestSigner(keyAlgorithm, createPQCSignatureDigest(keyAlgorithm, hashAlgorithm));
        default:
            throw new PGPException("cannot recognise keyAlgorithm: " + keyAlgorithm);
        }
    }

    /**
     * RFC 9980 sec. 5.3.1 and 6.2.1: a composite ML-DSA + EdDSA or an SLH-DSA signature MUST use a hash
     * algorithm with a digest size of at least 256 bits, and a verifier MUST reject one that does not.
     */
    static Digest createPQCSignatureDigest(int keyAlgorithm, int hashAlgorithm)
        throws PGPException
    {
        Digest digest = createDigest(hashAlgorithm);
        if (digest.getDigestSize() < 32)
        {
            throw new PGPException("public key algorithm " + keyAlgorithm
                + " MUST use a hash algorithm with a digest size of at least 256 bits (RFC 9980), got hash algorithm "
                + hashAlgorithm);
        }
        return digest;
    }

    static BlockCipher createBlockCipher(int encAlgorithm)
        throws PGPException
    {
        BlockCipher engine;

        switch (encAlgorithm)
        {
        case SymmetricKeyAlgorithmTags.AES_128:
        case SymmetricKeyAlgorithmTags.AES_192:
        case SymmetricKeyAlgorithmTags.AES_256:
            engine = AESEngine.newInstance();
            break;
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            engine = new CamelliaEngine();
            break;
        case SymmetricKeyAlgorithmTags.BLOWFISH:
            engine = new BlowfishEngine();
            break;
        case SymmetricKeyAlgorithmTags.CAST5:
            engine = new CAST5Engine();
            break;
        case SymmetricKeyAlgorithmTags.DES:
            engine = new DESEngine();
            break;
        case SymmetricKeyAlgorithmTags.IDEA:
            engine = new IDEAEngine();
            break;
        case SymmetricKeyAlgorithmTags.TWOFISH:
            engine = new TwofishEngine();
            break;
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
            engine = new DESedeEngine();
            break;
        default:
            throw new PGPException("cannot recognise cipher");
        }

        return engine;
    }

    static Wrapper createWrapper(int encAlgorithm)
        throws PGPException
    {
        switch (encAlgorithm)
        {
        case SymmetricKeyAlgorithmTags.AES_128:
        case SymmetricKeyAlgorithmTags.AES_192:
        case SymmetricKeyAlgorithmTags.AES_256:
            return new RFC3394WrapEngine(AESEngine.newInstance());
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            //RFC 5581 s3: Camellia may be used in any place in OpenPGP where a symmetric cipher
            //   is usable, and it is subject to the same usage requirements
            return new RFC3394WrapEngine(new CamelliaEngine());
        default:
            throw new PGPException("unknown wrap algorithm: " + encAlgorithm);
        }
    }

    static AsymmetricBlockCipher createPublicKeyCipher(int encAlgorithm)
        throws PGPException
    {
        AsymmetricBlockCipher c;

        switch (encAlgorithm)
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_GENERAL:
            c = new PKCS1Encoding(new RSABlindedEngine());
            break;
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
            c = new PKCS1Encoding(new ElGamalEngine());
            break;
        case PGPPublicKey.DSA:
            throw new PGPException("Can't use DSA for encryption.");
        case PGPPublicKey.ECDSA:
            throw new PGPException("Can't use ECDSA for encryption.");
        case PGPPublicKey.ECDH:
        case PGPPublicKey.X25519:
        case PGPPublicKey.X448:
            throw new PGPException("Not implemented.");
        default:
            throw new PGPException("unknown asymmetric algorithm: " + encAlgorithm);
        }

        return c;
    }

    /**
     * The ML-DSA + EdDSA composite signature of RFC 9980 sec. 5.2: the message digest (RFC 9580 sec. 5.2.4) is
     * signed independently with PureEdDSA (RFC 8032, empty context) and with the hedged pure ML-DSA (FIPS 204,
     * empty context), and the signature is the EdDSA signature followed by the ML-DSA signature. Verification
     * requires both component signatures to verify (sec. 5.2.3).
     */
    private static class MLDSACompositeSigner
        implements Signer
    {
        private final int keyAlgorithm;
        private final Digest digest;
        private final byte[] digBuf;
        private final int eddsaSigLen;
        private final int mldsaSigLen;

        private Signer eddsaSigner;
        private MLDSASigner mldsaSigner;

        MLDSACompositeSigner(int keyAlgorithm, Digest digest)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.digest = digest;
            this.digBuf = new byte[digest.getDigestSize()];
            this.eddsaSigLen = MLDSACompositePublicBCPGKey.getEdDSASignatureLength(keyAlgorithm);
            this.mldsaSigLen = MLDSACompositePublicBCPGKey.getMLDSASignatureLength(keyAlgorithm);
        }

        public void init(boolean forSigning, CipherParameters param)
        {
            SecureRandom random = null;
            if (param instanceof ParametersWithRandom)
            {
                random = ((ParametersWithRandom)param).getRandom();
                param = ((ParametersWithRandom)param).getParameters();
            }
            if (!(param instanceof BcPGPCompositeKeyParameters))
            {
                throw new IllegalArgumentException("ML-DSA + EdDSA composite signer requires BcPGPCompositeKeyParameters");
            }
            BcPGPCompositeKeyParameters comp = (BcPGPCompositeKeyParameters)param;
            AsymmetricKeyParameter eddsaKey = comp.getTraditionalKey();
            AsymmetricKeyParameter mldsaKey = comp.getPostQuantumKey();

            if (keyAlgorithm == PublicKeyAlgorithmTags.MLDSA65_Ed25519)
            {
                if (!(eddsaKey instanceof Ed25519PrivateKeyParameters || eddsaKey instanceof Ed25519PublicKeyParameters))
                {
                    throw new IllegalArgumentException("ML-DSA-65 + Ed25519 requires an Ed25519 component key");
                }
                eddsaSigner = new Ed25519Signer();
            }
            else
            {
                if (!(eddsaKey instanceof Ed448PrivateKeyParameters || eddsaKey instanceof Ed448PublicKeyParameters))
                {
                    throw new IllegalArgumentException("ML-DSA-87 + Ed448 requires an Ed448 component key");
                }
                eddsaSigner = new Ed448Signer(new byte[0]);
            }
            if (!(mldsaKey instanceof MLDSAKeyParameters)
                || ((MLDSAKeyParameters)mldsaKey).getParameters() != BcPGPKeyConverter.getMLDSAParameters(keyAlgorithm))
            {
                throw new IllegalArgumentException("ML-DSA component key does not match public key algorithm " + keyAlgorithm);
            }

            eddsaSigner.init(forSigning, eddsaKey);

            mldsaSigner = new MLDSASigner();
            if (forSigning)
            {
                // RFC 9980 sec. 5.1.2: the default hedged variant of ML-DSA.Sign
                mldsaSigner.init(true, new ParametersWithRandom(mldsaKey, CryptoServicesRegistrar.getSecureRandom(random)));
            }
            else
            {
                mldsaSigner.init(false, mldsaKey);
            }

            digest.reset();
        }

        public void update(byte b)
        {
            digest.update(b);
        }

        public void update(byte[] in, int off, int len)
        {
            digest.update(in, off, len);
        }

        public byte[] generateSignature()
            throws CryptoException, DataLengthException
        {
            digest.doFinal(digBuf, 0);

            eddsaSigner.update(digBuf, 0, digBuf.length);
            byte[] eddsaSig = eddsaSigner.generateSignature();

            mldsaSigner.update(digBuf, 0, digBuf.length);
            byte[] mldsaSig = mldsaSigner.generateSignature();

            if (eddsaSig.length != eddsaSigLen || mldsaSig.length != mldsaSigLen)
            {
                throw new CryptoException("unexpected component signature length");
            }

            return Arrays.concatenate(eddsaSig, mldsaSig);
        }

        public boolean verifySignature(byte[] signature)
        {
            digest.doFinal(digBuf, 0);

            if (signature.length != eddsaSigLen + mldsaSigLen)
            {
                reset();
                return false;
            }

            byte[] eddsaSig = Arrays.copyOfRange(signature, 0, eddsaSigLen);
            byte[] mldsaSig = Arrays.copyOfRange(signature, eddsaSigLen, signature.length);

            eddsaSigner.update(digBuf, 0, digBuf.length);
            boolean eddsaOk = eddsaSigner.verifySignature(eddsaSig);

            mldsaSigner.update(digBuf, 0, digBuf.length);
            boolean mldsaOk = mldsaSigner.verifySignature(mldsaSig);

            // RFC 9980 sec. 5.2.3: both component signatures MUST verify
            return eddsaOk & mldsaOk;
        }

        public void reset()
        {
            Arrays.clear(digBuf);
            digest.reset();
            if (eddsaSigner != null)
            {
                eddsaSigner.reset();
            }
            if (mldsaSigner != null)
            {
                mldsaSigner.reset();
            }
        }
    }

    /**
     * The SLH-DSA signature of RFC 9980 sec. 6: the message digest (RFC 9580 sec. 5.2.4) is signed with the
     * hedged pure variant of slh_sign (FIPS 205, empty context).
     */
    private static class SLHDSADigestSigner
        implements Signer
    {
        private final int keyAlgorithm;
        private final Digest digest;
        private final byte[] digBuf;
        private final int sigLen;
        private final SLHDSASigner signer = new SLHDSASigner();

        SLHDSADigestSigner(int keyAlgorithm, Digest digest)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.digest = digest;
            this.digBuf = new byte[digest.getDigestSize()];
            this.sigLen = SLHDSAPublicBCPGKey.getSignatureLength(keyAlgorithm);
        }

        public void init(boolean forSigning, CipherParameters param)
        {
            SecureRandom random = null;
            CipherParameters key = param;
            if (param instanceof ParametersWithRandom)
            {
                random = ((ParametersWithRandom)param).getRandom();
                key = ((ParametersWithRandom)param).getParameters();
            }
            if (!(key instanceof SLHDSAKeyParameters)
                || ((SLHDSAKeyParameters)key).getParameters() != BcPGPKeyConverter.getSLHDSAParameters(keyAlgorithm))
            {
                throw new IllegalArgumentException("SLH-DSA key does not match public key algorithm " + keyAlgorithm);
            }

            if (forSigning)
            {
                // RFC 9980 sec. 6.1.2: the default hedged variant of slh_sign
                signer.init(true, new ParametersWithRandom(key, CryptoServicesRegistrar.getSecureRandom(random)));
            }
            else
            {
                signer.init(false, key);
            }
            digest.reset();
        }

        public void update(byte b)
        {
            digest.update(b);
        }

        public void update(byte[] in, int off, int len)
        {
            digest.update(in, off, len);
        }

        public byte[] generateSignature()
            throws CryptoException, DataLengthException
        {
            digest.doFinal(digBuf, 0);

            byte[] sig = signer.generateSignature(digBuf);
            if (sig.length != sigLen)
            {
                throw new CryptoException("unexpected SLH-DSA signature length");
            }
            return sig;
        }

        public boolean verifySignature(byte[] signature)
        {
            digest.doFinal(digBuf, 0);

            if (signature.length != sigLen)
            {
                return false;
            }
            return signer.verifySignature(digBuf, signature);
        }

        public void reset()
        {
            Arrays.clear(digBuf);
            digest.reset();
        }
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
