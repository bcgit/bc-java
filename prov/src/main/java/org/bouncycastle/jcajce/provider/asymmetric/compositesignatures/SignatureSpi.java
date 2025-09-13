package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.interfaces.BCKey;
import org.bouncycastle.jcajce.spec.CompositeSignatureSpec;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.encoders.Hex;

/**
 * Signature class for composite signatures. Selected algorithm is set by the "subclasses" at the end of this file.
 */
public class SignatureSpi
    extends java.security.SignatureSpi
{
    //the byte encoding of the ASCII string "CompositeAlgorithmSignatures2025"
    private static final byte[] prefix = Hex.decode("436F6D706F73697465416C676F726974686D5369676E61747572657332303235");
    private static final Map<String, String> canonicalNames = new HashMap<String, String>();
    private static final HashMap<ASN1ObjectIdentifier, byte[]> domainSeparators = new HashMap<ASN1ObjectIdentifier, byte[]>();
    private static final HashMap<ASN1ObjectIdentifier, AlgorithmParameterSpec> algorithmsParameterSpecs = new HashMap<ASN1ObjectIdentifier, AlgorithmParameterSpec>();
    private static final String ML_DSA_44 = "ML-DSA-44";
    private static final String ML_DSA_65 = "ML-DSA-65";
    private static final String ML_DSA_87 = "ML-DSA-87";
    private final SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private Key compositeKey;

    static
    {
        canonicalNames.put("MLDSA44", ML_DSA_44);
        canonicalNames.put("MLDSA65", ML_DSA_65);
        canonicalNames.put("MLDSA87", ML_DSA_87);
        canonicalNames.put(NISTObjectIdentifiers.id_ml_dsa_44.getId(), ML_DSA_44);
        canonicalNames.put(NISTObjectIdentifiers.id_ml_dsa_65.getId(), ML_DSA_65);
        canonicalNames.put(NISTObjectIdentifiers.id_ml_dsa_87.getId(), ML_DSA_87);
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, Hex.decode("060B6086480186FA6B50090100"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, Hex.decode("060B6086480186FA6B50090101"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, Hex.decode("060B6086480186FA6B50090102"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, Hex.decode("060B6086480186FA6B50090103"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512, Hex.decode("060B6086480186FA6B50090104"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512, Hex.decode("060B6086480186FA6B50090105"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512, Hex.decode("060B6086480186FA6B50090106"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512, Hex.decode("060B6086480186FA6B50090107"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512, Hex.decode("060B6086480186FA6B50090108"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512, Hex.decode("060B6086480186FA6B50090109"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512, Hex.decode("060B6086480186FA6B5009010A"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, Hex.decode("060B6086480186FA6B5009010B"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512, Hex.decode("060B6086480186FA6B5009010C"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512, Hex.decode("060B6086480186FA6B5009010D"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256, Hex.decode("060B6086480186FA6B5009010E"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512, Hex.decode("060B6086480186FA6B5009010F"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512, Hex.decode("060B6086480186FA6B50090110"));
        domainSeparators.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512, Hex.decode("060B6086480186FA6B50090111"));

        algorithmsParameterSpecs.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256,
            new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
        algorithmsParameterSpecs.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512,
            new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
        algorithmsParameterSpecs.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512,
            new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1));
        algorithmsParameterSpecs.put(MiscObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512,
            new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1));
        algorithmsParameterSpecs.put(MiscObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512,
            new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
    }


    //List of Signatures. Each entry corresponds to a component signature from the composite definition.
    private final ASN1ObjectIdentifier algorithm;
    private final String[] algs;
    private final Signature[] componentSignatures;
    private final byte[] domain;
    private final Digest baseDigest;
    private final JcaJceHelper helper = new BCJcaJceHelper();

    private Digest preHashDigest;
    private ContextParameterSpec contextSpec;
    private AlgorithmParameters engineParams = null;

    private boolean unprimed = true;

    SignatureSpi(ASN1ObjectIdentifier algorithm, Digest preHashDigest)
    {
        this.algorithm = algorithm;
        this.baseDigest = preHashDigest;
        this.preHashDigest = preHashDigest;
        this.domain = domainSeparators.get(algorithm);

        this.algs = CompositeIndex.getPairing(algorithm);
        this.componentSignatures = new Signature[algs.length];
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof CompositePublicKey))
        {
            throw new InvalidKeyException("public key is not composite");
        }

        this.compositeKey = publicKey;

        CompositePublicKey compositePublicKey = (CompositePublicKey)this.compositeKey;

        if (!compositePublicKey.getAlgorithmIdentifier().getAlgorithm().equals(this.algorithm))
        {
            throw new InvalidKeyException("Provided composite public key cannot be used with the composite signature algorithm.");
        }
        createComponentSignatures(compositePublicKey.getPublicKeys(), compositePublicKey.getProviders());
        
        sigInitVerify();
    }

    private void sigInitVerify()
        throws InvalidKeyException
    {
        CompositePublicKey compositePublicKey = (CompositePublicKey)this.compositeKey;
        for (int i = 0; i < this.componentSignatures.length; i++)
        {
            this.componentSignatures[i].initVerify(compositePublicKey.getPublicKeys().get(i));
        }
        this.unprimed = true;
    }

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        if (!(privateKey instanceof CompositePrivateKey))
        {
            throw new InvalidKeyException("Private key is not composite.");
        }

        this.compositeKey = privateKey;

        CompositePrivateKey compositePrivateKey = (CompositePrivateKey)privateKey;
        if (!compositePrivateKey.getAlgorithmIdentifier().getAlgorithm().equals(this.algorithm))
        {
            throw new InvalidKeyException("Provided composite private key cannot be used with the composite signature algorithm.");
        }
        createComponentSignatures(compositePrivateKey.getPrivateKeys(), compositePrivateKey.getProviders());

        sigInitSign();
    }

    private void createComponentSignatures(List keys, List<Provider> providers)
    {
        try
        {
            if (providers == null)
            {
                for (int i = 0; i != componentSignatures.length; i++)
                {
                    componentSignatures[i] = getDefaultSignature(algs[i], keys.get(i));
                }
            }
            else
            {
                for (int i = 0; i != componentSignatures.length; i++)
                {
                    Provider prov = providers.get(i);
                    if (prov == null)
                    {
                        componentSignatures[i] = getDefaultSignature(algs[i], keys.get(i));
                    }
                    else
                    {
                        componentSignatures[i] = Signature.getInstance(algs[i], providers.get(i));
                    }
                }
            }
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

    private Signature getDefaultSignature(String alg, Object key)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        if (key instanceof BCKey)
        {
            return helper.createSignature(alg);
        }
        else
        {
            return Signature.getInstance(alg);
        }
    }

    private void sigInitSign()
        throws InvalidKeyException
    {
        CompositePrivateKey compositePrivateKey = (CompositePrivateKey)this.compositeKey;
        //for each component signature run initVerify with the corresponding private key.
        for (int i = 0; i < this.componentSignatures.length; i++)
        {
            this.componentSignatures[i].initSign(compositePrivateKey.getPrivateKeys().get(i));
        }
        this.unprimed = true;
    }

    private void baseSigInit()
        throws SignatureException
    {
        try
        {
            componentSignatures[0].setParameter(new ContextParameterSpec(domain));
            AlgorithmParameterSpec pssSpec = algorithmsParameterSpecs.get(this.algorithm);
            if (pssSpec != null)
            {
                componentSignatures[1].setParameter(pssSpec);
            }
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new IllegalStateException("unable to set context on ML-DSA");
        }

        this.unprimed = false;
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        if (unprimed)
        {
            baseSigInit();
        }

        if (preHashDigest != null)
        {
            preHashDigest.update(b);
        }
        else
        {
            for (int i = 0; i < this.componentSignatures.length; i++)
            {
                Signature componentSig = this.componentSignatures[i];

                componentSig.update(b);
            }
        }
    }

    protected void engineUpdate(byte[] bytes, int off, int len)
        throws SignatureException
    {
        if (unprimed)
        {
            baseSigInit();
        }

        if (preHashDigest != null)
        {
            preHashDigest.update(bytes, off, len);
        }
        else
        {
            for (int i = 0; i < this.componentSignatures.length; i++)
            {
                Signature componentSig = this.componentSignatures[i];

                componentSig.update(bytes, off, len);
            }
        }
    }

    /**
     * Method which calculates each component signature and constructs a composite signature
     * which is a sequence of BIT STRINGs https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-sigs-13.html#name-compositesignaturevalue
     *
     * @return composite signature bytes
     * @throws SignatureException
     */
    protected byte[] engineSign()
        throws SignatureException
    {
        byte[] r = new byte[32];
        random.nextBytes(r); // Secure random generator

        if (preHashDigest != null)
        {
            processPreHashedMessage(r);
        }

        byte[] mldsaSig = this.componentSignatures[0].sign();
        byte[] tradSig = this.componentSignatures[1].sign();

        // Concatenate: r || ML-DSA sig || Traditional sig
        byte[] compositeSig = new byte[32 + mldsaSig.length + tradSig.length];
        System.arraycopy(r, 0, compositeSig, 0, 32);
        System.arraycopy(mldsaSig, 0, compositeSig, 32, mldsaSig.length);
        System.arraycopy(tradSig, 0, compositeSig, 32 + mldsaSig.length, tradSig.length);

        return compositeSig;
    }

    private void processPreHashedMessage(byte[] r)
        throws SignatureException
    {
        byte[] dig = new byte[baseDigest.getDigestSize()];

        try
        {
            preHashDigest.doFinal(dig, 0);
        }
        catch (IllegalStateException e)
        {
            throw new SignatureException(e.getMessage());
        }

        for (int i = 0; i < this.componentSignatures.length; i++)
        {
            Signature componentSig = this.componentSignatures[i];
            componentSig.update(prefix);
            componentSig.update(domain);
            if (contextSpec == null)
            {
                componentSig.update((byte)0);
            }
            else
            {
                byte[] ctx = contextSpec.getContext();

                componentSig.update((byte)ctx.length);
                componentSig.update(ctx);
            }
            componentSig.update(r, 0, r.length);
            componentSig.update(dig, 0, dig.length);
        }
    }

    public static byte[][] splitCompositeSignature(byte[] compositeSignature, int mldsaSigLen)
    {
        byte[] r = new byte[32];
        byte[] mldsaSig = new byte[mldsaSigLen];
        byte[] tradSig = new byte[compositeSignature.length - 32 - mldsaSigLen];

        System.arraycopy(compositeSignature, 0, r, 0, 32);
        System.arraycopy(compositeSignature, 32, mldsaSig, 0, mldsaSigLen);
        System.arraycopy(compositeSignature, 32 + mldsaSigLen, tradSig, 0, tradSig.length);

        return new byte[][]{r, mldsaSig, tradSig};
    }

    /**
     * Corresponding verification method to the engineSign method.
     * The composite signature is valid if and only if all component signatures are valid.
     * The method verifies all component signatures even if it is already known that the composite signature is invalid.
     *
     * @param signature the signature bytes to be verified.
     * @return
     * @throws SignatureException
     */
    protected boolean engineVerify(byte[] signature)
        throws SignatureException
    {
        int mldsaSigLen = 0;
        if (componentSignatures[0] instanceof org.bouncycastle.jcajce.provider.asymmetric.mldsa.SignatureSpi.MLDSA44)
        {
            mldsaSigLen = 2420;
        }
        else if (componentSignatures[0] instanceof org.bouncycastle.jcajce.provider.asymmetric.mldsa.SignatureSpi.MLDSA65)
        {
            mldsaSigLen = 3309;
        }
        else if (componentSignatures[0] instanceof org.bouncycastle.jcajce.provider.asymmetric.mldsa.SignatureSpi.MLDSA87)
        {
            mldsaSigLen = 4627;
        }
        byte[][] signatures = splitCompositeSignature(signature, mldsaSigLen);

        if (preHashDigest != null)
        {
            processPreHashedMessage(signatures[0]);
        }

        // Currently all signatures try to verify even if, e.g., the first is invalid.
        // If each component verify() is constant time, then this is also, otherwise it does not make sense to iterate over all if one of them already fails.
        // However, it is important that we do not provide specific error messages, e.g., "only the 2nd component failed to verify".
        boolean fail = false;

        for (int i = 0; i < this.componentSignatures.length; i++)
        {
            //signatures[0] is 32-byte random number
            if (!this.componentSignatures[i].verify(signatures[i + 1]))
            {
                fail = true;
            }
        }

        return !fail;
    }

    protected void engineSetParameter(AlgorithmParameterSpec algorithmParameterSpec)
        throws InvalidAlgorithmParameterException
    {
        if (!unprimed)
        {
            throw new InvalidAlgorithmParameterException("attempt to set parameter after update");
        }

        if (algorithmParameterSpec instanceof ContextParameterSpec)
        {
            contextSpec = (ContextParameterSpec)algorithmParameterSpec;
            try
            {
                if (compositeKey instanceof PublicKey)
                {
                    sigInitVerify();
                }
                else
                {
                    sigInitSign();
                }
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidAlgorithmParameterException("keys invalid on reset: " + e.getMessage(), e);
            }
        }
        else if (algorithmParameterSpec instanceof CompositeSignatureSpec)
        {
            CompositeSignatureSpec compositeSignatureSpec = (CompositeSignatureSpec)algorithmParameterSpec;

            if (compositeSignatureSpec.isPrehashMode())
            {
                this.preHashDigest = new NullDigest(baseDigest.getDigestSize());
            }
            else
            {
                this.preHashDigest = this.baseDigest;
            }
            this.contextSpec = (ContextParameterSpec)compositeSignatureSpec.getSecondarySpec();
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown parameterSpec passed to composite signature");
        }
    }

    private String getCanonicalName(String baseName)
    {
        String name = canonicalNames.get(baseName);

        if (name != null)
        {
            return name;
        }

        return baseName;
    }

    protected void engineSetParameter(String s, Object o)
        throws InvalidParameterException
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected Object engineGetParameter(String s)
        throws InvalidParameterException
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    protected final AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (contextSpec != null)
            {
                try
                {
                    engineParams = helper.createAlgorithmParameters("CONTEXT");
                    engineParams.init(contextSpec);
                }
                catch (Exception e)
                {
                    throw Exceptions.illegalStateException(e.toString(), e);
                }
            }
        }

        return engineParams;
    }

    private static class NullDigest
        implements Digest
    {
        private final int expectedSize;
        private final OpenByteArrayOutputStream bOut = new OpenByteArrayOutputStream();

        NullDigest(int expectedSize)
        {
            this.expectedSize = expectedSize;
        }

        public String getAlgorithmName()
        {
            return "NULL";
        }

        public int getDigestSize()
        {
            return bOut.size();
        }

        public void update(byte in)
        {
            bOut.write(in);
        }

        public void update(byte[] in, int inOff, int len)
        {
            bOut.write(in, inOff, len);
        }

        public int doFinal(byte[] out, int outOff)
        {
            int size = bOut.size();
            if (size != expectedSize)
            {
                throw new IllegalStateException("provided pre-hash digest is the wrong length");
            }

            bOut.copy(out, outOff);

            reset();

            return size;
        }

        public void reset()
        {
            bOut.reset();
        }

        private static class OpenByteArrayOutputStream
            extends ByteArrayOutputStream
        {
            public void reset()
            {
                super.reset();

                Arrays.clear(buf);
            }

            void copy(byte[] out, int outOff)
            {
                System.arraycopy(buf, 0, out, outOff, this.size());
            }
        }
    }

    public static final class HashMLDSA44_ECDSA_P256_SHA256
        extends SignatureSpi
    {
        public HashMLDSA44_ECDSA_P256_SHA256()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_ECDSA_P256_SHA256, new SHA256Digest());
        }
    }

    public static final class HashMLDSA44_Ed25519_SHA512
        extends SignatureSpi
    {
        public HashMLDSA44_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_Ed25519_SHA512, new SHA512Digest());
        }
    }

    public static final class HashMLDSA44_RSA2048_PKCS15_SHA256
        extends SignatureSpi
    {
        public HashMLDSA44_RSA2048_PKCS15_SHA256()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PKCS15_SHA256, new SHA256Digest());
        }
    }

    public static final class HashMLDSA44_RSA2048_PSS_SHA256
        extends SignatureSpi
    {
        public HashMLDSA44_RSA2048_PSS_SHA256()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PSS_SHA256, new SHA256Digest());
        }
    }

    public static final class HashMLDSA65_ECDSA_brainpoolP256r1_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_ECDSA_brainpoolP256r1_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512, new SHA512Digest());
        }
    }

    public static final class HashMLDSA65_ECDSA_P384_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_ECDSA_P384_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_P384_SHA512, new SHA512Digest());
        }
    }

    public static final class HashMLDSA65_Ed25519_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_Ed25519_SHA512, new SHA512Digest());
        }
    }

    public static final class HashMLDSA65_RSA3072_PKCS15_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_RSA3072_PKCS15_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PKCS15_SHA512, new SHA512Digest());
        }
    }

    public static final class HashMLDSA65_RSA3072_PSS_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_RSA3072_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PSS_SHA512, new SHA512Digest());
        }
    }

    public static final class HashMLDSA65_RSA4096_PKCS15_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_RSA4096_PKCS15_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PKCS15_SHA512, new SHA512Digest());
        }
    }

    public static final class HashMLDSA65_RSA4096_PSS_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_RSA4096_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PSS_SHA512, new SHA512Digest());
        }
    }

    public static final class HashMLDSA87_ECDSA_brainpoolP384r1_SHA512
        extends SignatureSpi
    {
        public HashMLDSA87_ECDSA_brainpoolP384r1_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512, new SHA512Digest());
        }
    }

    public static final class HashMLDSA87_ECDSA_P384_SHA512
        extends SignatureSpi
    {
        public HashMLDSA87_ECDSA_P384_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_P384_SHA512, new SHA512Digest());
        }
    }

    public static final class HashMLDSA87_Ed448_SHA512
        extends SignatureSpi
    {
        public HashMLDSA87_Ed448_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA87_Ed448_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA44_ECDSA_P256_SHA256
        extends SignatureSpi
    {
        public MLDSA44_ECDSA_P256_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, new SHA256Digest());
        }
    }

    public static final class MLDSA44_Ed25519_SHA512
        extends SignatureSpi
    {
        public MLDSA44_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA44_RSA2048_PKCS15_SHA256
        extends SignatureSpi
    {
        public MLDSA44_RSA2048_PKCS15_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, new SHA256Digest());
        }
    }

    public static final class MLDSA44_RSA2048_PSS_SHA256
        extends SignatureSpi
    {
        public MLDSA44_RSA2048_PSS_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, new SHA256Digest());
        }
    }

    public static final class MLDSA65_ECDSA_brainpoolP256r1_SHA256
        extends SignatureSpi
    {
        public MLDSA65_ECDSA_brainpoolP256r1_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256, new SHA256Digest());
        }
    }

    public static final class MLDSA65_ECDSA_P384_SHA384
        extends SignatureSpi
    {
        public MLDSA65_ECDSA_P384_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA384, new SHA384Digest());
        }
    }

    public static final class MLDSA65_Ed25519_SHA512
        extends SignatureSpi
    {
        public MLDSA65_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA65_RSA3072_PKCS15_SHA256
        extends SignatureSpi
    {
        public MLDSA65_RSA3072_PKCS15_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256, new SHA256Digest());
        }
    }

    public static final class MLDSA65_RSA3072_PSS_SHA256
        extends SignatureSpi
    {
        public MLDSA65_RSA3072_PSS_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256, new SHA256Digest());
        }
    }

    public static final class MLDSA65_RSA4096_PKCS15_SHA384
        extends SignatureSpi
    {
        public MLDSA65_RSA4096_PKCS15_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA384, new SHA384Digest());
        }
    }

    public static final class MLDSA65_RSA4096_PSS_SHA384
        extends SignatureSpi
    {
        public MLDSA65_RSA4096_PSS_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA384, new SHA384Digest());
        }
    }

    public static final class MLDSA87_ECDSA_brainpoolP384r1_SHA384
        extends SignatureSpi
    {
        public MLDSA87_ECDSA_brainpoolP384r1_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384, new SHA384Digest());
        }
    }

    public static final class MLDSA87_ECDSA_P384_SHA384
        extends SignatureSpi
    {
        public MLDSA87_ECDSA_P384_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384, new SHA384Digest());
        }
    }

    public static final class MLDSA87_Ed448_SHA512
        extends SignatureSpi
    {
        public MLDSA87_Ed448_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA65_RSA3072_PSS_SHA512
        extends SignatureSpi
    {
        public MLDSA65_RSA3072_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA65_RSA3072_PKCS15_SHA512
        extends SignatureSpi
    {
        public MLDSA65_RSA3072_PKCS15_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA65_RSA4096_PSS_SHA512
        extends SignatureSpi
    {
        public MLDSA65_RSA4096_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA65_RSA4096_PKCS15_SHA512
        extends SignatureSpi
    {
        public MLDSA65_RSA4096_PKCS15_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA65_ECDSA_P256_SHA512
        extends SignatureSpi
    {
        public MLDSA65_ECDSA_P256_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA65_ECDSA_P384_SHA512
        extends SignatureSpi
    {
        public MLDSA65_ECDSA_P384_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA65_ECDSA_brainpoolP256r1_SHA512
        extends SignatureSpi
    {
        public MLDSA65_ECDSA_brainpoolP256r1_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA87_ECDSA_P384_SHA512
        extends SignatureSpi
    {
        public MLDSA87_ECDSA_P384_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA87_ECDSA_brainpoolP384r1_SHA512
        extends SignatureSpi
    {
        public MLDSA87_ECDSA_brainpoolP384r1_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA87_Ed448_SHAKE256
        extends SignatureSpi
    {
        public MLDSA87_Ed448_SHAKE256()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256, new SHAKEDigest(256));
        }
    }

    public static final class MLDSA87_RSA3072_PSS_SHA512
        extends SignatureSpi
    {
        public MLDSA87_RSA3072_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA87_RSA4096_PSS_SHA512
        extends SignatureSpi
    {
        public MLDSA87_RSA4096_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512, new SHA512Digest());
        }
    }

    public static final class MLDSA87_ECDSA_P521_SHA512
        extends SignatureSpi
    {
        public MLDSA87_ECDSA_P521_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512, new SHA512Digest());
        }
    }

    private static final class ErasableOutputStream
        extends ByteArrayOutputStream
    {
        public ErasableOutputStream()
        {
        }

        public byte[] getBuf()
        {
            return buf;
        }
    }
}
