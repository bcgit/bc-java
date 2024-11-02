package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Exceptions;

/**
 * Signature class for composite signatures. Selected algorithm is set by the "subclasses" at the end of this file.
 */
public class SignatureSpi
    extends java.security.SignatureSpi
{
    private static final Map<String, String> canonicalNames = new HashMap<String, String>();

    private static final String ML_DSA_44 = "ML-DSA-44";
    private static final String ML_DSA_65 = "ML-DSA-65";
    private static final String ML_DSA_87 = "ML-DSA-87";

    private Key compositeKey;

    static
    {
        canonicalNames.put("MLDSA44", ML_DSA_44);
        canonicalNames.put("MLDSA65", ML_DSA_65);
        canonicalNames.put("MLDSA87", ML_DSA_87);
        canonicalNames.put(NISTObjectIdentifiers.id_ml_dsa_44.getId(), ML_DSA_44);
        canonicalNames.put(NISTObjectIdentifiers.id_ml_dsa_65.getId(), ML_DSA_65);
        canonicalNames.put(NISTObjectIdentifiers.id_ml_dsa_87.getId(), ML_DSA_87);
    }

    //List of Signatures. Each entry corresponds to a component signature from the composite definition.
    private final ASN1ObjectIdentifier algorithm;
    private final Signature[] componentSignatures;
    private final byte[] domain;
    private final Digest preHashDigest;
    private final byte[] hashOID;
    private final JcaJceHelper helper = new BCJcaJceHelper();
    
    private ContextParameterSpec contextSpec;
    private AlgorithmParameters engineParams = null;

    private boolean unprimed = true;

    SignatureSpi(ASN1ObjectIdentifier algorithm)
    {
        this(algorithm, null, null);
    }

    SignatureSpi(ASN1ObjectIdentifier algorithm, Digest preHashDigest, ASN1ObjectIdentifier preHashOid)
    {
        this.algorithm = algorithm;
        this.preHashDigest = preHashDigest;

        String[] algs = CompositeIndex.getPairing(algorithm);

        if (preHashDigest != null)
        {
            try
            {
                this.hashOID = preHashOid.getEncoded();
            }
            catch (IOException e)
            {   // if this happens, we're in real trouble!
                throw new IllegalStateException("unable to encode domain value");
            }
        }
        else
        {
            hashOID = null;
        }

        try
        {
            this.domain = algorithm.getEncoded();
        }
        catch (IOException e)
        {   // if this happens, we're in real trouble!
            throw new IllegalStateException("unable to encode domain value");
        }

        this.componentSignatures = new Signature[algs.length];
        try
        {
            for (int i = 0; i != componentSignatures.length; i++)
            {
                componentSignatures[i] = Signature.getInstance(algs[i], "BC");
            }
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof CompositePublicKey))
        {
            throw new InvalidKeyException("Public key is not composite.");
        }

        this.compositeKey = publicKey;

        CompositePublicKey compositePublicKey = (CompositePublicKey)this.compositeKey;
        if (!compositePublicKey.getAlgorithmIdentifier().equals(this.algorithm))
        {
            throw new InvalidKeyException("Provided composite public key cannot be used with the composite signature algorithm.");
        }

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
        if (!compositePrivateKey.getAlgorithmIdentifier().equals(this.algorithm))
        {
            throw new InvalidKeyException("Provided composite private key cannot be used with the composite signature algorithm.");
        }

        sigInitSign();
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
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new IllegalStateException("unable to set context on ML-DSA");
        }

        if (preHashDigest == null)
        {
            for (int i = 0; i < this.componentSignatures.length; i++)
            {
                Signature componentSig = this.componentSignatures[i];
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
            }
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
        if (preHashDigest != null)
        {
            processPreHashedMessage();
        }

        ASN1EncodableVector signatureSequence = new ASN1EncodableVector();
        try
        {
            for (int i = 0; i < this.componentSignatures.length; i++)
            {
                byte[] signatureValue = this.componentSignatures[i].sign();
                signatureSequence.add(new DERBitString(signatureValue));
            }

            return new DERSequence(signatureSequence).getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new SignatureException(e.getMessage());
        }
    }

    private void processPreHashedMessage()
        throws SignatureException
    {
        byte[] dig = new byte[preHashDigest.getDigestSize()];

        preHashDigest.doFinal(dig, 0);

        for (int i = 0; i < this.componentSignatures.length; i++)
        {
            Signature componentSig = this.componentSignatures[i];
            componentSig.update(domain, 0, domain.length);
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
            componentSig.update(hashOID, 0, hashOID.length);
            componentSig.update(dig, 0, dig.length);
        }
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
        ASN1Sequence signatureSequence = DERSequence.getInstance(signature);
        //Check if the decoded sequence of component signatures has the expected size.
        if (signatureSequence.size() != this.componentSignatures.length)
        {
            return false;
        }

        if (preHashDigest != null)
        {
            if (preHashDigest != null)
            {
                processPreHashedMessage();
            }
        }
        
        // Currently all signatures try to verify even if, e.g., the first is invalid.
        // If each component verify() is constant time, then this is also, otherwise it does not make sense to iterate over all if one of them already fails.
        // However, it is important that we do not provide specific error messages, e.g., "only the 2nd component failed to verify".
        boolean fail = false;

        for (int i = 0; i < this.componentSignatures.length; i++)
        {
            if (!this.componentSignatures[i].verify(ASN1BitString.getInstance(signatureSequence.getObjectAt(i)).getOctets()))
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
        else
        {
            throw new InvalidAlgorithmParameterException("unknown parameterSpec passed to composite signature");
        }
    }

    private void setSigParameter(Signature targetSig, String targetSigName, List<String> names, List<AlgorithmParameterSpec> specs)
        throws InvalidAlgorithmParameterException
    {
        for (int i = 0; i != names.size(); i++)
        {
            String canonicalName = getCanonicalName(names.get(i));

            if (names.get(i).equals(targetSigName))
            {
                targetSig.setParameter(specs.get(i));
            }
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

    public static final class HashMLDSA44_ECDSA_P256_SHA256
        extends SignatureSpi
    {
        public HashMLDSA44_ECDSA_P256_SHA256()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_ECDSA_P256_SHA256, new SHA256Digest(), NISTObjectIdentifiers.id_sha256);
        }
    }

    public static final class HashMLDSA44_Ed25519_SHA512
        extends SignatureSpi
    {
        public HashMLDSA44_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_Ed25519_SHA512, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        }
    }

    public static final class HashMLDSA44_RSA2048_PKCS15_SHA256
        extends SignatureSpi
    {
        public HashMLDSA44_RSA2048_PKCS15_SHA256()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PKCS15_SHA256, new SHA256Digest(), NISTObjectIdentifiers.id_sha256);
        }
    }

    public static final class HashMLDSA44_RSA2048_PSS_SHA256
        extends SignatureSpi
    {
        public HashMLDSA44_RSA2048_PSS_SHA256()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PSS_SHA256, new SHA256Digest(), NISTObjectIdentifiers.id_sha256);
        }
    }

    public static final class HashMLDSA65_ECDSA_brainpoolP256r1_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_ECDSA_brainpoolP256r1_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        }
    }

    public static final class HashMLDSA65_ECDSA_P384_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_ECDSA_P384_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_P384_SHA512, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        }
    }

    public static final class HashMLDSA65_Ed25519_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_Ed25519_SHA512, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        }
    }

    public static final class HashMLDSA65_RSA3072_PKCS15_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_RSA3072_PKCS15_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PKCS15_SHA512, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        }
    }

    public static final class HashMLDSA65_RSA3072_PSS_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_RSA3072_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PSS_SHA512, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        }
    }

    public static final class HashMLDSA65_RSA4096_PKCS15_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_RSA4096_PKCS15_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PKCS15_SHA512, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        }
    }

    public static final class HashMLDSA65_RSA4096_PSS_SHA512
        extends SignatureSpi
    {
        public HashMLDSA65_RSA4096_PSS_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PSS_SHA512, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        }
    }

    public static final class HashMLDSA87_ECDSA_brainpoolP384r1_SHA512
        extends SignatureSpi
    {
        public HashMLDSA87_ECDSA_brainpoolP384r1_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        }
    }

    public static final class HashMLDSA87_ECDSA_P384_SHA512
        extends SignatureSpi
    {
        public HashMLDSA87_ECDSA_P384_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_P384_SHA512, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        }
    }
    
    public static final class HashMLDSA87_Ed448_SHA512
        extends SignatureSpi
    {
        public HashMLDSA87_Ed448_SHA512()
        {
            super(MiscObjectIdentifiers.id_HashMLDSA87_Ed448_SHA512, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        }
    }

    public static final class MLDSA44_ECDSA_P256_SHA256
        extends SignatureSpi
    {
        public MLDSA44_ECDSA_P256_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256);
        }
    }

    public static final class MLDSA44_Ed25519_SHA512
        extends SignatureSpi
    {
        public MLDSA44_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512);
        }
    }

    public static final class MLDSA44_RSA2048_PKCS15_SHA256
        extends SignatureSpi
    {
        public MLDSA44_RSA2048_PKCS15_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256);
        }
    }

    public static final class MLDSA44_RSA2048_PSS_SHA256
        extends SignatureSpi
    {
        public MLDSA44_RSA2048_PSS_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256);
        }
    }

    public static final class MLDSA65_ECDSA_brainpoolP256r1_SHA256
        extends SignatureSpi
    {
        public MLDSA65_ECDSA_brainpoolP256r1_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256);
        }
    }

    public static final class MLDSA65_ECDSA_P384_SHA384
        extends SignatureSpi
    {
        public MLDSA65_ECDSA_P384_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA384);
        }
    }

    public static final class MLDSA65_Ed25519_SHA512
        extends SignatureSpi
    {
        public MLDSA65_Ed25519_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512);
        }
    }

    public static final class MLDSA65_RSA3072_PKCS15_SHA256
        extends SignatureSpi
    {
        public MLDSA65_RSA3072_PKCS15_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256);
        }
    }

    public static final class MLDSA65_RSA3072_PSS_SHA256
        extends SignatureSpi
    {
        public MLDSA65_RSA3072_PSS_SHA256()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256);
        }
    }

    public static final class MLDSA65_RSA4096_PKCS15_SHA384
        extends SignatureSpi
    {
        public MLDSA65_RSA4096_PKCS15_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA384);
        }
    }

    public static final class MLDSA65_RSA4096_PSS_SHA384
        extends SignatureSpi
    {
        public MLDSA65_RSA4096_PSS_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA384);
        }
    }

    public static final class MLDSA87_ECDSA_brainpoolP384r1_SHA384
        extends SignatureSpi
    {
        public MLDSA87_ECDSA_brainpoolP384r1_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384);
        }
    }

    public static final class MLDSA87_ECDSA_P384_SHA384
        extends SignatureSpi
    {
        public MLDSA87_ECDSA_P384_SHA384()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384);
        }
    }

    public static final class MLDSA87_Ed448_SHA512
        extends SignatureSpi
    {
        public MLDSA87_Ed448_SHA512()
        {
            super(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512);
        }
    }
}
