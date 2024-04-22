package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.util.Exceptions;

/**
 * Signature class for composite signatures. Selected algorithm is set by the "subclasses" at the end of this file.
 */
public class SignatureSpi
    extends java.security.SignatureSpi
{
    //Enum value of the selected composite signature algorithm.
    private final CompositeSignaturesConstants.CompositeName algorithmIdentifier;
    //ASN1 OI value of the selected composite signature algorithm.
    private final ASN1ObjectIdentifier algorithmIdentifierASN1;

    //List of Signatures. Each entry corresponds to a component signature from the composite definition.
    private final List<Signature> componentSignatures;

    //Hash function that is used to pre-hash the input message before it is fed into the component Signature.
    //Each composite signature has a specific hash function https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-sigs-13.html
    private final Digest digest;
    private byte[] OIDBytes;


    SignatureSpi(CompositeSignaturesConstants.CompositeName algorithmIdentifier)
    {
        this.algorithmIdentifier = algorithmIdentifier;
        this.algorithmIdentifierASN1 = CompositeSignaturesConstants.compositeNameASN1IdentifierMap.get(this.algorithmIdentifier);
        List<Signature> componentSignatures = new ArrayList<Signature>();
        try
        {
            switch (this.algorithmIdentifier)
            {
            case MLDSA44_Ed25519_SHA512:
            case MLDSA65_Ed25519_SHA512:
                componentSignatures.add(Signature.getInstance("Dilithium", "BC"));
                componentSignatures.add(Signature.getInstance("Ed25519", "BC"));
                this.digest = DigestFactory.createSHA512();
                break;
            case MLDSA87_Ed448_SHA512:
                componentSignatures.add(Signature.getInstance("Dilithium", "BC"));
                componentSignatures.add(Signature.getInstance("Ed448", "BC"));
                this.digest = DigestFactory.createSHA512();
                break;
            case MLDSA44_RSA2048_PSS_SHA256:
                componentSignatures.add(Signature.getInstance("Dilithium", "BC"));
                componentSignatures.add(Signature.getInstance("SHA256withRSA/PSS", "BC")); //PSS with SHA-256 as digest algo and MGF.
                this.digest = DigestFactory.createSHA256();
                break;
            case MLDSA65_RSA3072_PSS_SHA512:
                componentSignatures.add(Signature.getInstance("Dilithium", "BC"));
                componentSignatures.add(Signature.getInstance("SHA512withRSA/PSS", "BC")); //PSS with SHA-512 as digest algo and MGF.
                this.digest = DigestFactory.createSHA512();
                break;
            case MLDSA44_RSA2048_PKCS15_SHA256:
                componentSignatures.add(Signature.getInstance("Dilithium", "BC"));
                componentSignatures.add(Signature.getInstance("SHA256withRSA", "BC")); //PKCS15
                this.digest = DigestFactory.createSHA256();
                break;
            case MLDSA65_RSA3072_PKCS15_SHA512:
                componentSignatures.add(Signature.getInstance("Dilithium", "BC"));
                componentSignatures.add(Signature.getInstance("SHA512withRSA", "BC")); //PKCS15
                this.digest = DigestFactory.createSHA512();
                break;
            case MLDSA44_ECDSA_P256_SHA256:
            case MLDSA44_ECDSA_brainpoolP256r1_SHA256:
                componentSignatures.add(Signature.getInstance("Dilithium", "BC"));
                componentSignatures.add(Signature.getInstance("SHA256withECDSA", "BC"));
                this.digest = DigestFactory.createSHA256();
                break;
            case MLDSA65_ECDSA_P256_SHA512:
            case MLDSA65_ECDSA_brainpoolP256r1_SHA512:
            case MLDSA87_ECDSA_P384_SHA512:
            case MLDSA87_ECDSA_brainpoolP384r1_SHA512:
                componentSignatures.add(Signature.getInstance("Dilithium", "BC"));
                componentSignatures.add(Signature.getInstance("SHA512withECDSA", "BC"));
                this.digest = DigestFactory.createSHA512();
                break;
            case Falcon512_ECDSA_P256_SHA256:
            case Falcon512_ECDSA_brainpoolP256r1_SHA256:
                componentSignatures.add(Signature.getInstance("Falcon", "BC"));
                componentSignatures.add(Signature.getInstance("SHA256withECDSA", "BC"));
                this.digest = DigestFactory.createSHA256();
                break;
            case Falcon512_Ed25519_SHA512:
                componentSignatures.add(Signature.getInstance("Falcon", "BC"));
                componentSignatures.add(Signature.getInstance("Ed25519", "BC"));
                this.digest = DigestFactory.createSHA512();
                break;
            default:
                throw new IllegalArgumentException("unknown composite algorithm");
            }

            //get bytes of composite signature algorithm OID in DER
            //these bytes are used a prefix to the message digest https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-sigs-13.html#name-composite-sign
            OIDBytes = this.algorithmIdentifierASN1.getEncoded(ASN1Encoding.DER);
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
        this.componentSignatures = Collections.unmodifiableList(componentSignatures);
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {

        if (!(publicKey instanceof CompositePublicKey))
        {
            throw new InvalidKeyException("Public key is not composite.");
        }

        CompositePublicKey compositePublicKey = (CompositePublicKey)publicKey;

        if (!compositePublicKey.getAlgorithmIdentifier().equals(this.algorithmIdentifierASN1))
        {
            throw new InvalidKeyException("Provided composite public key cannot be used with the composite signature algorithm.");
        }

        //for each component signature run initVerify with the corresponding public key.
        for (int i = 0; i < this.componentSignatures.size(); i++)
        {
            this.componentSignatures.get(i).initVerify(compositePublicKey.getPublicKeys().get(i));
        }
    }

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        if (!(privateKey instanceof CompositePrivateKey))
        {
            throw new InvalidKeyException("Private key is not composite.");
        }

        CompositePrivateKey compositePrivateKey = (CompositePrivateKey)privateKey;
        
        if (!compositePrivateKey.getAlgorithmIdentifier().equals(this.algorithmIdentifierASN1))
        {
            throw new InvalidKeyException("Provided composite private key cannot be used with the composite signature algorithm.");
        }

        //for each component signature run initVerify with the corresponding private key.
        for (int i = 0; i < this.componentSignatures.size(); i++)
        {
            this.componentSignatures.get(i).initSign(compositePrivateKey.getPrivateKeys().get(i));
        }
    }


    protected void engineUpdate(byte b)
        throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(byte[] bytes, int off, int len)
        throws SignatureException
    {
        digest.update(bytes, off, len);
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
        ASN1EncodableVector signatureSequence = new ASN1EncodableVector();
        try
        {
            //calculate message digest (pre-hashing of the message)
            byte[] digestResult = new byte[digest.getDigestSize()];
            digest.doFinal(digestResult, 0);

            for (int i = 0; i < this.componentSignatures.size(); i++)
            {
                this.componentSignatures.get(i).update(this.OIDBytes);
                this.componentSignatures.get(i).update(digestResult); //in total, "OID || digest(message)" is the message fed into each component signature
                byte[] signatureValue = this.componentSignatures.get(i).sign();
                signatureSequence.add(new DERBitString(signatureValue));
            }

            return new DERSequence(signatureSequence).getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new SignatureException(e.getMessage());
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
        if (signatureSequence.size() != this.componentSignatures.size())
        {
            return false;
        }

        //calculate message digest (pre-hashing of the message)
        byte[] digestResult = new byte[digest.getDigestSize()];
        digest.doFinal(digestResult, 0);

        // Currently all signatures try to verify even if, e.g., the first is invalid.
        // If each component verify() is constant time, then this is also, otherwise it does not make sense to iterate over all if one of them already fails.
        // However, it is important that we do not provide specific error messages, e.g., "only the 2nd component failed to verify".
        boolean fail = false;

        for (int i = 0; i < this.componentSignatures.size(); i++)
        {
            this.componentSignatures.get(i).update(this.OIDBytes);
            this.componentSignatures.get(i).update(digestResult); //in total, "OID || digest(message)" is the message fed into each component signature
            if (!this.componentSignatures.get(i).verify(ASN1BitString.getInstance(signatureSequence.getObjectAt(i)).getOctets()))
            {
                fail = true;
            }
        }

        return !fail;
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

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    public final static class MLDSA44_Ed25519_SHA512
        extends SignatureSpi
    {
        public MLDSA44_Ed25519_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_Ed25519_SHA512);
        }
    }

    public final static class MLDSA65_Ed25519_SHA512
        extends SignatureSpi
    {
        public MLDSA65_Ed25519_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_Ed25519_SHA512);
        }
    }

    public final static class MLDSA87_Ed448_SHA512
        extends SignatureSpi
    {
        public MLDSA87_Ed448_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_Ed448_SHA512);
        }
    }

    public final static class MLDSA44_RSA2048_PSS_SHA256
        extends SignatureSpi
    {
        public MLDSA44_RSA2048_PSS_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PSS_SHA256);
        }
    }

    public final static class MLDSA44_RSA2048_PKCS15_SHA256
        extends SignatureSpi
    {
        public MLDSA44_RSA2048_PKCS15_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_RSA2048_PKCS15_SHA256);
        }
    }

    public final static class MLDSA65_RSA3072_PSS_SHA512
        extends SignatureSpi
    {
        public MLDSA65_RSA3072_PSS_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PSS_SHA512);
        }
    }

    public final static class MLDSA65_RSA3072_PKCS15_SHA512
        extends SignatureSpi
    {
        public MLDSA65_RSA3072_PKCS15_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_RSA3072_PKCS15_SHA512);
        }
    }

    public final static class MLDSA44_ECDSA_P256_SHA256
        extends SignatureSpi
    {
        public MLDSA44_ECDSA_P256_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_P256_SHA256);
        }
    }

    public final static class MLDSA44_ECDSA_brainpoolP256r1_SHA256
        extends SignatureSpi
    {
        public MLDSA44_ECDSA_brainpoolP256r1_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA44_ECDSA_brainpoolP256r1_SHA256);
        }
    }

    public final static class MLDSA65_ECDSA_P256_SHA512
        extends SignatureSpi
    {
        public MLDSA65_ECDSA_P256_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_P256_SHA512);
        }
    }

    public final static class MLDSA65_ECDSA_brainpoolP256r1_SHA512
        extends SignatureSpi
    {
        public MLDSA65_ECDSA_brainpoolP256r1_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA65_ECDSA_brainpoolP256r1_SHA512);
        }
    }

    public final static class MLDSA87_ECDSA_P384_SHA512
        extends SignatureSpi
    {
        public MLDSA87_ECDSA_P384_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_P384_SHA512);
        }
    }

    public final static class MLDSA87_ECDSA_brainpoolP384r1_SHA512
        extends SignatureSpi
    {
        public MLDSA87_ECDSA_brainpoolP384r1_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.MLDSA87_ECDSA_brainpoolP384r1_SHA512);
        }
    }

    public final static class Falcon512_Ed25519_SHA512
        extends SignatureSpi
    {
        public Falcon512_Ed25519_SHA512()
        {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_Ed25519_SHA512);
        }
    }

    public final static class Falcon512_ECDSA_P256_SHA256
        extends SignatureSpi
    {
        public Falcon512_ECDSA_P256_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_P256_SHA256);
        }
    }

    public final static class Falcon512_ECDSA_brainpoolP256r1_SHA256
        extends SignatureSpi
    {
        public Falcon512_ECDSA_brainpoolP256r1_SHA256()
        {
            super(CompositeSignaturesConstants.CompositeName.Falcon512_ECDSA_brainpoolP256r1_SHA256);
        }
    }
}
