package org.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.util.Arrays;

public class DSASigner
    extends SignatureSpi
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers
{
    private Digest                  digest;
    private DSA                     signer;
    private SecureRandom            random;

    protected DSASigner(
        Digest digest,
        DSA signer)
    {
        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(
        PublicKey   publicKey)
        throws InvalidKeyException
    {
        CipherParameters    param = DSAUtil.generatePublicKeyParameter(publicKey);
        DSAParameters       dsaParam = ((DSAKeyParameters) param).getParameters();
        checkKey(dsaParam);
        digest.reset();
        signer.init(false, param);
    }

    protected void engineInitSign(
        PrivateKey      privateKey,
        SecureRandom    random)
        throws InvalidKeyException
    {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(
        PrivateKey  privateKey)
        throws InvalidKeyException
    {
        CipherParameters    param = DSAUtil.generatePrivateKeyParameter(privateKey);
        DSAParameters       dsaParam = ((DSAKeyParameters) param).getParameters();
        checkKey(dsaParam);

        if (random != null)
        {
            param = new ParametersWithRandom(param, random);
        }

        digest.reset();
        signer.init(true, param);
    }

    protected void engineUpdate(
        byte    b)
        throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len) 
        throws SignatureException
    {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        byte[]  hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        try
        {
            BigInteger[]    sig = signer.generateSignature(hash);

            return derEncode(sig[0], sig[1]);
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(
        byte[]  sigBytes) 
        throws SignatureException
    {
        byte[]  hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        BigInteger[]    sig;

        try
        {
            sig = derDecode(sigBytes);
        }
        catch (Exception e)
        {
            throw new SignatureException("error decoding signature bytes.");
        }

        return signer.verifySignature(hash, sig[0], sig[1]);
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected void checkKey(
        DSAParameters params)
        throws InvalidKeyException
    {
        if (params == null) {
            throw new InvalidKeyException("DSA key's parameter is null");
        }
        int valueL = params.getP().bitLength();
        int valueN = params.getQ().bitLength();
        int digestSize = digest.getDigestSize();

        // These checks are consistent with DSAParametersGenerator's init method.
        if ((valueL < 1024 || valueL > 3072) || valueL % 1024 != 0) 
        {
            throw new InvalidKeyException("valueL values must be between 1024 and 3072 and a multiple of 1024");
        } 
        else if (valueL == 1024 && valueN != 160) 
        {
            throw new InvalidKeyException("valueN must be 160 for valueL = 1024");
        } 
        else if (valueL == 2048 && (valueN != 224 && valueN != 256)) 
        {
            throw new InvalidKeyException("valueN must be 224 or 256 for valueL = 2048");
        } 
        else if (valueL == 3072 && valueN != 256) 
        {
            throw new InvalidKeyException("valueN must be 256 for valueL = 3072");
        }
        if (valueN > digestSize * 8) 
        {
            throw new InvalidKeyException("Key is too strong for this signature algorithm");
        }
    }

    /**
     * @deprecated replaced with <a href = "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">
     */
    protected void engineSetParameter(
        String  param,
        Object  value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(
        String      param)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    private byte[] derEncode(
        BigInteger  r,
        BigInteger  s)
        throws IOException
    {
        ASN1Integer[] rs = new ASN1Integer[]{ new ASN1Integer(r), new ASN1Integer(s) };
        return new DERSequence(rs).getEncoded(ASN1Encoding.DER);
    }

    private BigInteger[] derDecode(
        byte[]  encoding)
        throws IOException
    {
        ASN1Sequence s = (ASN1Sequence)ASN1Primitive.fromByteArray(encoding);
        if (s.size() != 2)
        {
            throw new IOException("malformed signature");
        }
        if (!Arrays.areEqual(encoding, s.getEncoded(ASN1Encoding.DER)))
        {
            throw new IOException("malformed signature");
        }

        return new BigInteger[]{
            ((ASN1Integer)s.getObjectAt(0)).getValue(),
            ((ASN1Integer)s.getObjectAt(1)).getValue()
        };
    }

    static public class stdDSA
        extends DSASigner
    {
        public stdDSA()
        {
            super(new SHA1Digest(), new org.bouncycastle.crypto.signers.DSASigner());
        }
    }

    static public class detDSA
        extends DSASigner
    {
        public detDSA()
        {
            super(new SHA1Digest(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(new SHA1Digest())));
        }
    }

    static public class dsa224
        extends DSASigner
    {
        public dsa224()
        {
            super(new SHA224Digest(), new org.bouncycastle.crypto.signers.DSASigner());
        }
    }

    static public class detDSA224
        extends DSASigner
    {
        public detDSA224()
        {
            super(new SHA224Digest(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(new SHA224Digest())));
        }
    }

    static public class dsa256
        extends DSASigner
    {
        public dsa256()
        {
            super(new SHA256Digest(), new org.bouncycastle.crypto.signers.DSASigner());
        }
    }

    static public class detDSA256
        extends DSASigner
    {
        public detDSA256()
        {
            super(new SHA256Digest(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(new SHA256Digest())));
        }
    }

    static public class dsa384
        extends DSASigner
    {
        public dsa384()
        {
            super(new SHA384Digest(), new org.bouncycastle.crypto.signers.DSASigner());
        }
    }

    static public class detDSA384
        extends DSASigner
    {
        public detDSA384()
        {
            super(new SHA384Digest(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(new SHA384Digest())));
        }
    }

    static public class dsa512
        extends DSASigner
    {
        public dsa512()
        {
            super(new SHA512Digest(), new org.bouncycastle.crypto.signers.DSASigner());
        }
    }

    static public class detDSA512
        extends DSASigner
    {
        public detDSA512()
        {
            super(new SHA512Digest(), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(new SHA512Digest())));
        }
    }

    static public class dsaSha3_224
        extends DSASigner
    {
        public dsaSha3_224()
        {
            super(new SHA3Digest(224), new org.bouncycastle.crypto.signers.DSASigner());
        }
    }

    static public class detDSASha3_224
        extends DSASigner
    {
        public detDSASha3_224()
        {
            super(new SHA3Digest(224), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(new SHA3Digest(224))));
        }
    }

    static public class dsaSha3_256
        extends DSASigner
    {
        public dsaSha3_256()
        {
            super(new SHA3Digest(256), new org.bouncycastle.crypto.signers.DSASigner());
        }
    }

    static public class detDSASha3_256
        extends DSASigner
    {
        public detDSASha3_256()
        {
            super(new SHA3Digest(256), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(new SHA3Digest(256))));
        }
    }

    static public class dsaSha3_384
        extends DSASigner
    {
        public dsaSha3_384()
        {
            super(new SHA3Digest(384), new org.bouncycastle.crypto.signers.DSASigner());
        }
    }

    static public class detDSASha3_384
        extends DSASigner
    {
        public detDSASha3_384()
        {
            super(new SHA3Digest(384), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(new SHA3Digest(384))));
        }
    }

    static public class dsaSha3_512
        extends DSASigner
    {
        public dsaSha3_512()
        {
            super(new SHA3Digest(512), new org.bouncycastle.crypto.signers.DSASigner());
        }
    }

    static public class detDSASha3_512
        extends DSASigner
    {
        public detDSASha3_512()
        {
            super(new SHA3Digest(512), new org.bouncycastle.crypto.signers.DSASigner(new HMacDSAKCalculator(new SHA3Digest(512))));
        }
    }

    static public class noneDSA
        extends DSASigner
    {
        public noneDSA()
        {
            super(new NullDigest(), new org.bouncycastle.crypto.signers.DSASigner());
        }
    }
}
