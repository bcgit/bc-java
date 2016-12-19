package org.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.Signature;
import java.security.interfaces.DSAKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.util.Arrays;

public class DSASigner
    extends Signature
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers
{
    private Digest                  digest;
    private DSA                     signer;

    protected DSASigner(
        Digest digest,
        DSA signer)
    {
	super(digest.getAlgorithmName() + "withDSA");
        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(
        PublicKey   publicKey)
        throws InvalidKeyException
    {
        CipherParameters    param;

        if (publicKey instanceof DSAKey)
        {
            param = DSAUtil.generatePublicKeyParameter(publicKey);
        }
        else
        {
            try
            {
                byte[]  bytes = publicKey.getEncoded();

                publicKey = new BCDSAPublicKey(SubjectPublicKeyInfo.getInstance(bytes));

                if (publicKey instanceof DSAKey)
                {
                    param = DSAUtil.generatePublicKeyParameter(publicKey);
                }
                else
                {
                    throw new InvalidKeyException("can't recognise key type in DSA based signer");
                }
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("can't recognise key type in DSA based signer");
            }
        }

        digest.reset();
        signer.init(false, param);
    }

    protected void engineInitSign(
        PrivateKey  privateKey)
        throws InvalidKeyException
    {
        CipherParameters    param;

        param = DSAUtil.generatePrivateKeyParameter(privateKey);

        if (appRandom != null)
        {
            param = new ParametersWithRandom(param, appRandom);
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
