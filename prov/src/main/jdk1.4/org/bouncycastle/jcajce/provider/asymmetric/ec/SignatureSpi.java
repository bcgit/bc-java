package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.ECNRSigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.DSABase;
import org.bouncycastle.jcajce.provider.asymmetric.util.DSAEncoder;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SignatureSpi
    extends DSABase
{
    SignatureSpi(Digest digest, DSAExt signer, DSAEncoding encoder)
    {
        super("ECDSA", digest, signer, encoder);
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        CipherParameters param = ECUtils.generatePublicKeyParameter(publicKey);

        digest.reset();

        signer.init(false, param);
    }

    protected void doEngineInitSign(
        PrivateKey privateKey,
        SecureRandom random)
        throws InvalidKeyException
    {
        CipherParameters param;

        param = ECUtils.generatePrivateKeyParameter(privateKey);

        digest.reset();

        if (random != null)
        {
            signer.init(true, new ParametersWithRandom(param, random));
        }
        else
        {
            signer.init(true, param);
        }
    }

    static public class ecDSA
        extends SignatureSpi
    {
        public ecDSA()
        {
            super(new SHA1Digest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSAnone
        extends SignatureSpi
    {
        public ecDSAnone()
        {
            super(new NullDigest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA224
        extends SignatureSpi
    {
        public ecDSA224()
        {
            super(new SHA224Digest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA256
        extends SignatureSpi
    {
        public ecDSA256()
        {
            super(new SHA256Digest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA384
        extends SignatureSpi
    {
        public ecDSA384()
        {
            super(new SHA384Digest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSA512
        extends SignatureSpi
    {
        public ecDSA512()
        {
            super(new SHA512Digest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_224
        extends SignatureSpi
    {
        public ecDSASha3_224()
        {
            super(new SHA3Digest(224), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_224
        extends SignatureSpi
    {
        public ecDetDSASha3_224()
        {
            super(new SHA3Digest(224), new ECDSASigner(new HMacDSAKCalculator(new SHA3Digest(224))), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_256
        extends SignatureSpi
    {
        public ecDSASha3_256()
        {
            super(new SHA3Digest(256), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_256
        extends SignatureSpi
    {
        public ecDetDSASha3_256()
        {
            super(new SHA3Digest(256), new ECDSASigner(new HMacDSAKCalculator(new SHA3Digest(256))), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_384
        extends SignatureSpi
    {
        public ecDSASha3_384()
        {
            super(new SHA3Digest(384), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_384
        extends SignatureSpi
    {
        public ecDetDSASha3_384()
        {
            super(new SHA3Digest(384), new ECDSASigner(new HMacDSAKCalculator(new SHA3Digest(384))), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSASha3_512
        extends SignatureSpi
    {
        public ecDSASha3_512()
        {
            super(new SHA3Digest(512), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDetDSASha3_512
        extends SignatureSpi
    {
        public ecDetDSASha3_512()
        {
            super(new SHA3Digest(512), new ECDSASigner(new HMacDSAKCalculator(new SHA3Digest(512))), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecDSARipeMD160
        extends SignatureSpi
    {
        public ecDSARipeMD160()
        {
            super(new RIPEMD160Digest(), new ECDSASigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR
        extends SignatureSpi
    {
        public ecNR()
        {
            super(new SHA1Digest(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR224
        extends SignatureSpi
    {
        public ecNR224()
        {
            super(new SHA224Digest(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR256
        extends SignatureSpi
    {
        public ecNR256()
        {
            super(new SHA256Digest(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR384
        extends SignatureSpi
    {
        public ecNR384()
        {
            super(new SHA384Digest(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecNR512
        extends SignatureSpi
    {
        public ecNR512()
        {
            super(new SHA512Digest(), new ECNRSigner(), StandardDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA
        extends SignatureSpi
    {
        public ecCVCDSA()
        {
            super(new SHA1Digest(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA224
        extends SignatureSpi
    {
        public ecCVCDSA224()
        {
            super(new SHA224Digest(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA256
        extends SignatureSpi
    {
        public ecCVCDSA256()
        {
            super(new SHA256Digest(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA384
        extends SignatureSpi
    {
        public ecCVCDSA384()
        {
            super(new SHA384Digest(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA512
        extends SignatureSpi
    {
        public ecCVCDSA512()
        {
            super(new SHA512Digest(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA3_224
        extends SignatureSpi
    {
        public ecCVCDSA3_224()
        {
            super(DigestFactory.createSHA3_224(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA3_256
        extends SignatureSpi
    {
        public ecCVCDSA3_256()
        {
            super(DigestFactory.createSHA3_256(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA3_384
        extends SignatureSpi
    {
        public ecCVCDSA3_384()
        {
            super(DigestFactory.createSHA3_384(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }

    static public class ecCVCDSA3_512
        extends SignatureSpi
    {
        public ecCVCDSA3_512()
        {
            super(DigestFactory.createSHA3_512(), new ECDSASigner(), PlainDSAEncoding.INSTANCE);
        }
    }
}
