package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.util.Arrays;

public class DigestSignatureSpi
    extends Signature
{
    private Digest digest;
    private AsymmetricBlockCipher cipher;
    private AlgorithmIdentifier algId;

    // care - this constructor is actually used by outside organisations
    protected DigestSignatureSpi(
        Digest digest,
        AsymmetricBlockCipher cipher)
    {
        super(digest.getAlgorithmName() + "withRSA");
        this.digest = digest;
        this.cipher = cipher;
        this.algId = null;
    }

    // care - this constructor is actually used by outside organisations
    protected DigestSignatureSpi(
        ASN1ObjectIdentifier objId,
        Digest digest,
        AsymmetricBlockCipher cipher)
    {
        super(digest.getAlgorithmName() + "withRSA");
        this.digest = digest;
        this.cipher = cipher;
        this.algId = new AlgorithmIdentifier(objId, DERNull.INSTANCE);
    }

    protected void engineInitVerify(
        PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof RSAPublicKey))
        {
            throw new InvalidKeyException("Supplied key (" + getType(publicKey) + ") is not a RSAPublicKey instance");
        }

        CipherParameters param = RSAUtil.generatePublicKeyParameter((RSAPublicKey)publicKey);

        digest.reset();
        cipher.init(false, param);
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        if (!(privateKey instanceof RSAPrivateKey))
        {
            throw new InvalidKeyException("Supplied key (" + getType(privateKey) + ") is not a RSAPrivateKey instance");
        }

        CipherParameters param = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)privateKey);

        digest.reset();

        cipher.init(true, param);
    }

    private String getType(
        Object o)
    {
        if (o == null)
        {
            return null;
        }
        
        return o.getClass().getName();
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
            byte[]  bytes = derEncode(hash);

            return cipher.processBlock(bytes, 0, bytes.length);
        }
        catch (ArrayIndexOutOfBoundsException e)
        {
            throw new SignatureException("key too small for signature type");
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

        byte[]      sig;
        byte[]      expected;

        try
        {
            sig = cipher.processBlock(sigBytes, 0, sigBytes.length);

            expected = derEncode(hash);
        }
        catch (Exception e)
        {
            return false;
        }

        if (sig.length == expected.length)
        {
            return Arrays.constantTimeAreEqual(sig, expected);
        }
        else if (sig.length == expected.length - 2)  // NULL left out
        {
            int sigOffset = sig.length - hash.length - 2;
            int expectedOffset = expected.length - hash.length - 2;

            expected[1] -= 2;      // adjust lengths
            expected[3] -= 2;

            int nonEqual = 0;

            for (int i = 0; i < hash.length; i++)
            {
                nonEqual |= (sig[sigOffset + i] ^ expected[expectedOffset + i]);
            }

            for (int i = 0; i < sigOffset; i++)
            {
                nonEqual |= (sig[i] ^ expected[i]);  // check header less NULL
            }

            return nonEqual == 0;
        }
        else
        {
            Arrays.constantTimeAreEqual(expected, expected);  // keep time "steady".

            return false;
        }
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
        String param,
        Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(
        String param)
    {
        return null;
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    private byte[] derEncode(
        byte[]  hash)
        throws IOException
    {
        if (algId == null)
        {
            // For raw RSA, the DigestInfo must be prepared externally
            return hash;
        }

        DigestInfo dInfo = new DigestInfo(algId, hash);

        return dInfo.getEncoded(ASN1Encoding.DER);
    }

    static public class SHA1
        extends DigestSignatureSpi
    {
        public SHA1()
        {
            super(OIWObjectIdentifiers.idSHA1, new SHA1Digest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class SHA224
        extends DigestSignatureSpi
    {
        public SHA224()
        {
            super(NISTObjectIdentifiers.id_sha224, new SHA224Digest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class SHA256
        extends DigestSignatureSpi
    {
        public SHA256()
        {
            super(NISTObjectIdentifiers.id_sha256, new SHA256Digest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class SHA384
        extends DigestSignatureSpi
    {
        public SHA384()
        {
            super(NISTObjectIdentifiers.id_sha384, new SHA384Digest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class SHA512
        extends DigestSignatureSpi
    {
        public SHA512()
        {
            super(NISTObjectIdentifiers.id_sha512, new SHA512Digest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class SHA512_224
        extends DigestSignatureSpi
    {
        public SHA512_224()
        {
            super(NISTObjectIdentifiers.id_sha512_224, new SHA512tDigest(224), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class SHA512_256
        extends DigestSignatureSpi
    {
        public SHA512_256()
        {
            super(NISTObjectIdentifiers.id_sha512_256, new SHA512tDigest(256), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class SHA3_224
        extends DigestSignatureSpi
    {
        public SHA3_224()
        {
            super(NISTObjectIdentifiers.id_sha3_224, new SHA3Digest(224), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class SHA3_256
        extends DigestSignatureSpi
    {
        public SHA3_256()
        {
            super(NISTObjectIdentifiers.id_sha3_256, new SHA3Digest(256), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class SHA3_384
        extends DigestSignatureSpi
    {
        public SHA3_384()
        {
            super(NISTObjectIdentifiers.id_sha3_384, new SHA3Digest(384), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class SHA3_512
        extends DigestSignatureSpi
    {
        public SHA3_512()
        {
            super(NISTObjectIdentifiers.id_sha3_512, new SHA3Digest(512), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class MD2
        extends DigestSignatureSpi
    {
        public MD2()
        {
            super(PKCSObjectIdentifiers.md2, new MD2Digest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class MD4
        extends DigestSignatureSpi
    {
        public MD4()
        {
            super(PKCSObjectIdentifiers.md4, new MD4Digest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class MD5
        extends DigestSignatureSpi
    {
        public MD5()
        {
            super(PKCSObjectIdentifiers.md5, new MD5Digest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class RIPEMD160
        extends DigestSignatureSpi
    {
        public RIPEMD160()
        {
            super(TeleTrusTObjectIdentifiers.ripemd160, new RIPEMD160Digest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class RIPEMD128
        extends DigestSignatureSpi
    {
        public RIPEMD128()
        {
            super(TeleTrusTObjectIdentifiers.ripemd128, new RIPEMD128Digest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class RIPEMD256
        extends DigestSignatureSpi
    {
        public RIPEMD256()
        {
            super(TeleTrusTObjectIdentifiers.ripemd256, new RIPEMD256Digest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }

    static public class noneRSA
        extends DigestSignatureSpi
    {
        public noneRSA()
        {
            super(new NullDigest(), new PKCS1Encoding(new RSABlindedEngine()));
        }
    }
}
