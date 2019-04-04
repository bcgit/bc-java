package org.bouncycastle.crypto.test;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class RSADigestSignerTest
    extends SimpleTest
{
    public String getName()
    {
        return "RSADigestSigner";
    }

    public void performTest() throws Exception
    {
        BigInteger rsaPubMod = new BigInteger(Base64.decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
        BigInteger rsaPubExp = new BigInteger(Base64.decode("EQ=="));
        BigInteger rsaPrivMod = new BigInteger(Base64.decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
        BigInteger rsaPrivDP = new BigInteger(Base64.decode("JXzfzG5v+HtLJIZqYMUefJfFLu8DPuJGaLD6lI3cZ0babWZ/oPGoJa5iHpX4Ul/7l3s1PFsuy1GhzCdOdlfRcQ=="));
        BigInteger rsaPrivDQ = new BigInteger(Base64.decode("YNdJhw3cn0gBoVmMIFRZzflPDNthBiWy/dUMSRfJCxoZjSnr1gysZHK01HteV1YYNGcwPdr3j4FbOfri5c6DUQ=="));
        BigInteger rsaPrivExp = new BigInteger(Base64.decode("DxFAOhDajr00rBjqX+7nyZ/9sHWRCCp9WEN5wCsFiWVRPtdB+NeLcou7mWXwf1Y+8xNgmmh//fPV45G2dsyBeZbXeJwB7bzx9NMEAfedchyOwjR8PYdjK3NpTLKtZlEJ6Jkh4QihrXpZMO4fKZWUm9bid3+lmiq43FwW+Hof8/E="));
        BigInteger rsaPrivP = new BigInteger(Base64.decode("AJ9StyTVW+AL/1s7RBtFwZGFBgd3zctBqzzwKPda6LbtIFDznmwDCqAlIQH9X14X7UPLokCDhuAa76OnDXb1OiE="));
        BigInteger rsaPrivQ = new BigInteger(Base64.decode("AM3JfD79dNJ5A3beScSzPtWxx/tSLi0QHFtkuhtSizeXdkv5FSba7lVzwEOGKHmW829bRoNxThDy4ds1IihW1w0="));
        BigInteger rsaPrivQinv = new BigInteger(Base64.decode("Lt0g7wrsNsQxuDdB8q/rH8fSFeBXMGLtCIqfOec1j7FEIuYA/ACiRDgXkHa0WgN7nLXSjHoy630wC5Toq8vvUg=="));
        RSAKeyParameters rsaPublic = new RSAKeyParameters(false, rsaPubMod, rsaPubExp);
        RSAPrivateCrtKeyParameters rsaPrivate = new RSAPrivateCrtKeyParameters(rsaPrivMod, rsaPubExp, rsaPrivExp, rsaPrivP, rsaPrivQ, rsaPrivDP, rsaPrivDQ, rsaPrivQinv);

        checkDigest(rsaPublic, rsaPrivate, new SHA1Digest(), X509ObjectIdentifiers.id_SHA1);
        checkNullDigest(rsaPublic, rsaPrivate, new SHA1Digest(), X509ObjectIdentifiers.id_SHA1);

        checkDigest(rsaPublic, rsaPrivate, new SHA224Digest(), NISTObjectIdentifiers.id_sha224);
        checkDigest(rsaPublic, rsaPrivate, new SHA256Digest(), NISTObjectIdentifiers.id_sha256);
        checkNullDigest(rsaPublic, rsaPrivate, new SHA256Digest(), NISTObjectIdentifiers.id_sha256);
        checkDigest(rsaPublic, rsaPrivate, new SHA384Digest(), NISTObjectIdentifiers.id_sha384);
        checkDigest(rsaPublic, rsaPrivate, new SHA512Digest(), NISTObjectIdentifiers.id_sha512);
        checkDigest(rsaPublic, rsaPrivate, new SHA512tDigest(224), NISTObjectIdentifiers.id_sha512_224);
        checkDigest(rsaPublic, rsaPrivate, new SHA512tDigest(256), NISTObjectIdentifiers.id_sha512_256);

        checkDigest(rsaPublic, rsaPrivate, new SHA3Digest(224), NISTObjectIdentifiers.id_sha3_224);
        checkDigest(rsaPublic, rsaPrivate, new SHA3Digest(256), NISTObjectIdentifiers.id_sha3_256);
        checkDigest(rsaPublic, rsaPrivate, new SHA3Digest(384), NISTObjectIdentifiers.id_sha3_384);
        checkDigest(rsaPublic, rsaPrivate, new SHA3Digest(512), NISTObjectIdentifiers.id_sha3_512);

        // Null format test
        RSADigestSigner signer = new RSADigestSigner(new NullDigest());
        
        signer.init(true, rsaPrivate);

        signer.update(new byte[16], 0, 16);

        try
        {
            signer.generateSignature();
            fail("no exception");
        }
        catch (CryptoException e)
        {
            isTrue(e.getMessage().startsWith("unable to encode signature: malformed DigestInfo"));
        }
    }

    private void checkDigest(RSAKeyParameters rsaPublic, RSAPrivateCrtKeyParameters rsaPrivate, Digest digest, ASN1ObjectIdentifier digOid)
        throws Exception
    {
        byte[] msg = new byte[] { 1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23 };

        RSADigestSigner signer = new RSADigestSigner(digest);
        signer.init(true, rsaPrivate);
        signer.update(msg, 0, msg.length);
        byte[] sig = signer.generateSignature();

        signer = new RSADigestSigner(digest, digOid);
        signer.init(false, rsaPublic);
        signer.update(msg, 0, msg.length);
        if (!signer.verifySignature(sig))
        {
            fail("RSA Digest Signer failed.");
        }
    }

    private void checkNullDigest(RSAKeyParameters rsaPublic, RSAPrivateCrtKeyParameters rsaPrivate, Digest digest, ASN1ObjectIdentifier digOid)
        throws Exception
    {
        byte[] msg = new byte[] { 1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23 };

        RSADigestSigner signer = new RSADigestSigner(new NullDigest());

        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(msg, 0, msg.length);
        digest.doFinal(hash, 0);

        DigestInfo digInfo = new DigestInfo(new AlgorithmIdentifier(digOid, DERNull.INSTANCE), hash);
        byte[] infoEnc = digInfo.getEncoded();

        signer.init(true, rsaPrivate);

        signer.update(infoEnc, 0, infoEnc.length);

        byte[] sig = signer.generateSignature();

        signer = new RSADigestSigner(digest, digOid);
        signer.init(false, rsaPublic);
        signer.update(msg, 0, msg.length);
        if (!signer.verifySignature(sig))
        {
            fail("NONE - RSA Digest Signer failed.");
        }

        signer = new RSADigestSigner(new NullDigest());
        signer.init(false, rsaPublic);
        signer.update(infoEnc, 0, infoEnc.length);
        if (!signer.verifySignature(sig))
        {
            fail("NONE - RSA Digest Signer failed.");
        }
    }

    public static void main(String[] args)
    {
        runTest(new RSADigestSignerTest());
    }
}
