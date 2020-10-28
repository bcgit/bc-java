package org.bouncycastle.jcajce.provider.asymmetric.dstu;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.ua.DSTU4145Params;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSTU4145Signer;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.interfaces.ECKey;

public class SignatureSpi
    extends java.security.SignatureSpi
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers
{
    private Digest digest;
    private DSAExt signer;

    public SignatureSpi()
    {
        this.signer = new DSTU4145Signer();
    }

    protected void engineInitVerify(
        PublicKey publicKey)
        throws InvalidKeyException
    {
        CipherParameters param;

        if (publicKey instanceof BCDSTU4145PublicKey)
        {
            param = ((BCDSTU4145PublicKey)publicKey).engineGetKeyParameters();
            digest = new GOST3411Digest(expandSbox(((BCDSTU4145PublicKey)publicKey).getSbox()));
        }
        else
        {
            param = ECUtil.generatePublicKeyParameter(publicKey);
            digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
        }

        signer.init(false, param);
    }

    byte[] expandSbox(byte[] compressed)
    {
        byte[] expanded = new byte[128];

        for (int i = 0; i < compressed.length; i++)
        {
            expanded[i * 2] = (byte)((compressed[i] >> 4) & 0xf);
            expanded[i * 2 + 1] = (byte)(compressed[i] & 0xf);
        }
        return expanded;
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        CipherParameters param = null;

        if (privateKey instanceof BCDSTU4145PrivateKey)
        {
            // TODO: add parameters support.
            param = ECUtil.generatePrivateKeyParameter(privateKey);
            digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
        }
        else if (privateKey instanceof ECKey)
        {
            param = ECUtil.generatePrivateKeyParameter(privateKey);
            digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
        }

        if (appRandom != null)
        {
            signer.init(true, new ParametersWithRandom(param, appRandom));
        }
        else
        {
            signer.init(true, param);
        }
    }

    protected void engineUpdate(
        byte b)
        throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(
        byte[] b,
        int off,
        int len)
        throws SignatureException
    {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        byte[] hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        try
        {
            BigInteger[] sig = signer.generateSignature(hash);
            byte[] r = sig[0].toByteArray();
            byte[] s = sig[1].toByteArray();

            byte[] sigBytes = new byte[(r.length > s.length ? r.length * 2 : s.length * 2)];
            System.arraycopy(s, 0, sigBytes, (sigBytes.length / 2) - s.length, s.length);
            System.arraycopy(r, 0, sigBytes, sigBytes.length - r.length, r.length);

            return new DEROctetString(sigBytes).getEncoded();
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(
        byte[] sigBytes)
        throws SignatureException
    {
        byte[] hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        BigInteger[] sig;

        try
        {
            byte[] bytes = ((ASN1OctetString)ASN1OctetString.fromByteArray(sigBytes)).getOctets();

            byte[] r = new byte[bytes.length / 2];
            byte[] s = new byte[bytes.length / 2];

            System.arraycopy(bytes, 0, s, 0, bytes.length / 2);

            System.arraycopy(bytes, bytes.length / 2, r, 0, bytes.length / 2);

            sig = new BigInteger[2];
            sig[0] = new BigInteger(1, r);
            sig[1] = new BigInteger(1, s);
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

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    /**
     * @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
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
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }
}
