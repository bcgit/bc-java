package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.util.BigIntegers;

/**
 * JCE support class for Diffie-Hellman key pair generation and key agreement over a specified Diffie-Hellman configuration.
 */
public class JceTlsDHDomain
    implements TlsDHDomain
{
    private static byte[] encodeValue(DHParameterSpec dh, boolean padded, BigInteger x)
    {
        return padded
            ?   BigIntegers.asUnsignedByteArray(getValueLength(dh), x)
            :   BigIntegers.asUnsignedByteArray(x);
    }

    private static int getValueLength(DHParameterSpec dh)
    {
        return (dh.getP().bitLength() + 7) / 8;
    }

    public static JceTlsSecret calculateDHAgreement(JcaTlsCrypto crypto, DHPrivateKey privateKey, DHPublicKey publicKey,
        boolean padded) throws IOException
    {
        try
        {
            /*
             * RFC 5246 8.1.2. Leading bytes of Z that contain all zero bits are stripped before it
             * is used as the pre_master_secret. We use the convention established by the JSSE to
             * signal this by asking for "TlsPremasterSecret".
             */
            byte[] secret = crypto.calculateKeyAgreement("DiffieHellman", privateKey, publicKey, "TlsPremasterSecret");

            if (padded)
            {
                int length = getValueLength(privateKey.getParams());
                byte[] tmp = new byte[length];
                System.arraycopy(secret, 0, tmp, length - secret.length, secret.length);
                Arrays.fill(secret, (byte)0);
                secret = tmp;
            }

            return crypto.adoptLocalSecret(secret);
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }

    protected final JcaTlsCrypto crypto;
    protected final TlsDHConfig dhConfig;
    protected final DHParameterSpec dhSpec;

    public JceTlsDHDomain(JcaTlsCrypto crypto, TlsDHConfig dhConfig)
    {
        DHGroup dhGroup = TlsDHUtils.getDHGroup(dhConfig);
        if (null != dhGroup)
        {
            DHParameterSpec spec = DHUtil.getDHParameterSpec(crypto, dhGroup);
            if (null != spec)
            {
                this.crypto = crypto;
                this.dhConfig = dhConfig;
                this.dhSpec = spec;
                return;
            }
        }

        throw new IllegalArgumentException("No DH configuration provided");
    }

    public JceTlsSecret calculateDHAgreement(DHPrivateKey privateKey, DHPublicKey publicKey)
        throws IOException
    {
        return calculateDHAgreement(crypto, privateKey, publicKey, dhConfig.isPadded());
    }

    public TlsAgreement createDH()
    {
        return new JceTlsDH(this);
    }

    public BigInteger decodeParameter(byte[] encoding) throws IOException
    {
        if (dhConfig.isPadded() && getValueLength(dhSpec) != encoding.length)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return new BigInteger(1, encoding);
    }

    public DHPublicKey decodePublicKey(byte[] encoding) throws IOException
    {
        /*
         * RFC 7919 3. [..] the client MUST verify that dh_Ys is in the range 1 < dh_Ys < dh_p - 1.
         * If dh_Ys is not in this range, the client MUST terminate the connection with a fatal
         * handshake_failure(40) alert.
         */
        try
        {
            BigInteger y = decodeParameter(encoding);
            KeySpec publicKeySpec = DHUtil.createPublicKeySpec(y, dhSpec);

            KeyFactory keyFactory = crypto.getHelper().createKeyFactory("DiffieHellman");
            return (DHPublicKey)keyFactory.generatePublic(publicKeySpec);
        }
        catch (IOException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure, e);
        }
    }

    public byte[] encodeParameter(BigInteger x) throws IOException
    {
        return encodeValue(dhSpec, dhConfig.isPadded(), x);
    }

    public byte[] encodePublicKey(DHPublicKey publicKey) throws IOException
    {
        return encodeValue(dhSpec, true, publicKey.getY());
    }

    public KeyPair generateKeyPair() throws IOException
    {
        try
        {
            KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("DiffieHellman");
            keyPairGenerator.initialize(dhSpec, crypto.getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("unable to create key pair", e);
        }
    }
}
