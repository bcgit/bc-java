package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

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
    public static DHParameterSpec getParameters(TlsDHConfig dhConfig)
    {
        DHGroup dhGroup = TlsDHUtils.getDHGroup(dhConfig);
        if (dhGroup == null)
        {
            throw new IllegalArgumentException("No DH configuration provided");
        }

        // NOTE: dhGroup.getQ() is ignored here
        return new DHParameterSpec(dhGroup.getP(), dhGroup.getG(), dhGroup.getL());
    }

    protected final JcaTlsCrypto crypto;
    protected final TlsDHConfig dhConfig;
    protected final DHParameterSpec dhParameterSpec;

    public JceTlsDHDomain(JcaTlsCrypto crypto, TlsDHConfig dhConfig)
    {
        this.crypto = crypto;
        this.dhConfig = dhConfig;
        this.dhParameterSpec = getParameters(dhConfig);
    }

    public JceTlsSecret calculateDHAgreement(DHPrivateKey privateKey, DHPublicKey publicKey)
        throws IOException
    {
        try
        {
            /*
             * RFC 5246 8.1.2. Leading bytes of Z that contain all zero bits are stripped before it is
             * used as the pre_master_secret. We use the convention established by the JSSE to signal this
             * by asking for "TlsPremasterSecret".
             */
            SecretKey secretKey = crypto.calculateKeyAgreement("DH", privateKey, publicKey, "TlsPremasterSecret");

            // TODO Need to consider cases where SecretKey may not be encodable

            return crypto.adoptLocalSecret(secretKey.getEncoded());
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }

    public TlsAgreement createDH()
    {
        return new JceTlsDH(this);
    }

    public static BigInteger decodeParameter(byte[] encoding) throws IOException
    {
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

            KeyFactory keyFactory = crypto.getHelper().createKeyFactory("DH");

            return (DHPublicKey)keyFactory.generatePublic(new DHPublicKeySpec(y, dhParameterSpec.getP(), dhParameterSpec.getG()));
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure, e);
        }
    }

    public byte[] encodeParameter(BigInteger x) throws IOException
    {
        return BigIntegers.asUnsignedByteArray(x);
    }

    public byte[] encodePublicKey(DHPublicKey publicKey) throws IOException
    {
        return encodeParameter(publicKey.getY());
    }

    public KeyPair generateKeyPair() throws IOException
    {
        try
        {
            KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("DH");
            keyPairGenerator.initialize(dhParameterSpec, crypto.getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("unable to create key pair", e);
        }
    }
}
