package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.util.BigIntegers;

public class BcTlsDHDomain implements TlsDHDomain
{
    protected TlsContext context;
    protected TlsDHConfig dhConfig;
    protected DHParameters dhDomain;

    public BcTlsDHDomain(TlsContext context, TlsDHConfig dhConfig)
    {
        this.context = context;
        this.dhConfig = dhConfig;
        this.dhDomain = getParameters(dhConfig);
    }

    public byte[] calculateDHAgreement(DHPublicKeyParameters publicKey, DHPrivateKeyParameters privateKey)
    {
        DHBasicAgreement basicAgreement = new DHBasicAgreement();
        basicAgreement.init(privateKey);
        BigInteger agreementValue = basicAgreement.calculateAgreement(publicKey);

        /*
         * RFC 5246 8.1.2. Leading bytes of Z that contain all zero bits are stripped before it is
         * used as the pre_master_secret.
         */
        return BigIntegers.asUnsignedByteArray(agreementValue);
    }

    public TlsAgreement createDH()
    {
        return new BcTlsDH(this);
    }

    public AsymmetricCipherKeyPair generateDHKeyPair()
    {
        DHBasicKeyPairGenerator keyPairGenerator = new DHBasicKeyPairGenerator();
        keyPairGenerator.init(new DHKeyGenerationParameters(context.getSecureRandom(), dhDomain));
        return keyPairGenerator.generateKeyPair();
    }

    public DHParameters getParameters(TlsDHConfig dhConfig)
    {
        // TODO There's a draft RFC for negotiated (named) groups

        BigInteger[] pg = dhConfig.getExplicitPG();
        if (pg != null)
        {
            return new DHParameters(pg[0], pg[1]);
        }

        throw new IllegalStateException("No DH configuration provided");
    }

    public static BigInteger readDHParameter(InputStream input) throws IOException
    {
        return new BigInteger(1, TlsUtils.readOpaque16(input));
    }

    public DHPublicKeyParameters readDHPublicKey(InputStream input) throws IOException
    {
        try
        {
            BigInteger y = TlsDHUtils.readDHParameter(input);

            // TODO Check RFCs for any validation that could/should be done here

            return new DHPublicKeyParameters(y, dhDomain);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    public static void writeDHParameter(BigInteger x, OutputStream output) throws IOException
    {
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(x), output);
    }

    public void writeDHPublicKey(DHPublicKeyParameters publicKey, OutputStream output) throws IOException
    {
        writeDHParameter(publicKey.getY(), output);
    }
}
