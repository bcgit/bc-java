package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.io.SignerInputStream;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

public class TlsDHEKeyExchange
    extends TlsDHKeyExchange
{

    protected TlsSignerCredentials serverCredentials = null;

    public TlsDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, DHParameters dhParameters)
    {
        super(keyExchange, supportedSignatureAlgorithms, dhParameters);
    }

    public void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException
    {

        if (!(serverCredentials instanceof TlsSignerCredentials))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        processServerCertificate(serverCredentials.getCertificate());

        this.serverCredentials = (TlsSignerCredentials)serverCredentials;
    }

    public byte[] generateServerKeyExchange()
        throws IOException
    {

        if (this.dhParameters == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        DHKeyPairGenerator kpg = new DHKeyPairGenerator();
        kpg.init(new DHKeyGenerationParameters(context.getSecureRandom(), this.dhParameters));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        BigInteger Ys = ((DHPublicKeyParameters)kp.getPublic()).getY();

        TlsDHUtils.writeDHParameter(dhParameters.getP(), buf);
        TlsDHUtils.writeDHParameter(dhParameters.getG(), buf);
        TlsDHUtils.writeDHParameter(Ys, buf);

        byte[] digestInput = buf.toByteArray();

        Digest d = new CombinedHash();
        SecurityParameters securityParameters = context.getSecurityParameters();
        d.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        d.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        d.update(digestInput, 0, digestInput.length);

        byte[] hash = new byte[d.getDigestSize()];
        d.doFinal(hash, 0);

        byte[] sigBytes = serverCredentials.generateCertificateSignature(hash);
        /*
         * TODO RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm prepended from TLS 1.2
         */
        TlsUtils.writeOpaque16(sigBytes, buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input)
        throws IOException
    {

        SecurityParameters securityParameters = context.getSecurityParameters();

        Signer signer = initVerifyer(tlsSigner, securityParameters);
        InputStream sigIn = new SignerInputStream(input, signer);

        BigInteger p = TlsDHUtils.readDHParameter(sigIn);
        BigInteger g = TlsDHUtils.readDHParameter(sigIn);
        BigInteger Ys = TlsDHUtils.readDHParameter(sigIn);

        byte[] sigBytes = TlsUtils.readOpaque16(input);
        if (!signer.verifySignature(sigBytes))
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error);
        }

        this.dhAgreeServerPublicKey = validateDHPublicKey(new DHPublicKeyParameters(Ys, new DHParameters(p, g)));
    }

    protected Signer initVerifyer(TlsSigner tlsSigner, SecurityParameters securityParameters)
    {
        Signer signer = tlsSigner.createVerifyer(this.serverPublicKey);
        signer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        signer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        return signer;
    }
}
