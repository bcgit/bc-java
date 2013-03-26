package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.io.SignerInputStream;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.util.BigIntegers;

class TlsDHEKeyExchange extends TlsDHKeyExchange {

    protected TlsSignerCredentials serverCredentials = null;

    TlsDHEKeyExchange(int keyExchange) {
        super(keyExchange);
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException {

        if (!(serverCredentials instanceof TlsSignerCredentials)) {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        processServerCertificate(serverCredentials.getCertificate());

        this.serverCredentials = (TlsSignerCredentials) serverCredentials;
    }

    public byte[] generateServerKeyExchange() throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // TODO Allow specification of DH parameters to use
        DHParametersGenerator pg = new DHParametersGenerator();
        pg.init(512, 100, context.getSecureRandom());
        DHParameters dhParameters = pg.generateParameters();

        DHKeyPairGenerator kpg = new DHKeyPairGenerator();
        kpg.init(new DHKeyGenerationParameters(context.getSecureRandom(), dhParameters));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        BigInteger Ys = ((DHPublicKeyParameters) kp.getPublic()).getY();

        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(dhParameters.getP()), buf);
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(dhParameters.getG()), buf);
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(Ys), buf);

        byte[] digestInput = buf.toByteArray();

        Digest d = new CombinedHash();
        SecurityParameters securityParameters = context.getSecurityParameters();
        d.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        d.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        d.update(digestInput, 0, digestInput.length);

        byte[] hash = new byte[d.getDigestSize()];
        d.doFinal(hash, 0);

        byte[] sigBytes = serverCredentials.generateCertificateSignature(hash);
        TlsUtils.writeOpaque16(sigBytes, buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException {

        SecurityParameters securityParameters = context.getSecurityParameters();

        Signer signer = initVerifyer(tlsSigner, securityParameters);
        InputStream sigIn = new SignerInputStream(input, signer);

        byte[] pBytes = TlsUtils.readOpaque16(sigIn);
        byte[] gBytes = TlsUtils.readOpaque16(sigIn);
        byte[] YsBytes = TlsUtils.readOpaque16(sigIn);

        byte[] sigBytes = TlsUtils.readOpaque16(input);
        if (!signer.verifySignature(sigBytes)) {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        BigInteger p = new BigInteger(1, pBytes);
        BigInteger g = new BigInteger(1, gBytes);
        BigInteger Ys = new BigInteger(1, YsBytes);

        this.dhAgreeServerPublicKey = validateDHPublicKey(new DHPublicKeyParameters(Ys,
            new DHParameters(p, g)));
    }

    protected Signer initVerifyer(TlsSigner tlsSigner, SecurityParameters securityParameters) {
        Signer signer = tlsSigner.createVerifyer(this.serverPublicKey);
        signer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        signer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        return signer;
    }
}
