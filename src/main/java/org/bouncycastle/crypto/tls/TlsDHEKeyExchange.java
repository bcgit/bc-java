package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.io.SignerInputStream;
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

        SecurityParameters sp = context.getSecurityParameters();
        byte[] cr = sp.clientRandom, sr = sp.serverRandom;

        // TODO Determine ephemeral DH parameters to use
        BigInteger p = BigInteger.ONE;
        BigInteger g = BigInteger.ONE;
        BigInteger Ys = BigInteger.ONE;

        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(p), buf);
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(g), buf);
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(Ys), buf);

        byte[] digestInput = buf.toByteArray();

        Digest d = new CombinedHash();
        d.update(cr, 0, cr.length);
        d.update(sr, 0, sr.length);
        d.update(digestInput, 0, digestInput.length);
        
        byte[] hash = new byte[d.getDigestSize()];
        d.doFinal(hash, 0);

        byte[] sigBytes = serverCredentials.generateCertificateSignature(hash);
        TlsUtils.writeOpaque16(sigBytes, buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream is) throws IOException {

        SecurityParameters securityParameters = context.getSecurityParameters();

        Signer signer = initVerifyer(tlsSigner, securityParameters);
        InputStream sigIn = new SignerInputStream(is, signer);

        byte[] pBytes = TlsUtils.readOpaque16(sigIn);
        byte[] gBytes = TlsUtils.readOpaque16(sigIn);
        byte[] YsBytes = TlsUtils.readOpaque16(sigIn);

        byte[] sigBytes = TlsUtils.readOpaque16(is);
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
