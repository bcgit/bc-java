package org.bouncycastle.pqc.crypto.xwing;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class XWingKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final XWingPrivateKeyParameters key;
    private final MLKEMExtractor kemExtractor;

    public XWingKEMExtractor(XWingPrivateKeyParameters privParams)
    {
        this.key = privParams;
        this.kemExtractor = new MLKEMExtractor((MLKEMPrivateKeyParameters)key.getKyberPrivateKey());
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        // Decryption
        byte[] kybSecret = kemExtractor.extractSecret(Arrays.copyOfRange(encapsulation, 0, encapsulation.length - X25519PublicKeyParameters.KEY_SIZE));
        X25519Agreement xdhAgree = new X25519Agreement();

        byte[] k = new byte[kybSecret.length + xdhAgree.getAgreementSize()];

        System.arraycopy(kybSecret, 0, k, 0, kybSecret.length);

        Arrays.clear(kybSecret);
        
        xdhAgree.init(key.getXDHPrivateKey());

        X25519PublicKeyParameters ephXdhPub = new X25519PublicKeyParameters(Arrays.copyOfRange(encapsulation, encapsulation.length - X25519PublicKeyParameters.KEY_SIZE, encapsulation.length));

        xdhAgree.calculateAgreement(ephXdhPub, k, kybSecret.length);
        
        SHA3Digest sha3 = new SHA3Digest(256);

        sha3.update(Strings.toByteArray("\\.//^\\"), 0, 6);
        sha3.update(k, 0, k.length);
        sha3.update(ephXdhPub.getEncoded(), 0, X25519PublicKeyParameters.KEY_SIZE);
        sha3.update(((X25519PrivateKeyParameters)key.getXDHPrivateKey()).generatePublicKey().getEncoded(), 0, X25519PublicKeyParameters.KEY_SIZE);

        byte[] kemSecret = new byte[32];

        sha3.doFinal(kemSecret, 0);

        return kemSecret;
    }

    public int getEncapsulationLength()
    {
        return kemExtractor.getEncapsulationLength() + X25519PublicKeyParameters.KEY_SIZE;
    }
}
