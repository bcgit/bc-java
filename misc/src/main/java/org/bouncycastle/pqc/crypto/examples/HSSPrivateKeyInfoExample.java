package org.bouncycastle.pqc.crypto.examples;

import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.lms.HSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.HSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.util.encoders.Hex;

/**
 * Demonstrates encoding an {@link HSSPrivateKeyParameters} value as a
 * PKCS#8 {@link PrivateKeyInfo} (RFC 5958), using the
 * {@code id-alg-hss-lms-hashsig} algorithm identifier from RFC 8708, and
 * decoding the resulting bytes back into the lightweight key parameters.
 * <p>
 * The HSS parameter set used here is intentionally small (two LMS levels,
 * each with an h=5 / w=8 OTS configuration) so the example runs quickly;
 * production deployments should consult RFC 8554 / SP 800-208 for sizing.
 */
public class HSSPrivateKeyInfoExample
{
    public static void main(String[] args)
        throws Exception
    {
        // 1. Generate an HSS key pair.
        LMSParameters[] hssLevels = new LMSParameters[]{
            new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w8),
            new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w8)
        };

        HSSKeyPairGenerator kpg = new HSSKeyPairGenerator();
        kpg.init(new HSSKeyGenerationParameters(hssLevels, new SecureRandom()));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        HSSPrivateKeyParameters priv = (HSSPrivateKeyParameters)kp.getPrivate();

        // 2. Encode the lightweight HSS private key as a PrivateKeyInfo.
        //    PrivateKeyInfoFactory recognises HSSPrivateKeyParameters and
        //    emits a PrivateKeyInfo carrying the id-alg-hss-lms-hashsig OID.
        PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(priv);

        byte[] derBytes = pkInfo.getEncoded(ASN1Encoding.DER);
        System.out.println("PrivateKeyInfo OID         : " + pkInfo.getPrivateKeyAlgorithm().getAlgorithm());
        System.out.println("PrivateKeyInfo DER length  : " + derBytes.length + " bytes");
        // -DM Hex.toHexString
        System.out.println("PrivateKeyInfo DER (head)  : "
            + Hex.toHexString(derBytes, 0, Math.min(derBytes.length, 32)) + "...");

        // 3. Round-trip: decode the PrivateKeyInfo back into an HSSPrivateKeyParameters.
        AsymmetricKeyParameter recovered = PrivateKeyFactory.createKey(derBytes);
        if (!(recovered instanceof HSSPrivateKeyParameters))
        {
            throw new IllegalStateException("expected HSSPrivateKeyParameters, got " + recovered.getClass());
        }
        HSSPrivateKeyParameters recoveredHSS = (HSSPrivateKeyParameters)recovered;

        System.out.println("Recovered HSS depth (L)    : " + recoveredHSS.getL());
        System.out.println("Round-trip OK              : "
            + (recoveredHSS.getL() == priv.getL()
                && recoveredHSS.getPublicKey().equals(priv.getPublicKey())));
    }
}
