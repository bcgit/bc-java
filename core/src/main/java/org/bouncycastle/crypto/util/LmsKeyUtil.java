package org.bouncycastle.crypto.util;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.HSSPublicKeyParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSPublicKeyParameters;
import org.bouncycastle.crypto.signers.lms.Composer;
import org.bouncycastle.util.Arrays;

/**
 * The LMS / HSS (RFC 8554) half of the key factories in this package, held apart from them so that
 * the distributions which exclude LMS - the jdk1.4 and jdk1.3 Ant builds - can replace this one
 * class rather than fork four factories. Every method answers null for a key or a key info that is
 * not LMS / HSS, which is what lets the callers fall through to their own unrecognised-algorithm
 * handling; the jdk1.4 twin answers null unconditionally.
 * <p>
 * <b>Keep the jdk1.4 twin (core/src/main/jdk1.4) in step with this class:</b> a method added
 * here and not there breaks the jdk1.4 and jdk1.3 Ant builds.
 */
class LmsKeyUtil
{
    private LmsKeyUtil()
    {
    }

    /**
     * The SubjectPublicKeyInfo for an LMS or HSS public key, or null if the key is neither.
     */
    static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        throws IOException
    {
        AlgorithmIdentifier algorithmIdentifier =
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);

        if (publicKey instanceof LMSPublicKeyParameters)
        {
            LMSPublicKeyParameters params = (LMSPublicKeyParameters)publicKey;

            byte[] encoding = Composer.compose().u32str(1).bytes(params).build();

            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }
        if (publicKey instanceof HSSPublicKeyParameters)
        {
            HSSPublicKeyParameters params = (HSSPublicKeyParameters)publicKey;

            byte[] encoding = Composer.compose().u32str(params.getL()).bytes(params.getLMSPublicKey()).build();

            return new SubjectPublicKeyInfo(algorithmIdentifier, encoding);
        }

        return null;
    }

    /**
     * The PrivateKeyInfo for an LMS or HSS private key, or null if the key is neither.
     */
    static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes)
        throws IOException
    {
        AlgorithmIdentifier algorithmIdentifier =
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);

        if (privateKey instanceof LMSPrivateKeyParameters)
        {
            LMSPrivateKeyParameters params = (LMSPrivateKeyParameters)privateKey;

            byte[] encoding = Composer.compose().u32str(1).bytes(params).build();
            byte[] pubEncoding = Composer.compose().u32str(1).bytes(params.getPublicKey()).build();

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }
        if (privateKey instanceof HSSPrivateKeyParameters)
        {
            HSSPrivateKeyParameters params = (HSSPrivateKeyParameters)privateKey;

            byte[] encoding = Composer.compose().u32str(params.getL()).bytes(params).build();
            byte[] pubEncoding = Composer.compose().u32str(params.getL())
                .bytes(params.getPublicKey().getLMSPublicKey()).build();

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }

        return null;
    }

    /**
     * The public key parameters for an HSS/LMS SubjectPublicKeyInfo. Only called for the
     * id-alg-hss-lms-hashsig algorithm, so this never answers null in the base tree.
     */
    static AsymmetricKeyParameter createPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        byte[] keyEnc = keyInfo.getPublicKeyData().getOctets();
        ASN1Primitive data = Utils.parseData(keyEnc);

        if (data instanceof ASN1OctetString)
        {
            return HSSPublicKeyParameters.getInstance(ASN1OctetString.getInstance(data).getOctets());
        }

        return HSSPublicKeyParameters.getInstance(keyEnc);
    }

    /**
     * The private key parameters for an HSS/LMS PrivateKeyInfo, or null when this distribution has
     * no LMS support. The 4-byte prefix skipped here is the RFC 8554 level count.
     */
    static AsymmetricKeyParameter createPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        byte[] keyEnc = Utils.parseOctetString(keyInfo.getPrivateKey(), 64).getOctets();
        ASN1BitString pubKey = keyInfo.getPublicKeyData();

        if (pubKey != null)
        {
            return HSSPrivateKeyParameters.getInstance(
                Arrays.copyOfRange(keyEnc, 4, keyEnc.length), pubKey.getOctets());
        }

        return HSSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
    }
}
