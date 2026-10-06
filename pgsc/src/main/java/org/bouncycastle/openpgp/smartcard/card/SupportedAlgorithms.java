package org.bouncycastle.openpgp.smartcard.card;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.Ed25519PublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;

import java.util.ArrayList;
import java.util.List;

/**
 * List of supported algorithms of a Smart Card.
 */
public class SupportedAlgorithms
{

    private final List<Algorithm> algorithms = new ArrayList<>();

    public SupportedAlgorithms(List<Algorithm> algorithms)
    {
        this.algorithms.addAll(algorithms);
    }

    public SupportedAlgorithms filter(byte keyRef)
    {
        List<Algorithm> filtered = new ArrayList<>();
        for (Algorithm algorithm : algorithms)
        {
            if (algorithm.keyRef == keyRef)
            {
                filtered.add(algorithm);
            }
        }
        return new SupportedAlgorithms(filtered);
    }

    public List<Algorithm> getAlgorithms()
    {
        return new ArrayList<>(algorithms);
    }

    /**
     * Return true, if the set of supported algorithms signals support for the given key.
     *
     * @param key OpenPGP key
     * @return true if key is supported
     */
    public boolean supports(OpenPGPCertificate.OpenPGPComponentKey key)
    {
        for (Algorithm algorithm : algorithms)
        {
            if (algorithm.matches(key))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Return true, if the set of supported algorithms signals support for the given keyAlgorithm + curve OID.
     *
     * @param keyAlgorithm public key algorithm ID
     * @param curveOID elliptic curve OID
     * @return true if algorithm is supported
     */
    public boolean supports(int keyAlgorithm, ASN1ObjectIdentifier curveOID)
    {
        for (Algorithm algorithm : algorithms)
        {
            if (algorithm.matches(keyAlgorithm, curveOID))
            {
                return true;
            }
        }
        return false;
    }

    public static abstract class Algorithm
    {
        public final byte keyRef;
        public final int algorithmId;

        public Algorithm(byte keyRef, int algorithmId)
        {
            this.keyRef = keyRef;
            this.algorithmId = algorithmId;
        }

        public abstract boolean matches(OpenPGPCertificate.OpenPGPComponentKey key);

        public abstract boolean matches(int keyAlgorithm, ASN1ObjectIdentifier curveOID);

        public abstract String toString();
    }

    public static class RSA extends Algorithm
    {
        public final int keySize;

        public RSA(byte keyRef, int algorithmId, int keySize)
        {
            super(keyRef, algorithmId);
            this.keySize = keySize;
        }

        @Override
        public boolean matches(OpenPGPCertificate.OpenPGPComponentKey key)
        {
            if (key.getPGPPublicKey().getAlgorithm() == algorithmId)
            {
                return key.getPGPPublicKey().getBitStrength() == keySize;
            }
            return false;
        }

        @Override
        public boolean matches(int keyAlgorithm, ASN1ObjectIdentifier curveOID)
        {
            return false;
        }

        @Override
        public String toString()
        {
            return "Rsa{algorithmId=" + algorithmId + ", keySize=" + keySize + '}';
        }
    }

    // Elliptic curves (Brainpool, NIST, Curve25519), ECDH/X25519
    public static class EC extends Algorithm
    {
        public final ASN1ObjectIdentifier curve;

        public EC(byte keyRef, int algorithmId, ASN1ObjectIdentifier curve)
        {
            super(keyRef, algorithmId);
            this.curve = curve;
        }

        @Override
        public boolean matches(int keyAlgorithm, ASN1ObjectIdentifier keyCurve)
        {
            // Explicit match (NIST, Brainpool curves)
            if (algorithmId == keyAlgorithm)
            {
                if (curve.equals(keyCurve))
                {
                    return true;
                }
            }

            // Manual matches

            // card advertises support for Ed25519 as EDDSA_LEGACY (22),
            // but can also be used for modern Ed25519 (27)
            if (algorithmId == PublicKeyAlgorithmTags.EDDSA_LEGACY)
            {
                // card emits Ed25519 support for curve 1.3.101.112,
                // but legacy Ed25519 keys carry OID 1.3.6.1.4.1.11591.15.1 (GNU)
                if (keyAlgorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY &&
                        keyCurve.equals(GNUObjectIdentifiers.Ed25519) &&
                        curve.equals(EdECObjectIdentifiers.id_Ed25519))
                {
                    // Manually match GNU Ed25519 to EdEC Ed25519
                    return true;
                }

                // Modern Ed25519 key (27)
                // Legacy Ed25519 (22) ~= Ed25519 (27)
                if (keyAlgorithm == PublicKeyAlgorithmTags.Ed25519)
                {
                    // modern Ed25519 keys carry OID 1.3.101.112
                    if (curve.equals(keyCurve))
                    {
                        return true;
                    }
                }
            }

            // Card advertises ECDH support
            if (algorithmId == PublicKeyAlgorithmTags.ECDH)
            {
                // Modern X25519 keys (25) can be used with the card
                if (keyAlgorithm == PublicKeyAlgorithmTags.X25519)
                {
                    if (curve.equals(keyCurve))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        @Override
        public boolean matches(OpenPGPCertificate.OpenPGPComponentKey key)
        {
            ASN1ObjectIdentifier keyCurve = getKeyCurveOID(key);
            if (keyCurve == null)
            {
                return false; // unknown key curve
            }

            int keyAlgorithm = key.getAlgorithm();
            return matches(keyAlgorithm, keyCurve);
        }

        private ASN1ObjectIdentifier getKeyCurveOID(OpenPGPCertificate.OpenPGPComponentKey key)
        {
            BCPGKey pubKey = key.getPGPPublicKey().getPublicKeyPacket().getKey();
            if (pubKey instanceof ECPublicBCPGKey)
            {
                ECPublicBCPGKey ecPubKey = (ECPublicBCPGKey) key.getPGPPublicKey().getPublicKeyPacket().getKey();
                return ecPubKey.getCurveOID();
            }
            else if (pubKey instanceof X25519PublicBCPGKey)
            {
                return CryptlibObjectIdentifiers.curvey25519;
            }
            else if (pubKey instanceof Ed25519PublicBCPGKey)
            {
                return EdECObjectIdentifiers.id_Ed25519;
            }
            return null;
        }

        @Override
        public String toString()
        {
            return "Ec{algorithmId=" + algorithmId + ", curve=" + curve + '}';
        }
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        for (Algorithm a : algorithms)
        {
            sb.append(a.toString());
            sb.append("\n");
        }

        if (sb.length() > 0)
        {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }
}
