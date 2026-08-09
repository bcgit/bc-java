package org.bouncycastle.openpgp.smartcard.card;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
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

    public List<Algorithm> getAlgorithms()
    {
        return new ArrayList<>(algorithms);
    }

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
        public String toString()
        {
            return "Rsa{algorithmId=" + algorithmId + ", keySize=" + keySize + '}';
        }
    }

    public static class EC extends Algorithm
    {
        public final ASN1ObjectIdentifier curve;

        public EC(byte keyRef, int algorithmId, ASN1ObjectIdentifier curve)
        {
            super(keyRef, algorithmId);
            this.curve = curve;
        }

        @Override
        public boolean matches(OpenPGPCertificate.OpenPGPComponentKey key)
        {
            if (algorithmId != key.getAlgorithm())
            {
                if (key.getAlgorithm() != PublicKeyAlgorithmTags.X25519 || algorithmId != PublicKeyAlgorithmTags.ECDH)
                {
                    return false;
                }
            }
            BCPGKey pubKey = key.getPGPPublicKey().getPublicKeyPacket().getKey();
            if (pubKey instanceof ECPublicBCPGKey)
            {
                ECPublicBCPGKey ecPubKey = (ECPublicBCPGKey) key.getPGPPublicKey().getPublicKeyPacket().getKey();
                if (curve.equals(ecPubKey.getCurveOID()))
                {
                    return true;
                }
            }
            else if (pubKey instanceof X25519PublicBCPGKey)
            {
                if (curve.equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    return true;
                }
            }
            return false;
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
        return sb.toString();
    }
}
