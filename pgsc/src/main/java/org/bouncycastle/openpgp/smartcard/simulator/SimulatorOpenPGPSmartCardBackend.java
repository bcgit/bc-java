package org.bouncycastle.openpgp.smartcard.simulator;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.card.SupportedAlgorithms;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class SimulatorOpenPGPSmartCardBackend
        extends OpenPGPSmartCardBackend<SimulatorOpenPGPSmartCard>
{
    private final List<SimulatorOpenPGPSmartCard> smartCards = new ArrayList<>();

    public SimulatorOpenPGPSmartCardBackend()
    {
        this(new BcOpenPGPSmartCardImplementation());
    }

    public SimulatorOpenPGPSmartCardBackend(OpenPGPSmartCardImplementation implementation)
    {
        this(implementation, new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider()));
    }

    public SimulatorOpenPGPSmartCardBackend(OpenPGPSmartCardImplementation implementation, JcaPGPKeyConverter keyConverter)
    {
        super(implementation, keyConverter);
    }

    @Override
    public String getName()
    {
        return "Simulator";
    }

    public SimulatorOpenPGPSmartCardBackend addSmartCard(SimulatorOpenPGPSmartCard card)
    {
        this.smartCards.add(card);
        return this;
    }

    @Override
    public List<SimulatorOpenPGPSmartCard> listSmartCards()
    {
        return smartCards;
    }

    PGPKeyPair generateKeyPair(SupportedAlgorithms.Algorithm algorithm,
                               int keyVersion,
                               int publicKeyAlgorithmTag,
                               Date creationTime,
                               boolean subkey)
            throws PGPException
    {
        PGPKeyPairGenerator kpGen = implementation.implementation.pgpKeyPairGeneratorProvider()
                .get(keyVersion, creationTime);

        PGPKeyPair kp;
        if (algorithm instanceof SupportedAlgorithms.RSA)
        {
            SupportedAlgorithms.RSA rsa = (SupportedAlgorithms.RSA)algorithm;
            kp = kpGen.generateRsaKeyPair(rsa.keySize);
        }
        else if (algorithm instanceof SupportedAlgorithms.EC)
        {
            SupportedAlgorithms.EC ec = (SupportedAlgorithms.EC)algorithm;
            switch (publicKeyAlgorithmTag)
            {
                case PublicKeyAlgorithmTags.ECDH:
                    kp = kpGen.generateECDHKeyPair(ec.curve);
                    break;

                case PublicKeyAlgorithmTags.ECDSA:
                    kp = kpGen.generateECDSAKeyPair(ec.curve);
                    break;

                case PublicKeyAlgorithmTags.EDDSA_LEGACY:
                    kp = kpGen.generateLegacyEd25519KeyPair();
                    break;

                case PublicKeyAlgorithmTags.X25519:
                    kp = kpGen.generateX25519KeyPair();
                    break;

                case PublicKeyAlgorithmTags.X448:
                    kp = kpGen.generateX448KeyPair();
                    break;

                case PublicKeyAlgorithmTags.Ed25519:
                    kp = kpGen.generateEd25519KeyPair();
                    break;

                case PublicKeyAlgorithmTags.Ed448:
                    kp = kpGen.generateEd448KeyPair();
                    break;

                default:
                    throw new IllegalArgumentException("unknown public key algorithm");
            }
        }
        else
        {
            throw new PGPException("unknown algorithm: " + algorithm);
        }

        if (subkey)
        {
            return kp.asSubkey(implementation.implementation.keyFingerPrintCalculator());
        }
        return kp;
    }

    OpenPGPSmartCardImplementation getImplementation()
    {
        return implementation;
    }
}
