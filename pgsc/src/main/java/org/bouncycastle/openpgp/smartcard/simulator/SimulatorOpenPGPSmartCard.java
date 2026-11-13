package org.bouncycastle.openpgp.smartcard.simulator;

import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.agreement.ECDHRawAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.smartcard.OpenPGPHardwareKey;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.card.SupportedAlgorithms;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.bouncycastle.bcpg.PublicKeyAlgorithmTags.ECDH;
import static org.bouncycastle.bcpg.PublicKeyAlgorithmTags.ECDSA;
import static org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EDDSA_LEGACY;
import static org.bouncycastle.bcpg.PublicKeyAlgorithmTags.RSA_GENERAL;
import static org.bouncycastle.openpgp.smartcard.OpenPGPHardwareKey.KEY_REF_AUTHENTICATION;
import static org.bouncycastle.openpgp.smartcard.OpenPGPHardwareKey.KEY_REF_DECRYPTION;
import static org.bouncycastle.openpgp.smartcard.OpenPGPHardwareKey.KEY_REF_SIGNATURE;

/**
 * In-memory stand-in for an OpenPGP smart card, backed by ordinary software keys.
 * <p>
 * <b>Test and development use only.</b> Unlike a real card this offers no isolation whatsoever: the
 * uploaded {@link OpenPGPKey.OpenPGPSecretKey secret keys} are held in the heap of the calling process
 * and {@link #getSoftwareKey} hands the private key straight back. It exists so that the smart-card API
 * can be exercised without hardware; never use it as a substitute for a token in production.
 */
public class SimulatorOpenPGPSmartCard
        extends OpenPGPSmartCard
{
    public static final char[] DEFAULT_USER_PIN = "123456".toCharArray();
    public static final char[] DEFAULT_ADMIN_PIN = "12345678".toCharArray();
    private char[] userPIN = Arrays.clone(DEFAULT_USER_PIN); // only for test purposes
    private char[] adminPIN = Arrays.clone(DEFAULT_ADMIN_PIN);

    private final Integer serialNumber;
    private final Map<Byte, PGPKeyPair> privateKeys = new HashMap<>();
    private final Map<Byte, OpenPGPHardwareKey> hardwareKeys = new HashMap<>();
    private final BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();

    public SimulatorOpenPGPSmartCard(SimulatorOpenPGPSmartCardBackend backend,
                                     Integer serialNumber)
    {
        super(backend);
        this.serialNumber = serialNumber;
    }

    public static SimulatorOpenPGPSmartCard createSimulatedCardFrom(SimulatorOpenPGPSmartCardBackend backend,
                                                                    OpenPGPKey softwareKey)
            throws PGPException, CardException
    {
        // the serial only has to be unique among simulated cards; it is not security relevant, but
        // take it from the registrar's RNG rather than introducing a java.util.Random into the tree.
        return createSimulatedCardFrom(backend,
                Integers.valueOf(CryptoServicesRegistrar.getSecureRandom().nextInt()), softwareKey);
    }

    public static SimulatorOpenPGPSmartCard createSimulatedCardFrom(SimulatorOpenPGPSmartCardBackend backend,
                                                                    Integer serialNumber,
                                                                    OpenPGPKey softwareKey)
            throws PGPException, CardException
    {
        SimulatorOpenPGPSmartCard card = new SimulatorOpenPGPSmartCard(backend, serialNumber);

        List<OpenPGPCertificate.OpenPGPComponentKey> signingKeys = softwareKey.getSigningKeys();
        if (!signingKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = softwareKey.getSecretKey(signingKeys.get(0));
            card.uploadSigningKey(secretKey.unlock(), key -> card.adminPIN);
        }

        List<OpenPGPCertificate.OpenPGPComponentKey> decryptionKeys = softwareKey.getEncryptionKeys();
        if (!decryptionKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = softwareKey.getSecretKey(decryptionKeys.get(0));
            card.uploadDecryptionKey(secretKey.unlock(), key -> card.adminPIN);
        }

        List<OpenPGPCertificate.OpenPGPComponentKey> authenticationKeys =
                softwareKey.getComponentKeysWithFlag(new Date(), KeyFlags.AUTHENTICATION);
        if (!authenticationKeys.isEmpty())
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = softwareKey.getSecretKey(authenticationKeys.get(0));
            card.uploadAuthenticationKey(secretKey.unlock(), key -> card.adminPIN);
        }

        return card;
    }

    private static OpenPGPHardwareKey asHardwareKey(OpenPGPSmartCard card,
                                                    OpenPGPKey.OpenPGPSecretKey key,
                                                    byte keyRef,
                                                    byte state)
    {
        return new OpenPGPHardwareKey(
                card,
                keyRef,
                state,
                card.getBackend().toStoredFingerprint(key.getPGPPublicKey()),
                key.getPGPPublicKey().getCreationTime());
    }

    @Override
    public SimulatorOpenPGPSmartCardBackend getBackend()
    {
        return (SimulatorOpenPGPSmartCardBackend) super.getBackend();
    }

    @Override
    public Integer getSerialNumber()
    {
        return serialNumber;
    }

    @Override
    public String getVersion()
    {
        return "1.0";
    }

    @Override
    public SupportedAlgorithms getSupportedAlgorithms()
    {
        List<SupportedAlgorithms.Algorithm> supported = new ArrayList<>();
        // Signature
        supported.add(new SupportedAlgorithms.RSA(KEY_REF_SIGNATURE, RSA_GENERAL, 2048));
        supported.add(new SupportedAlgorithms.RSA(KEY_REF_SIGNATURE, RSA_GENERAL, 3072));
        supported.add(new SupportedAlgorithms.RSA(KEY_REF_SIGNATURE, RSA_GENERAL, 4096));
        supported.add(new SupportedAlgorithms.EC(KEY_REF_SIGNATURE, ECDSA, X9ObjectIdentifiers.prime256v1)); // prime256v1 1.2.840.10045.3.1.7
        supported.add(new SupportedAlgorithms.EC(KEY_REF_SIGNATURE, ECDSA, SECObjectIdentifiers.secp384r1)); // secp384r1 1.3.132.0.34
        supported.add(new SupportedAlgorithms.EC(KEY_REF_SIGNATURE, ECDSA, SECObjectIdentifiers.secp521r1)); // secp384r1 1.3.132.0.35
        supported.add(new SupportedAlgorithms.EC(KEY_REF_SIGNATURE, ECDSA, SECObjectIdentifiers.secp256k1)); // secp256k1 1.3.132.0.10
        supported.add(new SupportedAlgorithms.EC(KEY_REF_SIGNATURE, ECDSA, TeleTrusTObjectIdentifiers.brainpoolP256r1)); // brainpoolP256r1 1.3.36.3.3.2.8.1.1.7
        supported.add(new SupportedAlgorithms.EC(KEY_REF_SIGNATURE, ECDSA, TeleTrusTObjectIdentifiers.brainpoolP384r1)); // brainpoolP384r1 1.3.36.3.3.2.8.1.1.11
        supported.add(new SupportedAlgorithms.EC(KEY_REF_SIGNATURE, ECDSA, TeleTrusTObjectIdentifiers.brainpoolP512r1)); // brainpoolP512r1 1.3.36.3.3.2.8.1.1.13
        supported.add(new SupportedAlgorithms.EC(KEY_REF_SIGNATURE, EDDSA_LEGACY, GNUObjectIdentifiers.Ed25519)); // ed25519 1.3.6.1.4.1.11591.15.1

        // Encryption
        supported.add(new SupportedAlgorithms.RSA(KEY_REF_DECRYPTION, RSA_GENERAL, 2048));
        supported.add(new SupportedAlgorithms.RSA(KEY_REF_DECRYPTION, RSA_GENERAL, 3072));
        supported.add(new SupportedAlgorithms.RSA(KEY_REF_DECRYPTION, RSA_GENERAL, 4096));
        supported.add(new SupportedAlgorithms.EC(KEY_REF_DECRYPTION, ECDSA, X9ObjectIdentifiers.prime256v1)); // prime256v1/secp256r1 1.2.840.10045.3.1.7
        supported.add(new SupportedAlgorithms.EC(KEY_REF_DECRYPTION, ECDSA, SECObjectIdentifiers.secp384r1)); // secp384r1 1.3.132.0.34
        supported.add(new SupportedAlgorithms.EC(KEY_REF_DECRYPTION, ECDSA, SECObjectIdentifiers.secp521r1)); // secp384r1 1.3.132.0.35
        supported.add(new SupportedAlgorithms.EC(KEY_REF_DECRYPTION, ECDSA, SECObjectIdentifiers.secp256k1)); // secp256k1 1.3.132.0.10
        supported.add(new SupportedAlgorithms.EC(KEY_REF_DECRYPTION, ECDSA, TeleTrusTObjectIdentifiers.brainpoolP256r1)); // brainpoolP256r1 1.3.36.3.3.2.8.1.1.7
        supported.add(new SupportedAlgorithms.EC(KEY_REF_DECRYPTION, ECDSA, TeleTrusTObjectIdentifiers.brainpoolP384r1)); // brainpoolP384r1 1.3.36.3.3.2.8.1.1.11
        supported.add(new SupportedAlgorithms.EC(KEY_REF_DECRYPTION, ECDSA, TeleTrusTObjectIdentifiers.brainpoolP512r1)); // brainpoolP512r1 1.3.36.3.3.2.8.1.1.13
        supported.add(new SupportedAlgorithms.EC(KEY_REF_DECRYPTION, ECDH, CryptlibObjectIdentifiers.curvey25519)); // curve25519 (X25519) 1.3.6.1.4.1.3029.1.5.1

        // Authentication
        supported.add(new SupportedAlgorithms.RSA(KEY_REF_AUTHENTICATION, RSA_GENERAL, 2048));
        supported.add(new SupportedAlgorithms.RSA(KEY_REF_AUTHENTICATION, RSA_GENERAL, 3072));
        supported.add(new SupportedAlgorithms.RSA(KEY_REF_AUTHENTICATION, RSA_GENERAL, 4096));
        supported.add(new SupportedAlgorithms.EC(KEY_REF_AUTHENTICATION, ECDSA, X9ObjectIdentifiers.prime256v1)); // prime256v1 1.2.840.10045.3.1.7
        supported.add(new SupportedAlgorithms.EC(KEY_REF_AUTHENTICATION, ECDSA, SECObjectIdentifiers.secp384r1)); // secp384r1 1.3.132.0.34
        supported.add(new SupportedAlgorithms.EC(KEY_REF_AUTHENTICATION, ECDSA, SECObjectIdentifiers.secp521r1)); // secp384r1 1.3.132.0.35
        supported.add(new SupportedAlgorithms.EC(KEY_REF_AUTHENTICATION, ECDSA, SECObjectIdentifiers.secp256k1)); // secp256k1 1.3.132.0.10
        supported.add(new SupportedAlgorithms.EC(KEY_REF_AUTHENTICATION, ECDSA, TeleTrusTObjectIdentifiers.brainpoolP256r1)); // brainpoolP256r1 1.3.36.3.3.2.8.1.1.7
        supported.add(new SupportedAlgorithms.EC(KEY_REF_AUTHENTICATION, ECDSA, TeleTrusTObjectIdentifiers.brainpoolP384r1)); // brainpoolP384r1 1.3.36.3.3.2.8.1.1.11
        supported.add(new SupportedAlgorithms.EC(KEY_REF_AUTHENTICATION, ECDSA, TeleTrusTObjectIdentifiers.brainpoolP512r1)); // brainpoolP512r1 1.3.36.3.3.2.8.1.1.13
        supported.add(new SupportedAlgorithms.EC(KEY_REF_AUTHENTICATION, EDDSA_LEGACY, GNUObjectIdentifiers.Ed25519)); // ed25519 1.3.6.1.4.1.11591.15.1

        return new SupportedAlgorithms(supported);
    }

    @Override
    public OpenPGPHardwareKey getKeyByKeyRef(byte keyRef)
    {
        return hardwareKeys.get(keyRef);
    }

    @Override
    public List<OpenPGPHardwareKey> getKeys()
    {
        return new ArrayList<>(hardwareKeys.values());
    }

    @Override
    public boolean checkUserPIN(CardPinProvider userPinProvider)
            throws CardException
    {
        return Arrays.areEqual(userPIN, userPinProvider.providePIN(this));
    }

    @Override
    public boolean checkAdminPIN(CardPinProvider adminPinProvider)
            throws CardException
    {
        return Arrays.areEqual(adminPIN, adminPinProvider.providePIN(this));
    }

    @Override
    public OpenPGPSmartCard changeUserPIN(CardPinProvider oldPinProvider, CardPinProvider newPinProvider)
            throws CardException
    {
        char[] oldPIN = oldPinProvider.providePIN(this);
        char[] newPIN = newPinProvider.providePIN(this);
        if (Arrays.areEqual(userPIN, oldPIN))
        {
            userPIN = Arrays.clone(newPIN);
        }
        else
        {
            throw new CardException("Invalid simulator user PIN");
        }
        return this;
    }

    @Override
    public OpenPGPSmartCard changeAdminPIN(CardPinProvider oldPinProvider, CardPinProvider newPinProvider)
            throws CardException
    {
        char[] oldPIN = oldPinProvider.providePIN(this);
        char[] newPIN = newPinProvider.providePIN(this);
        if (Arrays.areEqual(adminPIN, oldPIN))
        {
            adminPIN = Arrays.clone(newPIN);
        }
        else
        {
            throw new CardException("Invalid simulator admin PIN");
        }
        return this;
    }

    @Override
    public SimulatorOpenPGPSmartCard reset()
    {
        hardwareKeys.clear();
        privateKeys.clear();
        adminPIN = Arrays.clone(DEFAULT_ADMIN_PIN);
        userPIN = Arrays.clone(DEFAULT_USER_PIN);
        return this;
    }

    /**
     * {@inheritDoc}
     * <p>
     * The simulator enforces no admin PIN, so <code>adminPin</code> is ignored.
     */
    @Override
    public SimulatorOpenPGPSmartCard uploadKey(byte keyRef,
                                               OpenPGPKey.OpenPGPPrivateKey key,
                                               char[] adminPin)
            throws CardException
    {
        if (!Arrays.areEqual(this.adminPIN, adminPin))
        {
            throw new CardException("Invalid simulator admin PIN");
        }
        privateKeys.put(keyRef, key.getKeyPair());
        hardwareKeys.put(keyRef, asHardwareKey(this, key.getSecretKey(), keyRef, OpenPGPHardwareKey.STATE_IMPORTED));
        return this;
    }

    @Override
    public PGPPublicKey generateKey(
            SupportedAlgorithms.Algorithm algorithm,
            int keyVersion,
            int publicKeyAlgorithmTag,
            boolean subkey,
            CardPinProvider adminPinProvider)
            throws CardException
    {
        OpenPGPImplementation implementation = getBackend().getImplementation().implementation;
        char[] pin = adminPinProvider.providePIN(this);
        if (!Arrays.areEqual(pin, adminPIN))
        {
            throw new CardException("Invalid simulator admin PIN");
        }

        Date now = new Date();
        PGPKeyPair keyPair;
        try
        {
            keyPair = getBackend().generateKeyPair(algorithm, keyVersion, publicKeyAlgorithmTag, now, subkey);
        }
        catch (PGPException e)
        {
            throw new CardException("Cannot generate key.");
        }

        OpenPGPCertificate.OpenPGPComponentKey componentKey = subkey ?
                new OpenPGPCertificate.OpenPGPSubkey(keyPair.getPublicKey(), null) :
                new OpenPGPCertificate.OpenPGPPrimaryKey(keyPair.getPublicKey(), null);
        PGPSecretKey extSecKey = new PGPSecretKey(
                new SecretKeyPacket(keyPair.getPublicKey().getPublicKeyPacket(), null),
                keyPair.getPublicKey());

        privateKeys.put(algorithm.keyRef, keyPair);
        hardwareKeys.put(algorithm.keyRef,
                asHardwareKey(
                        this,
                        new OpenPGPKey.OpenPGPSecretKey(componentKey, extSecKey, null),
                        algorithm.keyRef,
                        OpenPGPHardwareKey.STATE_GENERATED));
        return keyPair.getPublicKey();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns null if the given slot is empty, matching the hardware implementations.
     */
    @Override
    public PGPPublicKey reconstructPGPPublicKey(byte keyRef)
    {
        PGPKeyPair softwareKey = privateKeys.get(keyRef);
        if (softwareKey == null)
        {
            return null;
        }
        return softwareKey.getPublicKey();
    }

    private PGPPrivateKey getSoftwareKey(OpenPGPCertificate.OpenPGPComponentKey key)
            throws PGPException
    {
        for (Iterator<PGPKeyPair> it = privateKeys.values().iterator(); it.hasNext();)
        {
            PGPKeyPair k = it.next();
            if (k.getKeyIdentifier().matchesExplicit(key.getKeyIdentifier()))
            {
                return k.getPrivateKey();
            }
        }
        return null;
    }

    @Override
    public String getCardType()
    {
        return "SimulatorSmartCard";
    }

    @Override
    public byte[] sign(byte[] data,
                       OpenPGPHardwareKey key,
                       OpenPGPKey.OpenPGPSecretKey stubKey,
                       KeyPassphraseProvider userPinProvider)
            throws KeyPassphraseException
    {
        if (!Arrays.areEqual(userPIN, userPinProvider.getKeyPassword(stubKey)))
        {
            throw new KeyPassphraseException(stubKey, new CardException("Invalid user PIN provided."));
        }
        try
        {
            PGPPrivateKey pgpPrivateKey = getSoftwareKey(stubKey);
            if (pgpPrivateKey == null)
            {
                throw new CardException("No signing key.");
            }
            AsymmetricKeyParameter privateKey = keyConverter.getPrivateKey(pgpPrivateKey);

            switch (stubKey.getAlgorithm())
            {
                case RSA_GENERAL:
                case PublicKeyAlgorithmTags.RSA_SIGN:
                    AsymmetricBlockCipher rsaEngine = new PKCS1Encoding(new RSABlindedEngine());
                    rsaEngine.init(true, privateKey);
                    return rsaEngine.processBlock(data, 0, data.length);

                case PublicKeyAlgorithmTags.DSA:
                    DSASigner dsaEngine = new DSASigner();
                    dsaEngine.init(true, privateKey);
                    BigInteger[] dsaSig = dsaEngine.generateSignature(data);
                    return StandardDSAEncoding.INSTANCE.encode(dsaEngine.getOrder(), dsaSig[0], dsaSig[1]);

                case ECDSA:
                    ECDSASigner ecdsaSigner = new ECDSASigner();
                    ecdsaSigner.init(true, privateKey);
                    BigInteger[] ecdsaSig = ecdsaSigner.generateSignature(data);
                    return StandardDSAEncoding.INSTANCE.encode(ecdsaSigner.getOrder(), ecdsaSig[0], ecdsaSig[1]);

                case EDDSA_LEGACY:
                case PublicKeyAlgorithmTags.Ed25519:
                case PublicKeyAlgorithmTags.Ed448:
                    Signer edSigner;
                    if (stubKey.getAlgorithm() == PublicKeyAlgorithmTags.Ed25519 ||
                            (stubKey.getAlgorithm() == EDDSA_LEGACY && privateKey instanceof Ed25519PrivateKeyParameters))
                    {
                        edSigner = new Ed25519Signer();
                    }
                    else
                    {
                        edSigner = new Ed448Signer(new byte[0]);
                    }
                    edSigner.init(true, privateKey);
                    edSigner.update(data, 0, data.length);
                    return edSigner.generateSignature();

                default:
                    throw new PGPException("Unknown public key algorithm: " + stubKey.getAlgorithm());
            }
        }
        catch (PGPException | IOException | CryptoException e)
        {
            throw new PGPRuntimeOperationException("Unable to create signature: " + e.getMessage(), e);
        }
        catch (CardException e)
        {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] message,
                          OpenPGPHardwareKey openPGPHardwareKey,
                          OpenPGPKey.OpenPGPSecretKey stubKey,
                          KeyPassphraseProvider userPinProvider)
    {
        try
        {
            PGPPrivateKey pgpPrivateKey = getSoftwareKey(stubKey);
            if (pgpPrivateKey == null)
            {
                throw new PGPException("Missing decryption private key.");
            }
            AsymmetricKeyParameter privateKey = keyConverter.getPrivateKey(pgpPrivateKey);
            int keyAlgorithm = stubKey.getAlgorithm();
            switch (keyAlgorithm)
            {
                case RSA_GENERAL:
                case PublicKeyAlgorithmTags.RSA_ENCRYPT:
                    BufferedAsymmetricBlockCipher c1 = new BufferedAsymmetricBlockCipher(new PKCS1Encoding(new RSABlindedEngine()));
                    c1.init(false, privateKey);
                    c1.processBytes(message, 0, message.length);
                    return c1.doFinal();

                case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
                case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                    throw new PGPException("Not implemented.");

                default:
                    throw new PGPException("Unknown public key algorithm: " + keyAlgorithm);
            }
        }
        catch (PGPException | InvalidCipherTextException e)
        {
            throw new PGPRuntimeOperationException("Unable to decrypt: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(PublicKey publicKey,
                          OpenPGPHardwareKey openPGPHardwareKey,
                          OpenPGPKey.OpenPGPSecretKey stubKey,
                          KeyPassphraseProvider userPinProvider)
    {
        try
        {
            PGPPrivateKey pgpPrivateKey = getSoftwareKey(stubKey);
            if (pgpPrivateKey == null)
            {
                throw new PGPException("Missing decryption private key.");
            }
            AsymmetricKeyParameter privateKey = keyConverter.getPrivateKey(pgpPrivateKey);

            RawAgreement agreement;
            AsymmetricKeyParameter pubKey;

            pubKey = PublicKeyFactory.createKey(publicKey.getEncoded());
            switch (stubKey.getAlgorithm())
            {
                case ECDH:
                    if (privateKey instanceof X25519PrivateKeyParameters)
                    {
                        agreement = new X25519Agreement();
                    }
                    else if (privateKey instanceof X448PrivateKeyParameters)
                    {
                        agreement = new X448Agreement();
                    }
                    else
                    {
                        agreement = new ECDHRawAgreement();
                    }
                    break;

                case PublicKeyAlgorithmTags.X25519:
                    agreement = new X25519Agreement();
                    break;

                case PublicKeyAlgorithmTags.X448:
                    agreement = new X448Agreement();
                    break;

                default:
                    throw new PGPException("Unknown public key algorithm: " + stubKey.getAlgorithm());
            }

            agreement.init(privateKey);
            byte[] secret = new byte[agreement.getAgreementSize()];
            agreement.calculateAgreement(pubKey, secret, 0);
            return secret;
        }
        catch (IOException | PGPException e)
        {
            throw new PGPRuntimeOperationException("Unable to decrypt: " + e.getMessage(), e);
        }
    }
}
