package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;


/**
 * base class for HPKE KEM
 */
public abstract class KEM
{
    // Key Generation
    abstract AsymmetricCipherKeyPair GeneratePrivateKey();
    abstract AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm);

    // Encapsulates a shared secret for a given public key and returns the encapsulated key and shared secret.
    abstract byte[][] Encap(AsymmetricKeyParameter recipientPublicKey);
    abstract byte[][] Encap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpE);
    abstract byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS);

    // Decapsulates the given encapsulated key using the recipient's key pair and returns the shared secret.
    abstract byte[] Decap(byte[] encapsulatedKey, AsymmetricCipherKeyPair recipientKeyPair);
    abstract byte[] AuthDecap(byte[] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS);

    // Serialization
    abstract byte[] SerializePublicKey(AsymmetricKeyParameter publicKey);
    abstract byte[] SerializePrivateKey(AsymmetricKeyParameter key);

    // Deserialization
    abstract AsymmetricKeyParameter DeserializePublicKey(byte[] encodedPublicKey);
    abstract AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded);

    abstract int getEncryptionSize();

}