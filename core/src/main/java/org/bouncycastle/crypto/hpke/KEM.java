package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;


/**
 * base class for HPKE KEM
 */
public abstract class KEM
{
    // Key Generation
    protected abstract AsymmetricCipherKeyPair GeneratePrivateKey();
    protected abstract AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm);

    // Encapsulates a shared secret for a given public key and returns the encapsulated key and shared secret.
    protected abstract byte[][] Encap(AsymmetricKeyParameter recipientPublicKey);
    protected abstract byte[][] Encap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpE);
    protected abstract byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS);

    // Decapsulates the given encapsulated key using the recipient's key pair and returns the shared secret.
    protected abstract byte[] Decap(byte[] encapsulatedKey, AsymmetricCipherKeyPair recipientKeyPair);
    protected abstract byte[] AuthDecap(byte[] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS);

    // Serialization
    protected abstract byte[] SerializePublicKey(AsymmetricKeyParameter publicKey);
    protected abstract byte[] SerializePrivateKey(AsymmetricKeyParameter key);

    // Deserialization
    protected abstract AsymmetricKeyParameter DeserializePublicKey(byte[] encodedPublicKey);
    protected abstract AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded);

    protected abstract int getEncryptionSize();

}
