package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public abstract class KEM {
    // Generates a key pair.
    abstract AsymmetricCipherKeyPair GeneratePrivateKey();

    // Generates a key pair derived from input keying material (IKM).
    abstract AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm);

    // Encapsulates a shared secret for a given public key and returns the encapsulated key and shared secret.
    abstract byte[][] Encap(AsymmetricKeyParameter recipientPublicKey);
    abstract byte[][] Encap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpE);
    abstract byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS);

    // Decapsulates the given encapsulated key using the recipient's key pair and returns the shared secret.
    abstract byte[] Decap(byte[] encapsulatedKey, AsymmetricCipherKeyPair recipientKeyPair);
    abstract byte[] AuthDecap(byte[] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS);

    // Serializes a key to a byte array.
    abstract byte[] SerializePublicKey(AsymmetricKeyParameter publicKey);
    abstract byte[] SerializePrivateKey(AsymmetricKeyParameter key);

    // Deserializes a public key from a byte array.
    abstract AsymmetricKeyParameter DeserializePublicKey(byte[] encodedPublicKey);
    // Deserializes a key pair from a byte array.
    abstract AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded);
}