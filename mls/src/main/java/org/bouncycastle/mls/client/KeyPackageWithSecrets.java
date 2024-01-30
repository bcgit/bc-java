package org.bouncycastle.mls.client;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.codec.KeyPackage;

public class KeyPackageWithSecrets
{
    AsymmetricCipherKeyPair initKeyPair; // HPKE key pair
    AsymmetricCipherKeyPair encryptionKeyPair; // HPKE key pair
    AsymmetricCipherKeyPair signatureKeyPair; // sig key pair
    KeyPackage keyPackage;

    public KeyPackageWithSecrets(AsymmetricCipherKeyPair initKeyPair, AsymmetricCipherKeyPair encryptionKeyPair, AsymmetricCipherKeyPair signatureKeyPair, KeyPackage keyPackage)
    {
        this.initKeyPair = initKeyPair;
        this.encryptionKeyPair = encryptionKeyPair;
        this.signatureKeyPair = signatureKeyPair;
        this.keyPackage = keyPackage;
    }
}