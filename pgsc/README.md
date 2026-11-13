# OpenPGP Smart Card Support

This module contains code extending Bouncy Castle's OpenPGP API
with support for hardware security devices, such as OpenPGP Smart Cards.

## Usage
At the heart of the Smart Card API is the `OpenPGPSmartCardManager`.
It can manage one or more `OpenPGPSmartCardBackend`s.
Each backend implements support for a certain type of `OpenPGPSmartCard`.

One available implementation is the `YubikeyOpenPGPSmartCardBackend`, which implements support for Yubico's Yubikey
hardware tokens.

For testing purposes, there is the `SimulatorOpenPGPSmartCardBackend`, which emulates hardware support through OpenPGP
software keys.

### Set up
The basic setup looks as follows:

```java
OpenPGPApi openPGPApi = new BcOpenPGPApi(); // ...or JcaOpenPGPApi();
OpenPGPSmartCardManager smartCardManager = new OpenPGPSmartCardManager();

// Set up smart card backends
YubikeyOpenPGPSmartCardBackend ykBackend = YubikeyOpenPGPSmartCardBackend.createInstance();
ykBackend.addAllowedCardSerial(12345678); // Add your device serial number to the allow-list.
// Alternatively, disable the allow-list to allow all available devices to be used:
// ykBackend.setEnableAllowList(false);
```

### Manage Smart Cards
The `OpenPGPSmartCardManager` can enumerate all available (allow-listed) smart cards:

```java
List<OpenPGPSmartCard> cards = smartCardManager.listSmartCards();

// or you can search by serial number:
OpenPGPSmartCard card = smartCardManager.findSmartCard(12345678);
```

### Change key PINs
You can change the cards user PIN by providing both the old and new PIN with a callback, e.g.:

```java
OpenPGPSmartCard card = ...
CardPinProvider oldPinProvider = k -> "123456".toCharArray();
CardPinProvider newPinProvider = k -> "676767".toCharArray();

card = changeUserPIN(oldPinProvider, newPinProvider);
```

Similarly, you can also change the cards admin PIN.

### Key Upload
You can either upload an existing `OpenPGPSecretKey` to the card, or generate one on the device itself.
The OpenPGP Smart Card Specification defines 3 different 'KEYREF' values that refer to keys used for different purposes:
* `OpenPGPHardwareKey.KEY_REF_SIGNATURE` refers to keys used to generate document signatures
* `OpenPGPHardwareKey.KEY_REF_DECRYPTION` refers to keys that can decrypt messages
* `OpenPGPHardwareKey.KEY_REF_AUTHENTICATION` refers to authentication keys

In order to upload a key to the card, you need to unlock the `OpenPGPSecretKey` and then call the respective
method on the `OpenPGPSmartCard`.

In this example, we upload a signing key to the card:

```java
OpenPGPKey key; // retrieve key, e.g. by generating it or parsing an existing key
OpenPGPSmartCard card = smartCardManager.findSmartCard(12345678); // get your card

OpenPGPKey.OpenPGPSecretKey signingKey = key.getSecretKey(key.getSigningKeys().get(0));
// unlock the signing key, pass in passphrase if required
OpenPGPKey.OpenPGPPrivateKey privSigningKey = signingKey.unlock(keyPassphrase);
card.uploadSigningKey(privSigningKey, cardAdminPin);
```

Uploading decryption / authentication keys works analogous.

The implementation automatically checks key/algorithm compatibility.
Bouncy Castle's Smart Card API supports uploading both OpenPGP v4 and OpenPGP v6 keys.

Uploading a key this way leaves the software-key intact.
It is advisable to strip the secret key material from the software key in order to gain the benefits
of hardware-backed secret keys:

```java
OpenPGPImplementation implementation = new BcOpenPGPImplementation(); // or JcaOpenPGPImplementation()
ExternalOpenPGPKeyUtils keyUtils = new ExternalOpenPGPKeyUtils(implementation);
OpenPGPKey key = ...; // "full" software key
OpenPGPKey fullyStrippedKey = keyUtils.toExternalKey(key); // strip all component keys secret key material

// in order to strip only a certain component keys secret key material:
KeyIdentifier keyIdentifier = key.getSigningKeys().get(0).getKeyIdentifier();
OpenPGPKey partiallyStrippedKey = keyUtils.toExternalKey(key, keyIdentifier);
```

Note: Uploading a key to a card and stripping secret key material from a software key are two distinct operations.

### On-Device Key Generation
Most smart cards can be prompted to generate certain keys on the device itself.
That way, sensitive private key information never leaves the card. Only the public key material is accessible.

Cards advertise, what key types can be generated via the supported algorithms mechanic.
The workflow of generating a key on the card itself is therefore the following:
* Query for supported algorithms
* Select a supported algorithm type for the desired key slot
* Prompt the card to generate that key type

```java
OpenPGPCard card = ...;
SupportedAlgorithms supportedAlgorithms = card.getSupportedAlgorithms()
        .signingKey(); // or .decryptionKey() / .authenticationKey()

SupportedAlgorithms.Algorithm algorithm = supportedAlgorithms.getAlgorithms()
        .get(0); // Find an appropriate item of you choice, e.g. by filtering the list by algorithm ID

boolean isSubkey = false; // here we generate a primary key, set to true if you want to generate a subkey instead.
PGPPublicKey publicKey = card.generateKey(
        algorithm,
        4, // OpenPGP key version (4, 6)
        PublicKeyAlgorithmTags.RSA_GENERAL, // alg-id matching the selected algorithm type
        isSubkey,
        k -> "12345678".toCharArray());

// Create an external secret key from the public key material.
PGPSecretKey externalKey = ExternalOpenPGPKeyUtils.toExternalKey(publicKey, null);
```
Note: The generated key is a bare component key without any user-ids, subkeys etc., so you might need to bind its
components manually to form an OpenPGP certificate.

**TODO**: Implement higher-level key generation API.

### Signing
To make use of OpenPGP keys on Smart Cards, you need access to an `OpenPGPKey` object that
contains `OpenPGPSecretKey` stubs for the hardware-backed component keys.
See `ExternalOpenPGPKeyUtils` on how to obtain a stubbed key.

The process of signing with a hardware-backed key is pretty much analogous to signing with software keys.
One difference is, that you need to register the `OpenPGPSmartCardManager` as a custom signature factory.

```java
OpenPGPApi openPGPApi = ...;
OpenPGPSmartCardManager smartCardManager; // See section "Set Up"

OpenPGPKey stubbedKey = ...; // See ExternalOpenPGPKeyUtils or section "Key Upload"
KeyPassphraseProvider userPinProvider = ...; // Callback to retrieve the cards USER PIN

OutputStream out = ...; // wherever you want to emit the signed message to
OpenPGPMessageOutputStream mOut = openPGPApi.signAndOrEncryptMessage()
        .addCustomPGPContentSignerBuilderProviderFactory(manager) // first add the smart card manager
        .addSigningKey(stubbedKey, userPinProvider) // then add one or more stubbed signing keys
        .open(out);

mOut.write(plaintext); // pass in the plaintext
mOut.close();
```

### Decryption
To use a hardware-backed key for asymmetric message decryption, you need to register the `OpenPGPSmartCardManager` as
a custom decryptor factory.
Similar to message signing, you need to provide the stub of the hardware-backed decryption secret key during
decryption stream setup.

```java
OpenPGPApi openPGPApi = ...;
OpenPGPSmartCardManager smartCardManager; // See section "Set Up"

OpenPGPKey stubbedKey = ...; // See ExternalOpenPGPKeyUtils or section "Key Upload"
KeyPassphraseProvider userPinProvider = ...; // Callback to retrieve the cards USER PIN

InputStream ciphertextIn = ...; // the message ciphertext
OutputStream out = ...;
OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
        .addPublicKeyDataDecryptorFactoryProvider(manager) // add the smart card manager as decryptor factory
        .addDecryptionKey(externalKey, userPinProvider) // add key as decryption key
        .process(bIn);

Streams.pipeAll(mIn, out); // process all the ciphertext
mIn.close();
```

## Extend With Custom Backends

If you want to add support for a custom set of hardware tokens, you need to inherit from two classes:

* `OpenPGPSmartCardBackend` is in duty of discovering your hardware tokens.
   Its most important method is the `listSmartCards()` method, which emits all cards that your user should 
   be able to access.
* `OpenPGPSmartCard` represents an abstraction of your hardware token.
  You need to implement the `sign()` and `decrypt()` methods, which perform the low-level public key crypto operations.

Your card may perform logic different from the generic implementation (e.g. support for custom PGP variants).
In this case, you can make apply custom logic on a deeper level by overriding `OpenPGPSmartCardBackend`s
`providePublicKeyDataDecryptorFactory()` or `providePGPContentSignerBuilderProvider()` methods.
