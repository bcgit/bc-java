package org.bouncycastle.crypto.test;

import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.SecureRandomProvider;
import org.bouncycastle.crypto.agreement.SM9KeyExchange;
import org.bouncycastle.crypto.engines.SM9Engine;
import org.bouncycastle.crypto.generators.SM9EncMasterKeyPairGenerator;
import org.bouncycastle.crypto.kems.SM9KEMExtractor;
import org.bouncycastle.crypto.kems.SM9KEMGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests of the SM9 encryption key-usage check: a user key declared for one of the KEM and decryption
 * is refused for the other on every use, and within one JVM a user key is held to the first of the two
 * it is used for, recognised by its value rather than by its object, and refused for the other unless
 * {@link Properties#SM9_ALLOW_MULTI_USE} is set.
 */
public class SM9KeyUsageTest
    extends SimpleTest
{
    private static final String USED_FOR_KEM = "SM9 encryption user key has been used for KEM decapsulation"
        + " in this JVM: key-usage separation refuses it for decryption (set org.bouncycastle.sm9.allow_multi_use"
        + " to true to turn the check off)";
    private static final String USED_FOR_DECRYPTION = "SM9 encryption user key has been used for decryption"
        + " in this JVM: key-usage separation refuses it for KEM decapsulation (set"
        + " org.bouncycastle.sm9.allow_multi_use to true to turn the check off)";
    private static final String DECLARED_FOR_KEM =
        "SM9 encryption user key is declared for KEM decapsulation and cannot be used for decryption";
    private static final String DECLARED_FOR_DECRYPTION =
        "SM9 encryption user key is declared for decryption and cannot be used for KEM decapsulation";
    private static final byte HID = SM9EncMasterPrivateKeyParameters.HID;

    private SecureRandom random;
    private SM9EncMasterPrivateKeyParameters master;
    // what collected() allocates, held here so that the allocation is made
    private byte[] garbage;

    public String getName()
    {
        return "SM9KeyUsage";
    }

    public void performTest()
        throws Exception
    {
        // a master key of this run's own, so that none of these keys shares a value with another test's
        random = CryptoServicesRegistrar.getSecureRandom();
        SM9EncMasterKeyPairGenerator kpGen = new SM9EncMasterKeyPairGenerator();
        kpGen.init(new KeyGenerationParameters(random, 256));
        master = (SM9EncMasterPrivateKeyParameters)kpGen.generateKeyPair().getPrivate();

        checkNoRandomSource();
        checkKemFirst();
        checkDecryptionFirst();
        checkSameValueNewObject();
        checkDistinctValues();
        checkMultiUseAllowed();
        checkConcurrentFirstUse();
        checkKeyExchangeUnaffected();
        checkArguments();
        checkDestroyed();
        checkRecordOutlivesRecentKeys();

        checkDeclared();
        checkDeclaredUnderProperty();
        checkDeclaredKeyRecorded();
        checkDeclaredImport();
        checkDeclaredArguments();
        checkUsageReported();
    }

    /**
     * Handing a key over for the KEM or for decryption, and the check made then, draw on no random
     * source, so a process without a default one takes a key as one with a source does, and the check
     * still holds the key to its first use. Run first, so that in a JVM of its own the keys are the first
     * this copy of the library checks.
     */
    private void checkNoRandomSource()
    {
        SM9EncPrivateKeyParameters kemKey = key("Uma", HID);
        SM9EncPrivateKeyParameters decryptionKey = key("Vic", HID);
        // a default source this thread cannot have, and the one there was put back afterwards, as the
        // registrar is shared by the whole JVM
        final Thread caller = Thread.currentThread();
        final boolean specified = CryptoServicesRegistrar.isSecureRandomSpecified();
        final SecureRandom previous = CryptoServicesRegistrar.getSecureRandom();
        try
        {
            CryptoServicesRegistrar.setSecureRandomProvider(new SecureRandomProvider()
            {
                public SecureRandom get()
                {
                    if (Thread.currentThread() == caller)
                    {
                        throw new IllegalStateException("no default source");
                    }
                    return previous;
                }
            });
            new SM9KEMExtractor(kemKey, 128);
            new SM9Engine().init(false, decryptionKey);
            try
            {
                new SM9Engine().init(false, kemKey);
                fail("SM9Engine took a key used for the KEM where there was no default source");
            }
            catch (IllegalArgumentException e)
            {
                isTrue(e.getMessage(), USED_FOR_KEM.equals(e.getMessage()));
            }
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(specified ? previous : null);
        }
    }

    /**
     * A key declared for the KEM is refused for decryption on its first use as on later ones, and
     * decapsulates; one declared for decryption is refused for the KEM likewise, and decrypts.
     */
    private void checkDeclared()
        throws Exception
    {
        SM9EncPrivateKeyParameters kemKey = declared("Olivia", SM9EncPrivateKeyParameters.USAGE_KEM);
        decryptionRefused(kemKey, DECLARED_FOR_KEM);
        decapsulate(recipient("Olivia", HID), kemKey);
        decryptionRefused(kemKey, DECLARED_FOR_KEM);

        SM9EncPrivateKeyParameters decryptionKey = declared("Peggy", SM9EncPrivateKeyParameters.USAGE_DECRYPTION);
        kemRefused(decryptionKey, DECLARED_FOR_DECRYPTION);
        decrypt(recipient("Peggy", HID), decryptionKey, SM9Engine.Mode.SM4);
        kemRefused(decryptionKey, DECLARED_FOR_DECRYPTION);
    }

    /**
     * Setting the property does not lift a declared usage.
     */
    private void checkDeclaredUnderProperty()
    {
        Properties.setThreadOverride(Properties.SM9_ALLOW_MULTI_USE, true);
        try
        {
            decryptionRefused(declared("Quentin", SM9EncPrivateKeyParameters.USAGE_KEM), DECLARED_FOR_KEM);
            kemRefused(declared("Quentin", SM9EncPrivateKeyParameters.USAGE_DECRYPTION), DECLARED_FOR_DECRYPTION);
        }
        finally
        {
            Properties.removeThreadOverride(Properties.SM9_ALLOW_MULTI_USE);
        }
    }

    /**
     * A declared key's use is recorded as any other key's is, so an undeclared object of the same key is
     * held to it, and so is an object of it declared for the other use, unless the property is set.
     */
    private void checkDeclaredKeyRecorded()
        throws Exception
    {
        decapsulate(recipient("Rupert", HID), declared("Rupert", SM9EncPrivateKeyParameters.USAGE_KEM));
        decryptionRefused(key("Rupert", HID), USED_FOR_KEM);
        SM9EncPrivateKeyParameters declaredOther = declared("Rupert", SM9EncPrivateKeyParameters.USAGE_DECRYPTION);
        decryptionRefused(declaredOther, USED_FOR_KEM);

        Properties.setThreadOverride(Properties.SM9_ALLOW_MULTI_USE, true);
        try
        {
            decrypt(recipient("Rupert", HID), declaredOther, SM9Engine.Mode.SM4);
        }
        finally
        {
            Properties.removeThreadOverride(Properties.SM9_ALLOW_MULTI_USE);
        }
    }

    /**
     * A key rebuilt from its encoding is declared there as at derivation.
     */
    private void checkDeclaredImport()
        throws Exception
    {
        SM9EncPrivateKeyParameters imported = SM9EncPrivateKeyParameters.fromEncoded(key("Sybil", HID).getEncoded(),
            master.getPublicKeyParameters(), Strings.toByteArray("Sybil"), HID,
            SM9EncPrivateKeyParameters.USAGE_DECRYPTION);
        isTrue("an imported key reports the usage it was declared for",
            imported.getUsage() == SM9EncPrivateKeyParameters.USAGE_DECRYPTION);
        kemRefused(imported, DECLARED_FOR_DECRYPTION);
        decrypt(recipient("Sybil", HID), imported, SM9Engine.Mode.STREAM);
    }

    /**
     * A KEM / decryption key is declared for the KEM, decryption or neither: the key exchange's usage, or
     * a value that is no usage, is refused where the key is derived and where it is imported.
     */
    private void checkDeclaredArguments()
    {
        String message = "usage must be USAGE_UNSPECIFIED, USAGE_KEM or USAGE_DECRYPTION - a key-exchange key"
            + " comes from generateExchangeKey or fromEncodedExchangeKey";
        byte[] identity = Strings.toByteArray("Trent");
        byte[] encoding = key("Trent", HID).getEncoded();
        int[] usages = { SM9EncPrivateKeyParameters.USAGE_KEY_EXCHANGE, 4, -1 };
        for (int i = 0; i != usages.length; i++)
        {
            try
            {
                master.generateUserKey(identity, HID, usages[i]);
                fail("generateUserKey took usage " + usages[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue(e.getMessage(), message.equals(e.getMessage()));
            }
            try
            {
                SM9EncPrivateKeyParameters.fromEncoded(encoding, master.getPublicKeyParameters(), identity, HID,
                    usages[i]);
                fail("fromEncoded took usage " + usages[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue(e.getMessage(), message.equals(e.getMessage()));
            }
        }
    }

    /**
     * getUsage reports the usage a key was derived or imported for, and isExchangeKey agrees with it.
     */
    private void checkUsageReported()
    {
        byte[] identity = Strings.toByteArray("Uma");
        isTrue("an undeclared key", key("Uma", HID).getUsage() == SM9EncPrivateKeyParameters.USAGE_UNSPECIFIED);
        isTrue("a key declared for the KEM",
            declared("Uma", SM9EncPrivateKeyParameters.USAGE_KEM).getUsage() == SM9EncPrivateKeyParameters.USAGE_KEM);
        isTrue("a key declared for decryption", declared("Uma", SM9EncPrivateKeyParameters.USAGE_DECRYPTION)
            .getUsage() == SM9EncPrivateKeyParameters.USAGE_DECRYPTION);
        isTrue("a declared key is not an exchange key",
            !declared("Uma", SM9EncPrivateKeyParameters.USAGE_KEM).isExchangeKey());

        SM9EncPrivateKeyParameters exchangeKey = master.generateExchangeKey(identity);
        isTrue("an exchange key", exchangeKey.getUsage() == SM9EncPrivateKeyParameters.USAGE_KEY_EXCHANGE
            && exchangeKey.isExchangeKey());
        isTrue("an imported exchange key", SM9EncPrivateKeyParameters.fromEncodedExchangeKey(
            exchangeKey.getEncoded(), master.getPublicKeyParameters(), identity).getUsage()
            == SM9EncPrivateKeyParameters.USAGE_KEY_EXCHANGE);
    }

    /**
     * A key used for the KEM goes on decapsulating and is refused for decryption, at init, with a message
     * naming both uses and the property.
     */
    private void checkKemFirst()
        throws Exception
    {
        SM9EncPublicKeyParameters recipient = recipient("Alice", HID);
        SM9EncPrivateKeyParameters key = key("Alice", HID);
        decapsulate(recipient, key);
        decryptionRefused(key, USED_FOR_KEM);
        decapsulate(recipient, key);
    }

    /**
     * A key used for decryption goes on decrypting, in either mode, and is refused for the KEM, by the
     * extractor's constructor.
     */
    private void checkDecryptionFirst()
        throws Exception
    {
        SM9EncPublicKeyParameters recipient = recipient("Bob", HID);
        SM9EncPrivateKeyParameters key = key("Bob", HID);
        decrypt(recipient, key, SM9Engine.Mode.SM4);
        kemRefused(key, USED_FOR_DECRYPTION);
        decrypt(recipient, key, SM9Engine.Mode.STREAM);
        decrypt(recipient, key, SM9Engine.Mode.SM4);
    }

    /**
     * The key is recognised by its value: derived again, or rebuilt from its encoding under a master public
     * key decoded afresh, it is a new object held to the use its first object was put to.
     */
    private void checkSameValueNewObject()
        throws Exception
    {
        SM9EncPrivateKeyParameters key = key("Carol", HID);
        decapsulate(recipient("Carol", HID), key);

        decryptionRefused(key("Carol", HID), USED_FOR_KEM);
        SM9EncMasterPublicKeyParameters decoded =
            SM9EncMasterPublicKeyParameters.fromEncoded(master.getPublicKeyParameters().getEncoded());
        decryptionRefused(SM9EncPrivateKeyParameters.fromEncoded(key.getEncoded(), decoded,
            Strings.toByteArray("Carol"), HID), USED_FOR_KEM);
    }

    /**
     * Keys of different values are held apart: the same identity's key under another hid, and another
     * identity's key under the same hid, are each free for whichever use comes first.
     */
    private void checkDistinctValues()
        throws Exception
    {
        decapsulate(recipient("Dave", HID), key("Dave", HID));

        byte otherHid = (byte)0x05;
        SM9EncPrivateKeyParameters underOtherHid = key("Dave", otherHid);
        decrypt(recipient("Dave", otherHid), underOtherHid, SM9Engine.Mode.SM4);
        kemRefused(underOtherHid, USED_FOR_DECRYPTION);

        decrypt(recipient("Erin", HID), key("Erin", HID), SM9Engine.Mode.SM4);
    }

    /**
     * With the property set for the thread, a key serves both uses and nothing is recorded; what was
     * recorded before it was set is still held once it is cleared.
     */
    private void checkMultiUseAllowed()
        throws Exception
    {
        SM9EncPublicKeyParameters recipient = recipient("Frank", HID);
        SM9EncPrivateKeyParameters key = key("Frank", HID);
        Properties.setThreadOverride(Properties.SM9_ALLOW_MULTI_USE, true);
        try
        {
            decapsulate(recipient, key);
            decrypt(recipient, key, SM9Engine.Mode.SM4);
            decapsulate(recipient, key);
        }
        finally
        {
            Properties.removeThreadOverride(Properties.SM9_ALLOW_MULTI_USE);
        }

        // nothing was recorded, so the first use now is the one the key is held to
        decrypt(recipient, key, SM9Engine.Mode.SM4);
        kemRefused(key, USED_FOR_DECRYPTION);

        Properties.setThreadOverride(Properties.SM9_ALLOW_MULTI_USE, true);
        try
        {
            decapsulate(recipient, key);
        }
        finally
        {
            Properties.removeThreadOverride(Properties.SM9_ALLOW_MULTI_USE);
        }
        kemRefused(key, USED_FOR_DECRYPTION);
    }

    /**
     * Threads handed separate objects of one key at once, half for the KEM and half for decryption, agree
     * on one use: every thread of that use is let through and every thread of the other is refused.
     */
    private void checkConcurrentFirstUse()
        throws Exception
    {
        for (int round = 0; round != 4; round++)
        {
            String name = "Grace " + round;
            final SM9EncPrivateKeyParameters[] keys = new SM9EncPrivateKeyParameters[8];
            for (int i = 0; i != keys.length; i++)
            {
                keys[i] = key(name, HID);
            }
            final boolean[] refused = new boolean[keys.length];
            final Throwable[] unexpected = new Throwable[keys.length];
            final Gate gate = new Gate();
            Thread[] threads = new Thread[keys.length];
            for (int i = 0; i != threads.length; i++)
            {
                final int index = i;
                threads[i] = new Thread()
                {
                    public void run()
                    {
                        try
                        {
                            gate.await();
                            if (index % 2 == 0)
                            {
                                new SM9KEMExtractor(keys[index], 128);
                            }
                            else
                            {
                                new SM9Engine().init(false, keys[index]);
                            }
                        }
                        catch (IllegalArgumentException e)
                        {
                            refused[index] = true;
                        }
                        catch (Throwable t)
                        {
                            unexpected[index] = t;
                        }
                    }
                };
                threads[i].start();
            }
            gate.open();
            for (int i = 0; i != threads.length; i++)
            {
                threads[i].join();
            }

            for (int i = 0; i != threads.length; i++)
            {
                isTrue("unexpected failure in thread " + i + ": " + unexpected[i], unexpected[i] == null);
            }
            boolean kemHeld = !refused[0];
            for (int i = 0; i != threads.length; i++)
            {
                boolean kem = (i % 2 == 0);
                isTrue("round " + round + ": thread " + i + " disagrees with the use the key is held to",
                    refused[i] == (kem != kemHeld));
            }
        }
    }

    /**
     * The key exchange is not part of the check: an exchange key formed under the encryption hid is the
     * same point as the KEM key, and the exchange runs after that point has been used for the KEM. The
     * exchange key itself is refused by recordUsage, as by the KEM and decryption.
     */
    private void checkKeyExchangeUnaffected()
        throws Exception
    {
        byte[] heidi = Strings.toByteArray("Heidi");
        byte[] ivan = Strings.toByteArray("Ivan");
        SM9EncPrivateKeyParameters kemKey = master.generateUserKey(heidi, HID);
        decapsulate(recipient("Heidi", HID), kemKey);

        SM9EncPrivateKeyParameters exchangeKey = master.generateExchangeKey(heidi, HID);
        isTrue("an exchange key under the encryption hid is the KEM key's point",
            Arrays.areEqual(kemKey.getEncoded(), exchangeKey.getEncoded()));
        SM9KeyExchange initiator = new SM9KeyExchange(exchangeKey, ivan, true);
        SM9KeyExchange responder = new SM9KeyExchange(master.generateExchangeKey(ivan, HID), heidi, false);
        ECPoint ra = initiator.generateEphemeral(random);
        ECPoint rb = responder.generateEphemeral(random);
        isTrue("SM9 key exchange agrees after the point's KEM use",
            Arrays.areEqual(initiator.calculateKey(128, rb), responder.calculateKey(128, ra)));

        try
        {
            exchangeKey.recordUsage(SM9EncPrivateKeyParameters.USAGE_KEM);
            fail("recordUsage took a key-exchange key for the KEM");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(), "SM9 key-exchange user key cannot be used for KEM decapsulation".equals(e.getMessage()));
        }
        try
        {
            exchangeKey.recordUsage(SM9EncPrivateKeyParameters.USAGE_DECRYPTION);
            fail("recordUsage took a key-exchange key for decryption");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(), "SM9 key-exchange user key cannot be used for decryption".equals(e.getMessage()));
        }
    }

    private void checkArguments()
    {
        SM9EncPrivateKeyParameters key = key("Judy", HID);
        int[] usages = { SM9EncPrivateKeyParameters.USAGE_UNSPECIFIED, SM9EncPrivateKeyParameters.USAGE_KEY_EXCHANGE, -1 };
        for (int i = 0; i != usages.length; i++)
        {
            try
            {
                key.recordUsage(usages[i]);
                fail("recordUsage took usage " + usages[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue(e.getMessage(), "usage must be USAGE_KEM or USAGE_DECRYPTION".equals(e.getMessage()));
            }
        }
    }

    /**
     * A destroyed key is taken by the engine and the extractor as before, and reported destroyed when used,
     * whether it was destroyed before it was first handed over or since; it records nothing. Destroyed
     * before its first use it leaves the key's value free; destroyed since, it lets go of the record of its
     * value, which still holds the value to that use.
     */
    private void checkDestroyed()
        throws Exception
    {
        SM9EncPrivateKeyParameters key = key("Ken", HID);
        key.destroy();
        SM9Engine engine = new SM9Engine();
        engine.init(false, key);
        SM9KEMExtractor extractor = new SM9KEMExtractor(key, 128);
        byte[] ciphertext = encrypt(recipient("Ken", HID), SM9Engine.Mode.SM4);
        try
        {
            engine.processBlock(ciphertext, 0, ciphertext.length);
            fail("SM9Engine decrypted under a destroyed key");
        }
        catch (IllegalStateException e)
        {
            isTrue(e.getMessage(), "key destroyed".equals(e.getMessage()));
        }
        byte[] encapsulation = new SM9KEMGenerator(128, random)
            .generateEncapsulated(recipient("Ken", HID)).getEncapsulation();
        try
        {
            extractor.extractSecret(encapsulation);
            fail("SM9KEMExtractor decapsulated under a destroyed key");
        }
        catch (IllegalStateException e)
        {
            isTrue(e.getMessage(), "key destroyed".equals(e.getMessage()));
        }

        decrypt(recipient("Ken", HID), key("Ken", HID), SM9Engine.Mode.SM4);
        kemRefused(key("Ken", HID), USED_FOR_DECRYPTION);

        // destroyed since its first use, for the KEM: taken for decryption as well, the operation then
        // reporting the key destroyed, rather than refused at init for the other use
        SM9EncPrivateKeyParameters used = key("Kim", HID);
        used.recordUsage(SM9EncPrivateKeyParameters.USAGE_KEM);
        used.destroy();
        Field recordField = SM9EncPrivateKeyParameters.class.getDeclaredField("usageRecord");
        recordField.setAccessible(true);
        isTrue("a destroyed key holds the record of its value", recordField.get(used) == null);
        SM9Engine afterUse = new SM9Engine();
        afterUse.init(false, used);
        byte[] kimCiphertext = encrypt(recipient("Kim", HID), SM9Engine.Mode.SM4);
        try
        {
            afterUse.processBlock(kimCiphertext, 0, kimCiphertext.length);
            fail("SM9Engine decrypted under a key destroyed since its first use");
        }
        catch (IllegalStateException e)
        {
            isTrue(e.getMessage(), "key destroyed".equals(e.getMessage()));
        }
        decryptionRefused(key("Kim", HID), USED_FOR_KEM);
    }

    /**
     * A key is recognised for as long as one of its objects that has been checked is in use, however many
     * other keys are used meanwhile - more than the records held beyond the key objects - and for a while
     * after its last object is let go.
     */
    private void checkRecordOutlivesRecentKeys()
        throws Exception
    {
        // the guard is package-private, so how many records it holds besides the key objects is read
        // from it rather than repeated here
        Class guard = Class.forName("org.bouncycastle.crypto.params.SM9KeyUsageGuard");
        Field recentField = guard.getDeclaredField("RECENT");
        recentField.setAccessible(true);
        int recent = recentField.getInt(null);
        Field countField = guard.getDeclaredField("recentCount");
        countField.setAccessible(true);

        SM9EncPrivateKeyParameters held = key("Leo", HID);
        decapsulate(recipient("Leo", HID), held);
        SM9EncPrivateKeyParameters oldest = null;
        SM9EncPrivateKeyParameters newest = null;
        for (int i = 0; i != recent + 8; i++)
        {
            newest = key("other " + i, HID);
            newest.recordUsage(SM9EncPrivateKeyParameters.USAGE_DECRYPTION);
            if (oldest == null)
            {
                oldest = newest;
            }
        }
        // as many are held besides as there is room for, the oldest let go to make room for the newest,
        // and a record checked again moves among them rather than adding to them. Read from the guard,
        // so that the order is tested whether or not the collector takes the object below
        isTrue("records held besides the key objects: " + countField.getInt(null), countField.getInt(null) == recent);
        isTrue("the newest record is held besides the key objects", heldBesides(newest));
        isTrue("the oldest records are let go", !heldBesides(held) && !heldBesides(oldest));
        held.recordUsage(SM9EncPrivateKeyParameters.USAGE_KEM);
        held.recordUsage(SM9EncPrivateKeyParameters.USAGE_KEM);
        isTrue("records held besides the key objects: " + countField.getInt(null), countField.getInt(null) == recent);
        isTrue("a record checked again is held besides the key objects", heldBesides(held));
        decryptionRefused(key("Leo", HID), USED_FOR_KEM);
        isTrue("the key object is in use to here", held.getHid() == HID);

        // once a key's last object has gone, its record is among those held besides, so the key derived
        // again is held to the same use. The object has to have been collected for that to be what is
        // tested: while it lives the record is found through it
        SM9EncPrivateKeyParameters later = key("Niaj", HID);
        later.recordUsage(SM9EncPrivateKeyParameters.USAGE_KEM);
        WeakReference laterRef = new WeakReference(later);
        later = null;
        if (!collected(laterRef))
        {
            // System.gc() is only a request, which a JVM can be run to ignore, and a JVM may keep the
            // object for its own reasons; where the collector would not take it, this last part cannot
            // be tested. The order the records are let go in is tested above either way
            return;
        }
        for (int i = 0; i != 8; i++)
        {
            key("another " + i, HID).recordUsage(SM9EncPrivateKeyParameters.USAGE_DECRYPTION);
        }
        decryptionRefused(key("Niaj", HID), USED_FOR_KEM);
    }

    // whether the record of the value of key is among those the guard holds besides the key objects:
    // a record in that ring has neighbours, and one out of it has none
    private boolean heldBesides(SM9EncPrivateKeyParameters key)
        throws Exception
    {
        Field recordField = SM9EncPrivateKeyParameters.class.getDeclaredField("usageRecord");
        recordField.setAccessible(true);
        Object record = recordField.get(key);
        Field nextField = record.getClass().getDeclaredField("next");
        nextField.setAccessible(true);
        return nextField.get(record) != null;
    }

    // whether the collector takes what ref refers to, asked through System.gc() and through allocation,
    // which a JVM that ignores System.gc() still collects for, for up to five seconds
    private boolean collected(WeakReference ref)
    {
        long deadline = System.currentTimeMillis() + 5000;
        while (ref.get() != null && System.currentTimeMillis() < deadline)
        {
            System.gc();
            garbage = new byte[1 << 20];
        }
        garbage = null;
        return ref.get() == null;
    }

    private SM9EncPrivateKeyParameters key(String identity, byte hid)
    {
        return master.generateUserKey(Strings.toByteArray(identity), hid);
    }

    private SM9EncPrivateKeyParameters declared(String identity, int usage)
    {
        return master.generateUserKey(Strings.toByteArray(identity), HID, usage);
    }

    private SM9EncPublicKeyParameters recipient(String identity, byte hid)
    {
        return master.getPublicKeyParameters().getUserPublicKey(Strings.toByteArray(identity), hid);
    }

    private void decapsulate(SM9EncPublicKeyParameters recipient, SM9EncPrivateKeyParameters key)
    {
        SecretWithEncapsulation enc = new SM9KEMGenerator(128, random).generateEncapsulated(recipient);
        isTrue("SM9 KEM round trip",
            Arrays.areEqual(enc.getSecret(), new SM9KEMExtractor(key, 128).extractSecret(enc.getEncapsulation())));
    }

    private byte[] encrypt(SM9EncPublicKeyParameters recipient, SM9Engine.Mode mode)
        throws InvalidCipherTextException
    {
        byte[] message = Strings.toByteArray("a message of twenty-nine bytes");
        SM9Engine engine = new SM9Engine(mode);
        engine.init(true, new ParametersWithRandom(recipient, random));
        return engine.processBlock(message, 0, message.length);
    }

    private void decrypt(SM9EncPublicKeyParameters recipient, SM9EncPrivateKeyParameters key, SM9Engine.Mode mode)
        throws InvalidCipherTextException
    {
        byte[] ciphertext = encrypt(recipient, mode);
        SM9Engine engine = new SM9Engine(mode);
        engine.init(false, key);
        isTrue("SM9 decryption round trip", Arrays.areEqual(Strings.toByteArray("a message of twenty-nine bytes"),
            engine.processBlock(ciphertext, 0, ciphertext.length)));
    }

    private void kemRefused(SM9EncPrivateKeyParameters key, String expected)
    {
        try
        {
            new SM9KEMExtractor(key, 128);
            fail("SM9KEMExtractor took a key held to decryption");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(), expected.equals(e.getMessage()));
        }
    }

    private void decryptionRefused(SM9EncPrivateKeyParameters key, String expected)
    {
        SM9Engine engine = new SM9Engine();
        try
        {
            engine.init(false, key);
            fail("SM9Engine took a key held to the KEM for decryption");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(), expected.equals(e.getMessage()));
        }
        try
        {
            // the refused init leaves the engine uninitialised
            engine.processBlock(new byte[128], 0, 128);
            fail("SM9Engine decrypted after a refused init");
        }
        catch (IllegalStateException e)
        {
            isTrue(e.getMessage(), "SM9 engine not initialised for decryption".equals(e.getMessage()));
        }
        catch (InvalidCipherTextException e)
        {
            fail("SM9Engine decrypted after a refused init: " + e.getMessage());
        }
    }

    // a start line for the threads of checkConcurrentFirstUse
    private static final class Gate
    {
        private boolean open;

        synchronized void await()
            throws InterruptedException
        {
            while (!open)
            {
                wait();
            }
        }

        synchronized void open()
        {
            open = true;
            notifyAll();
        }
    }

    public static void main(String[] args)
    {
        runTest(new SM9KeyUsageTest());
    }
}
