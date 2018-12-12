package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.util.JournalingSecureRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

public class JournalingSecureRandomTest
    extends SimpleTest
{
    public String getName()
    {
        return "JournalingSecureRandom";
    }

    public void performTest()
        throws Exception
    {
        SecureRandom rand = new SecureRandom();

        JournalingSecureRandom jRandom1 = new JournalingSecureRandom(rand);

        byte[] base = new byte[1024];

        jRandom1.nextBytes(base);

        byte[] transcript = jRandom1.getTranscript();

        byte[] block = new byte[512];

        JournalingSecureRandom jRandom2 = new JournalingSecureRandom(transcript, rand);

        jRandom2.nextBytes(block);

        areEqual(Arrays.copyOfRange(base, 0, 512), block);

        jRandom2.nextBytes(block);

        areEqual(Arrays.copyOfRange(base, 512, 1024), block);

        jRandom2.nextBytes(block);

        isTrue(!Arrays.areEqual(Arrays.copyOfRange(base, 0, 512), block));

    }

    public static void main(
        String[] args)
    {
        runTest(new JournalingSecureRandomTest());
    }
}
