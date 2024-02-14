package org.bouncycastle.openpgp.test;

import java.security.Security;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.test.SimpleTest;

public class OpenpgpTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OpenpgpTest());
    }

    @Override
    public String getName()
    {
        return "OpenpgpTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testPGPUtil();
        testPGPCompressedDataGenerator();
    }

    public void testPGPCompressedDataGenerator()
    {
        testException("unknown compression algorithm", "IllegalArgumentException", () -> new PGPCompressedDataGenerator(110));
        testException("unknown compression level:", "IllegalArgumentException", () -> new PGPCompressedDataGenerator(CompressionAlgorithmTags.UNCOMPRESSED, 10));
    }

    public void testPGPUtil()
        throws PGPException
    {
        isEquals("SHA1", PGPUtil.getDigestName(HashAlgorithmTags.SHA1));
        isEquals("MD2", PGPUtil.getDigestName(HashAlgorithmTags.MD2));
        isEquals("MD5", PGPUtil.getDigestName(HashAlgorithmTags.MD5));
        isEquals("RIPEMD160", PGPUtil.getDigestName(HashAlgorithmTags.RIPEMD160));
        isEquals("SHA256", PGPUtil.getDigestName(HashAlgorithmTags.SHA256));
        isEquals("SHA256", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_256));
        isEquals("SHA256", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_256_OLD));
        isEquals("SHA384", PGPUtil.getDigestName(HashAlgorithmTags.SHA384));
        isEquals("SHA384", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_384));
        isEquals("SHA512", PGPUtil.getDigestName(HashAlgorithmTags.SHA512));
        isEquals("SHA512", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_512));
        isEquals("SHA512", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_512_OLD));
        isEquals("SHA224", PGPUtil.getDigestName(HashAlgorithmTags.SHA224));
        isEquals("SHA224", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_224));
        isEquals("TIGER", PGPUtil.getDigestName(HashAlgorithmTags.TIGER_192));
        testException("unknown hash algorithm tag in getDigestName: ", "PGPException", ()->PGPUtil.getDigestName(HashAlgorithmTags.MD4));

        testException("unable to map ", "IllegalArgumentException", () -> PGPUtil.getDigestIDForName("Test"));
    }
}
