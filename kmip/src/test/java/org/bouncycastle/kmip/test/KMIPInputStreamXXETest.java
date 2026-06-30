package org.bouncycastle.kmip.test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.Writer;

import junit.framework.TestCase;

import org.bouncycastle.kmip.wire.KMIPInputStream;

/**
 * Regression test for the XXE hardening of the KMIP XML wire parser (CVD ANT-2026-340FH9ZA):
 * KMIPInputStream must not resolve DTDs / external entities in untrusted, pre-authentication input.
 */
public class KMIPInputStreamXXETest
    extends TestCase
{
    public void testExternalEntityNotResolved()
        throws Exception
    {
        File secret = File.createTempFile("kmip-xxe", ".txt");
        try
        {
            Writer w = new FileWriter(secret);
            w.write("XXE_SECRET_LEAKED");
            w.close();

            String xml =
                "<!DOCTYPE RequestMessage [<!ENTITY xxe SYSTEM \"file://" + secret.getAbsolutePath() + "\">]>"
                    + "<RequestMessage><RequestHeader>&xxe;</RequestHeader></RequestMessage>";

            try
            {
                new KMIPInputStream(new ByteArrayInputStream(xml.getBytes("UTF-8"))).parse();
                fail("KMIP XML parser resolved a DTD / external entity");
            }
            catch (Exception e)
            {
                // With DTDs disabled the entity is never declared, so it cannot resolve to the file
                // contents: the parse fails because "xxe" is referenced but not declared, and the
                // secret never appears.
                String m = String.valueOf(e.getMessage());
                assertFalse("external entity was resolved (XXE): " + m, m.contains("XXE_SECRET_LEAKED"));
                assertTrue("expected the external entity to be rejected as undeclared, got: " + m,
                    m.contains("not declared"));
            }
        }
        finally
        {
            secret.delete();
        }
    }
}
