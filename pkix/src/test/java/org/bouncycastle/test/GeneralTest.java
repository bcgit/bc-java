package org.bouncycastle.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public abstract class GeneralTest
    extends TestCase
{
    protected DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
    protected DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();

    protected static final DigestCalculatorProvider digCalcProv;

    static
    {
        try
        {
            digCalcProv = new JcaDigestCalculatorProviderBuilder().build();
        }
        catch (OperatorCreationException e)
        {
            throw new RuntimeException(e);
        }
    }

    protected static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    protected interface TestExceptionOperation
    {
        void operation()
            throws Exception;
    }

    protected Exception testException(String failMessage, String exceptionClass, TestExceptionOperation operation)
    {
        try
        {
            operation.operation();
            fail(failMessage);
        }
        catch (Exception e)
        {
            if (failMessage != null)
            {
                assertTrue(e.getMessage().contains(failMessage));
            }
            assertTrue(e.getClass().getName().contains(exceptionClass));
            return e;
        }
        return null;
    }

}
