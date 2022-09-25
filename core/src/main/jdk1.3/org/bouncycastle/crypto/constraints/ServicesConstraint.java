package org.bouncycastle.crypto.constraints;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
//import java.util.logging.Logger;

import org.bouncycastle.crypto.CryptoServicesConstraints;
import org.bouncycastle.util.Strings;

/**
 * Base class for a constraint, serves to provide storage for the set of exceptions (if any).
 */
abstract public class ServicesConstraint
    implements CryptoServicesConstraints
{
    //protected static final Logger LOG = Logger.getLogger(ServicesConstraint.class.getName());

    private final Set<String> exceptions;

    protected ServicesConstraint(Set<String> exceptions)
    {
        if (exceptions.isEmpty())
        {
            this.exceptions = Collections.EMPTY_SET;
        }
        else
        {
            this.exceptions = new HashSet<String>(exceptions.size());
            for (Iterator it = exceptions.iterator(); it.hasNext();)
            {
                this.exceptions.add(Strings.toUpperCase(it.next().toString()));
            }

            Utils.addAliases(this.exceptions);
        }
    }

    protected boolean isException(String algorithm)
    {
        if (exceptions.isEmpty())
        {
            return false;
        }

        return exceptions.contains(Strings.toUpperCase(algorithm));
    }
}
