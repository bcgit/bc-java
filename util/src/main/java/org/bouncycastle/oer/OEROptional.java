package org.bouncycastle.oer;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.bouncycastle.asn1.ASN1Absent;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * A placeholder object that represents an absent item.
 */
public class OEROptional
    extends ASN1Object
{
    public static final OEROptional ABSENT = new OEROptional(false, null);
    private final boolean defined;
    private final ASN1Encodable value;


    private OEROptional(boolean defined, ASN1Encodable value)
    {
        this.defined = defined;
        this.value = value;
    }

    public static OEROptional getInstance(Object o)
    {
        if (o instanceof OEROptional)
        {
            return (OEROptional)o;
        }
        else if (o instanceof ASN1Encodable)
        {
            return new OEROptional(true, (ASN1Encodable)o);
        }
        return ABSENT;
    }

    public static <T> T getValue(Class<T> type, Object src)
    {
        OEROptional o = OEROptional.getInstance(src);
        if (!o.defined)
        {
            return null;
        }
        return o.getObject(type);
    }

    /**
     * utility method to cast value to a given type or to call that type's getInstance(Object o) method
     * if it has one.
     *
     * @param type The target type.
     * @param <T>  The type.
     * @return An instance of that type.
     */
    public <T> T getObject(final Class<T> type)
    {

        if (defined)
        {
            if (value.getClass().isInstance(type))
            {
                return type.cast(value);
            }
            else
            {
                return AccessController.doPrivileged(new PrivilegedAction<T>()
                {
                    public T run()
                    {
                        try
                        {
                            Method m = type.getMethod("getInstance", Object.class);
                            return type.cast(m.invoke(null, value));
                        }
                        catch (Exception ex)
                        {
                            throw new IllegalStateException("could not invoke getInstance on type " + ex.getMessage(), ex);
                        }
                    }
                });
            }
        }
        return null;
    }

    public ASN1Encodable get()
    {
        if (!defined)
        {
            return ABSENT;
        }
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (!defined)
        {
            return ASN1Absent.INSTANCE;
        }
        return get().toASN1Primitive();
    }

    public boolean isDefined()
    {
        return defined;
    }

    public String toString()
    {
        if (defined)
        {
            return "OPTIONAL(" + value + ")";
        }
        else
        {
            return "ABSENT";
        }
    }

    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }
        if (!super.equals(o))
        {
            return false;
        }

        OEROptional that = (OEROptional)o;

        if (defined != that.defined)
        {
            return false;
        }
        return value != null ? value.equals(that.value) : that.value == null;
    }

    public int hashCode()
    {
        int result = super.hashCode();
        result = 31 * result + (defined ? 1 : 0);
        result = 31 * result + (value != null ? value.hashCode() : 0);
        return result;
    }


}
