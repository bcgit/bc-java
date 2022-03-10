package org.bouncycastle.oer.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.OEROutputStream;
import org.bouncycastle.oer.its.ieee1609dot2.ContributedExtensionBlocks;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PolygonalRegion;
import org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941TrustLists;
import org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941TypesAuthorization;
import org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941TypesAuthorizationValidation;
import org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941TypesCaManagement;
import org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941TypesEnrolment;
import org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941TypesLinkCertificate;
import org.bouncycastle.oer.its.template.etsi102941.basetypes.EtsiTs102941BaseTypes;
import org.bouncycastle.oer.its.template.etsi103097.EtsiTs103097Module;
import org.bouncycastle.oer.its.template.etsi103097.extension.EtsiTs103097ExtensionModule;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.oer.its.template.ieee1609dot2.basetypes.Ieee1609Dot2BaseTypes;
import org.bouncycastle.oer.its.template.ieee1609dot2dot1.Ieee1609Dot2Dot1EcaEeInterface;
import org.bouncycastle.oer.its.template.ieee1609dot2dot1.Ieee1609Dot2Dot1EeRaInterface;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestFailedException;
import org.bouncycastle.util.test.TestResult;

public class ExpansionTest
    extends SimpleTest
{
    @Override
    public String getName()
    {
        return "OER Expansion test";
    }

    @Override
    public void performTest()
        throws Exception
    {

        List<Field> items = extractFields(
            EtsiTs102941BaseTypes.class,
            EtsiTs102941TypesAuthorization.class,
            EtsiTs102941TrustLists.class,
            EtsiTs102941TypesAuthorizationValidation.class,
            EtsiTs102941TypesCaManagement.class,
            EtsiTs102941TypesEnrolment.class,
            EtsiTs102941TypesLinkCertificate.class,
            Ieee1609Dot2Dot1EcaEeInterface.class,
            Ieee1609Dot2Dot1EeRaInterface.class,
            EtsiTs103097ExtensionModule.class,
            EtsiTs103097Module.class,
            Ieee1609Dot2BaseTypes.class,
            IEEE1609dot2.class);
        for (Field f : items)
        {
            OERDefinition.Builder builder = (OERDefinition.Builder)f.get(null);
            Element def = builder.build();

            if (ExpansionCaveats.skip(def))
            {
                continue;
            }

            //
            // Does the definition have a label.
            //
            if (def.getLabel() == null)
            {
                fail(f.getName() + " has no label");
            }

            //
            // Does the definition have a typename.
            //
            if (def.getTypeName() == null)
            {
                fail(f.getName() + " has no type name");
            }

//            // Type name and field name in template class must match.
//            if (!def.getTypeName().replace("-", "_").equals(f.getName()))
//            {
//                fail(String.format("type '%s' name does not match field name '%s' in template class %s", def.getTypeName(), f.getName(), f.getDeclaringClass().getName()));
//            }

            //
            // Resolve upper level class.
            //
            String name = def.getTypeName();// f.getName();
            String pack = f.getDeclaringClass().getPackage().getName();
            pack = pack.replace("template.", "");
            String upperLevelClassName = (pack + "." + name).replace("/", ".");
            Class upperLevelClass = null;
            try
            {
                upperLevelClass = Class.forName(upperLevelClassName);
            }
            catch (Throwable ex)
            {
                if (ex instanceof ExceptionInInitializerError)
                {
                    ex = ((ExceptionInInitializerError)ex).getException();
                }
                fail("unable to load " + upperLevelClassName + " " + ex.getMessage());
            }


            checkUpperLevelClassStructure(upperLevelClass, def);

            //
            // Find getInstance
            //
            Method getInstanceMethod = null;
            try
            {
                getInstanceMethod = upperLevelClass.getMethod("getInstance", Object.class);
            }
            catch (Exception ex)
            {
                fail(upperLevelClass.getName() + ": unable to find getInstance method for " + upperLevelClassName + " " + ex.getMessage());
            }

            if (!Modifier.isStatic(getInstanceMethod.getModifiers()))
            {
                fail(upperLevelClass.getName() + ": getInstance method is not static");
            }

            try
            {
                // Invoke with null parameter, should return null;
                Object expectNull = getInstanceMethod.invoke(null, new Object[]{null});
                if (expectNull != null)
                {
                    fail(upperLevelClass.getName() + ": getInstance with null as parameter did not return null");
                }
            }
            catch (Throwable t)
            {
                fail(upperLevelClass.getName() + ": getInstance failed on null parameter, " + t.getMessage());
            }

            HashSet<String> skipExpansionOn = new HashSet<String>()
            {

            };

            if (!skipExpansionOn.contains(name))
            {
                Set<ASN1Encodable> validAsn1 = OERExpander.expandElement(def);
                int dataIndex = 0;
                for (ASN1Encodable encodable : validAsn1)
                {
                    ASN1Encodable target = (ASN1Encodable)getInstanceMethod.invoke(null, encodable);

                    ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                    OEROutputStream oos = new OEROutputStream(encoded);
                    oos.write(target, def);
                    oos.flush();
                    oos.close();

                    ByteArrayInputStream bin = new ByteArrayInputStream(encoded.toByteArray());
                    OERInputStream oin = new OERInputStream(bin);
                    ASN1Encodable recreated = oin.parse(def);
                    Object recreatedTarget = (ASN1Encodable)getInstanceMethod.invoke(null, recreated);

                    isEquals(upperLevelClass.getName() + ": failed with data " + dataIndex, target, recreatedTarget);
                    dataIndex++;

                }
            }
        }

    }

    private void checkUpperLevelClassStructure(Class upperLevelClass, Element element)
        throws Exception
    {

        // Is it sequence of xxx
        String name = upperLevelClass.getName();
        if (name.contains("."))
        {
            name = name.substring(name.lastIndexOf('.') + 1);
        }


        Hashtable<Class, String> sequenceOfMapping = new Hashtable<Class, String>()
        {
            {
                put(PolygonalRegion.class, "PolygonalRegion");
                put(ContributedExtensionBlocks.class, "ContributedExtensionBlock");
            }
        };

        //
        // Checking for SequenceOf types.
        //
        if (element.getBaseType() == OERDefinition.BaseType.SEQ_OF)
        {

            String returnTypeName = null;
            returnTypeName = sequenceOfMapping.get(upperLevelClass);

            if (!name.startsWith("SequenceOf"))
            {
                if (returnTypeName == null)
                {
                    // Not a Sequence of with a non conforming name.
                    fail(upperLevelClass.getName() + ": SequenceOf class name did not start with SequenceOf");
                }
            }

            if (returnTypeName == null)
            {
                returnTypeName = name.substring(10);
            }

            String getter;
            if (Strings.toLowerCase(returnTypeName).endsWith("s"))
            {
                getter = "get" + returnTypeName;
            }
            else if (Strings.toLowerCase(returnTypeName).endsWith("y"))
            {
                getter = "get" + returnTypeName.substring(0, returnTypeName.length() - 1) + "ies";
            }
            else
            {
                getter = "get" + returnTypeName + "s";
            }


            Class returnType = ExpansionCaveats.getSequenceOfReturnType(returnTypeName);
            Method getterMethod = ExpansionCaveats.getSequenceOfGetterMethod(returnTypeName);
            // Specific case.

            if (returnType == null)
            {
                try
                {
                    String k = (upperLevelClass.getPackage().getName().replace("template.", "") + "." + returnTypeName)
                        .replace("/", ".");
                    returnType = Class.forName(k);
                }
                catch (ClassNotFoundException ncdf)     // Java 8
                {
                    // Look for all caps version of class name, eg UINT16 etc
                    String k = (upperLevelClass.getPackage().getName().replace("template.", "") + "." + returnTypeName.toUpperCase())
                        .replace("/", ".");
                    returnType = Class.forName(k);
                }
                catch (NoClassDefFoundError ncdf)
                {
                    // Look for all caps version of class name, eg UINT16 etc
                    String k = (upperLevelClass.getPackage().getName().replace("template.", "") + "." + returnTypeName.toUpperCase())
                        .replace("/", ".");
                    returnType = Class.forName(k);
                }
            }

            Class listElementType = returnType;

            if (getterMethod == null)
            {
                try
                {
                    getterMethod = upperLevelClass.getMethod(getter);
                    returnType = getterMethod.getReturnType();
                }
                catch (Throwable t)
                {
                    fail(upperLevelClass.getName() + ": count not find getter on SequenceOf " + t.getMessage());
                }
            }
            else
            {
                returnType = getterMethod.getReturnType();
            }

            if (!returnType.isAssignableFrom(List.class))
            {
                fail(upperLevelClass.getName() + ": SequenceOf getter is not a list type");
            }


            //
            // Look for a list accepting constructor.
            //

            try
            {
                Constructor lac = upperLevelClass.getConstructor(java.util.List.class);
                ArrayList ar = new ArrayList();
                ar.add(create(listElementType, element.getChildren().get(0)));
                Object seqOf = lac.newInstance(ar);

                List l = (List)getterMethod.invoke(seqOf);


                if (l.size() != 1)
                {
                    fail(upperLevelClass.getName() + ": returned list did not have size of 1");
                }

                if (!listElementType.isAssignableFrom(l.get(0).getClass()))
                {
                    fail(upperLevelClass.getName() + ": list item " + l.get(0).getClass() + " did not match returned type " + returnType);
                }

                try
                {
                    l.add(create(listElementType, element.getChildren().get(0)));
                    fail(upperLevelClass.getName() + ": must fail on add.");
                }
                catch (UnsupportedOperationException umex)
                {
                    // ok!
                }

            }
            catch (TestFailedException t)
            {
                throw t;
            }
            catch (Throwable t)
            {
                fail(upperLevelClass.getName() + ": finding list accepting constructor for SequenceOf " + t);
            }


            //
            // Does it have a private AS1Sequence constructor
            //

            try
            {
                Constructor lac = upperLevelClass.getDeclaredConstructor(ASN1Sequence.class);
                if (!Modifier.isPrivate(lac.getModifiers()))
                {
                    fail(upperLevelClass.getName() + ": ASN1Sequence accepting constructor is not private.");
                }
            }
            catch (Throwable t)
            {
                fail(upperLevelClass.getName() + ": finding list accepting constructor for SequenceOf " + t);
            }
        }
        else
        {
            if (element.getBaseType() == OERDefinition.BaseType.SEQ)
            {
                Constructor c = null;
                try
                {
                    c = upperLevelClass.getDeclaredConstructor(ASN1Sequence.class);

                    if (!(Modifier.isPrivate(c.getModifiers()) || Modifier.isProtected(c.getModifiers())))
                    {
                        fail(upperLevelClass.getName() + ": ASN1Sequence accepting constructor is not private or protected");
                    }

                }
                catch (TestFailedException t)
                {
                    throw t;
                }
                catch (Throwable ex)
                {
                    fail(upperLevelClass.getName() + ": Does not have ASN1Sequence accepting constructor");
                }

                //
                // Test sequence size validation
                //

                // Make private constructor accessible
                c.setAccessible(true);

                //
                // Count expected size, skipping extension entries
                //
                int expectedSeqSize = 0;
                for (Element e : element.getChildren())
                {
                    if (e.getBaseType() != OERDefinition.BaseType.EXTENSION)
                    {
                        expectedSeqSize++;
                    }
                }

                // Zero length sequence should cause failure.
                try
                {
                    c.newInstance(new DERSequence(new ASN1Encodable[0]));
                    fail(upperLevelClass.getName() + ": Did not fail on empty sequence");
                }
                catch (Throwable t)
                {

                    if (t instanceof InvocationTargetException)
                    {
                        t = ((InvocationTargetException)t).getTargetException();
                    }

                    if (!(t instanceof IllegalArgumentException))
                    {
                        fail(upperLevelClass.getName() + ": invalid sequence len did not thow IllegalArgumentException");
                    }

                    String expected = "expected sequence size of";
                    if (!t.getMessage().contains(expected) || !t.getMessage().contains("" + expectedSeqSize))
                    {
                        fail(String.format(upperLevelClass.getName() + ": expected sequence out of range error message '%s' got '%s'", expected, t.getMessage()));
                    }
                }

                //
                // Sequence one longer than expected.
                //
                try
                {
                    ASN1Encodable[] items = new ASN1Encodable[expectedSeqSize + 1];
                    for (int t = 0; t < items.length; t++)
                    {
                        items[t] = DERNull.INSTANCE;
                    }
                    c.newInstance(new DERSequence(items));
                    fail(upperLevelClass.getName() + ": Did not fail on overly long sequence");
                }
                catch (Throwable t)
                {
                    if (t instanceof InvocationTargetException)
                    {
                        t = ((InvocationTargetException)t).getTargetException();
                    }

                    if (!(t instanceof IllegalArgumentException))
                    {
                        fail(upperLevelClass.getName() + ": invalid sequence len did not thow IllegalArgumentException");
                    }

                    String expected = "expected sequence size of";
                    if (!t.getMessage().contains(expected) || !t.getMessage().contains("" + expectedSeqSize))
                    {
                        fail(String.format(upperLevelClass.getName() + ": expected sequence out of range error message '%s' got '%s'", expected, t.getMessage()));
                    }
                }


            }
            else if (element.getBaseType() == OERDefinition.BaseType.CHOICE)
            {
                boolean foundAsn1Choice = false;
                for (Class c : upperLevelClass.getInterfaces())
                {
                    if (c == ASN1Choice.class)
                    {
                        foundAsn1Choice = true;
                    }
                }

                if (!foundAsn1Choice)
                {
                    fail(upperLevelClass.getName() + ": does not implement ASN1Choice interface");
                }

                Constructor c = null;
                try
                {
                    c = upperLevelClass.getDeclaredConstructor(ASN1TaggedObject.class);

                    if (!Modifier.isPrivate(c.getModifiers()))
                    {
                        fail(upperLevelClass.getName() + ": ASN1TaggedObject accepting constructor is not private");
                    }
                }
                catch (Throwable ex)
                {
                    fail(upperLevelClass.getName() + ": Does not have ASN1TaggedObject accepting constructor");
                }

                // Make private constructor accessible.
                c.setAccessible(true);

                //
                // Pass in invalid choice, one more than defined.
                //
                try
                {
                    c.newInstance(new DERTaggedObject(element.getChildren().size() + 1, DERNull.INSTANCE));
                    fail(upperLevelClass.getName() + ": should fail on unknown tag");
                }
                catch (InvocationTargetException t)
                {

                    Throwable target = t.getTargetException();
                    if (!(target instanceof IllegalArgumentException))
                    {
                        fail(upperLevelClass.getName() + ": expected IllegalArgumentException on invalid choice supplied it ASN1TaggedObject constructor");
                    }

                    String expected = "invalid choice value " + (element.getChildren().size() + 1);
                    if (!target.getMessage().equals((expected)))
                    {
                        if (!target.getMessage().contains("choice not implemented"))
                        {
                            fail(String.format(upperLevelClass.getName() + ": expected '%s' got '%s' ", expected, target.getMessage()));
                        }
                    }
                }


            }
            else if (element.getBaseType() == OERDefinition.BaseType.ENUM)
            {
                testEnumeration(upperLevelClass, element);
            }
        }

        //
        // Getter check
        //

        for (Field f : upperLevelClass.getDeclaredFields())
        {
            if (Modifier.isStatic(f.getModifiers()))
            {
                continue; // Skip static ones.
            }

            if (!Modifier.isPrivate(f.getModifiers()) && !Modifier.isProtected(f.getModifiers()))
            {
                fail(upperLevelClass.getName() + ": field " + f.getName() + " is neither private or protected");
            }

            if (!Modifier.isFinal(f.getModifiers()))
            {
                fail(upperLevelClass.getName() + ": field " + f.getName() + " is not final.");
            }

            String fName = f.getName();
            if (fName.startsWith("_"))
            {
                fName = fName.substring(1);
            }

            String getter = "get" + fName.substring(0, 1).toUpperCase() + fName.substring(1);


            Method getterMethod = null;
            try
            {
                getterMethod = upperLevelClass.getMethod(getter);
            }
            catch (Throwable t)
            {
                fail(upperLevelClass.getName() + ": field " + f.getName() + " has no getter " + getter);
            }

            if (!getterMethod.getReturnType().isAssignableFrom(f.getType()))
            {
                fail(upperLevelClass.getName() + ": field " + f.getName() + " returns different type to expected " + getter);
            }

        }


    }

    private void testEnumeration(Class upperLevelClass, Element element)
        throws IllegalAccessException, InstantiationException
    {
        if (!ASN1Enumerated.class.isAssignableFrom(upperLevelClass))
        {
            fail(upperLevelClass.getName() + ": is not assignable from ASN1Enumerated");
        }

        if (element.getChildren().isEmpty())
        {
            fail(upperLevelClass.getName() + ": oer definition for " + element.getLabel() + " did not enumerate constants");
        }

        //
        // Enumeration has a protected assert values method
        //

        try
        {
            Method m = upperLevelClass.getDeclaredMethod("assertValues");
            if (!Modifier.isProtected(m.getModifiers()))
            {
                fail(upperLevelClass.getName() + ": assertValues method is not protected.");
            }

            if (m.getReturnType() != void.class)
            {
                fail(upperLevelClass.getName() + ": assertValues method has return value");
            }


        }
        catch (Throwable t)
        {
            fail(upperLevelClass.getName() + ": enum does not have assertValues method, " + t.getMessage());
        }

        //
        // Look for static int fields with same name as enumerated elements.
        //
        int index = -1;

        // Used later to test limit enforcement of enumeration
        List<BigInteger> declaredConstants = new ArrayList<BigInteger>();

        defLoop:
        for (Element child : element.getChildren())
        {
            index++;

            if (child.getBaseType() == OERDefinition.BaseType.EXTENSION)
            {
                continue;
            }

            String itemName = child.getLabel().replace("-", "_");
            if (child.getBaseType() == OERDefinition.BaseType.EXTENSION)
            {
                continue;
            }

            if (itemName == null)
            {
                fail(String.format(upperLevelClass.getName() + ": enum item at index %i is unnamed", index));
            }

            BigInteger enumValue = BigInteger.valueOf(index);
            if (child.getEnumValue() != null)
            {
                enumValue = child.getEnumValue();
            }
            Field[] declaredFields = upperLevelClass.getDeclaredFields();
            for (Field f : declaredFields)
            {
                if (f.getName().equals(itemName))
                {
                    if (Modifier.isPublic(f.getModifiers()) &&
                        Modifier.isFinal(f.getModifiers()) && Modifier.isStatic(f.getModifiers()))
                    {
                        if (f.getType() == upperLevelClass)
                        {
                            //
                            // Assert values in class match values in definition
                            //
                            if (!((ASN1Enumerated)f.get(null)).getValue().equals(enumValue))
                            {
                                fail(upperLevelClass.getName() + ": enum const value did not match index for " + child.getLabel());
                            }

                            declaredConstants.add(((ASN1Enumerated)f.get(null)).getValue());
                        }
                        else
                        {
                            fail(upperLevelClass.getName() + ": enum const value not " + upperLevelClass.getName() + " for " + child.getLabel());
                        }
                    }
                    else
                    {
                        fail(upperLevelClass.getName() + ": enum const value field not 'public static final' for " + child.getLabel());
                    }

                    continue defLoop;
                }
            }

            fail(upperLevelClass.getName() + ": could not find static field int field for " + child.getLabel());
        }


        Constructor privateAns1Constructor = null;
        try
        {
            privateAns1Constructor = upperLevelClass.getDeclaredConstructor(ASN1Enumerated.class);

            if (!Modifier.isPrivate(privateAns1Constructor.getModifiers()))
            {
                fail(upperLevelClass.getName() + ": ASN1Enumerated accepting constructor is not private");
            }
        }
        catch (Throwable ex)
        {
            fail(upperLevelClass.getName() + ": Does not have ASN1Enumerated accepting constructor");
        }


        Constructor publicBigIntConstructor = null;

        try
        {
            publicBigIntConstructor = upperLevelClass.getDeclaredConstructor(BigInteger.class);

            if (!Modifier.isPublic(publicBigIntConstructor.getModifiers()))
            {
                fail(upperLevelClass.getName() + ": BigInteger accepting constructor is not public");
            }
        }
        catch (Throwable ex)
        {
            fail(upperLevelClass.getName() + ": Does not have BigInteger accepting constructor");
        }


        // Make private constructor accessible.
        privateAns1Constructor.setAccessible(true);


        //
        // Test enumerated
        //
        for (BigInteger i : declaredConstants)
        {
            try
            {
                privateAns1Constructor.newInstance(new ASN1Enumerated(i));
            }
            catch (Throwable t)
            {
                fail(upperLevelClass.getName() + ": private constructor failed on known constant value (ASN1Enumerated) " + i);
            }

            // test public constructor.
            try
            {
                publicBigIntConstructor.newInstance(i);
            }
            catch (Throwable t)
            {
                fail(upperLevelClass.getName() + ": public constructor failed on known constant value (BigInteger) " + i);
            }
        }


        //
        // Test enumerated rejection of out of range values.
        //
        BigInteger min = null;
        BigInteger max = null;

        for (BigInteger j : declaredConstants)
        {
            if (min == null || j.compareTo(min) < 0)
            {
                min = j;
            }
            if (max == null || j.compareTo(max) > 0)
            {
                max = j;
            }
        }

        //
        // Pass in invalid choice, one less than identified min.
        //
        try
        {
            privateAns1Constructor.newInstance(new ASN1Enumerated(min.subtract(BigInteger.ONE)));
            fail(upperLevelClass.getName() + ": should fail on unknown constant");
        }
        catch (Throwable t)
        {

            if (t instanceof InvocationTargetException)
            {
                t = ((InvocationTargetException)t).getTargetException();
            }

            if (!(t instanceof IllegalArgumentException))
            {
                fail(upperLevelClass.getName() + ": private constructor, expected IllegalArgumentException on invalid enum value supplied at ASN1Enumerated constructor (below min)");
            }

            if (min.equals(BigInteger.ZERO))
            {
                String expected = "enumerated must be non-negative";
                if (!t.getMessage().equals((expected)))
                {
                    fail(String.format(upperLevelClass.getName() + ": private constructor, expected '%s' got '%s' ", expected, t.getMessage()));
                }
            }
            else
            {
                String expected = "invalid enumeration value " + min.subtract(BigInteger.ONE);
                if (!t.getMessage().equals((expected)))
                {
                    fail(String.format(upperLevelClass.getName() + ": private constructor, expected '%s' got '%s' ", expected, t.getMessage()));
                }
            }

        }


        //
        // Pass in invalid enum, one more than identified max value.
        //
        try
        {
            privateAns1Constructor.newInstance(new ASN1Enumerated(max.add(BigInteger.ONE)));
            fail(upperLevelClass.getName() + ": private constructor, should fail on unknown constant");
        }
        catch (InvocationTargetException t)
        {

            Throwable target = t.getTargetException();
            if (!(target instanceof IllegalArgumentException))
            {
                fail(upperLevelClass.getName() + ": private constructor, expected IllegalArgumentException on invalid enum value supplied at ASN1Enumerated constructor (above max)");
            }

            String expected = "invalid enumeration value " + (max.add(BigInteger.ONE));
            if (!target.getMessage().equals((expected)))
            {
                fail(String.format(upperLevelClass.getName() + ": private constructor, expected '%s' got '%s' ", expected, target.getMessage()));
            }
        }


        // ---- Public Constructor ----

        //
        // Pass in invalid choice, one less than identified min.
        //
        try
        {
            publicBigIntConstructor.newInstance(min.subtract(BigInteger.ONE));
            fail(upperLevelClass.getName() + ": public constructor should fail on unknown constant");
        }
        catch (Throwable t)
        {

            if (t instanceof InvocationTargetException)
            {
                t = ((InvocationTargetException)t).getTargetException();
            }

            if (!(t instanceof IllegalArgumentException))
            {
                fail(upperLevelClass.getName() + ": public constructor, expected IllegalArgumentException on invalid enum value supplied at ASN1Enumerated constructor (below min)");
            }

            if (min.equals(BigInteger.ZERO))
            {
                String expected = "enumerated must be non-negative";
                if (!t.getMessage().equals((expected)))
                {
                    fail(String.format(upperLevelClass.getName() + ": public constructor, expected '%s' got '%s' ", expected, t.getMessage()));
                }
            }
            else
            {
                String expected = "invalid enumeration value " + min.subtract(BigInteger.ONE);
                if (!t.getMessage().equals((expected)))
                {
                    fail(String.format(upperLevelClass.getName() + ": public constructor, expected '%s' got '%s' ", expected, t.getMessage()));
                }
            }

        }


        //
        // Pass in invalid enum, one more than identified max value.
        //
        try
        {
            publicBigIntConstructor.newInstance(max.add(BigInteger.ONE));
            fail(upperLevelClass.getName() + ": should fail on unknown constant");
        }
        catch (InvocationTargetException t)
        {

            Throwable target = t.getTargetException();
            if (!(target instanceof IllegalArgumentException))
            {
                fail(upperLevelClass.getName() + ": public constructor, expected IllegalArgumentException on invalid enum value supplied at ASN1Enumerated constructor (above max)");
            }

            String expected = "invalid enumeration value " + (max.add(BigInteger.ONE));
            if (!target.getMessage().equals((expected)))
            {
                fail(String.format(upperLevelClass.getName() + ": public constructor, expected '%s' got '%s' ", expected, target.getMessage()));
            }
        }

    }


    public static <T> T create(Class<T> type, Element element)
        throws Exception
    {
        Object createdValue;
        if (type == byte[].class)
        {
            if (element.isFixedLength())
            {
                createdValue = new byte[element.getLowerBound().intValue()];
            }
            else if (element.isUnbounded())
            {
                createdValue = new byte[10]; // Unbounded so pick an arbitrary size.
            }
            else if (element.getLowerBound() != null && element.getUpperBound() != null)
            {
                createdValue = new byte[element.getLowerBound().intValue() + 1];
            } else
            {
                throw new IllegalArgumentException("unhandled type " + type);
            }
        }
        else if (type == String.class)
        {
            createdValue = "Test string";
        }
        else
        {
            Method getInstance = type.getMethod("getInstance", Object.class);
            createdValue = getInstance.invoke(null, OERExpander.expandElement(element).iterator().next());
        }

        return type.cast(createdValue);
    }


    private static List<Field> extractFields(Class... clasz)
        throws Exception
    {
        List<Field> fields = new ArrayList<Field>();
        for (Class c : clasz)
        {
            for (Field f : c.getFields())
            {
                if (Modifier.isFinal(f.getModifiers()) && Modifier.isStatic(f.getModifiers()))
                {
                    Object v = f.get(null);
                    if (v instanceof OERDefinition.Builder)
                    {
                        fields.add(f);
                    }
                }
                else if (Modifier.isPublic(f.getModifiers()))
                {
                    throw new IllegalStateException("Public field " + f.getName() + " that is not static final in " + f.getDeclaringClass().getName());
                }

            }
        }
        return fields;

    }


    public static void main(
        String[] args)
    {
        ExpansionTest test = new ExpansionTest();
        TestResult result = test.perform();

        System.out.println(result);
        if (result.getException() != null)
        {
            result.getException().printStackTrace();
        }
    }
}
