package org.bouncycastle.oer.test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.SwitchIndexer;
import org.bouncycastle.oer.its.etsi102941.DeltaCtl;
import org.bouncycastle.oer.its.etsi103097.extension.Extension;
import org.bouncycastle.oer.its.ieee1609dot2.ContributedExtensionBlock;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.GroupLinkageValue;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Point256;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Point384;
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
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class TestBuilders
    extends TestCase
{


    /**
     * Examine each type defined in the OER definition and ensure it has a conforming builder
     * class. Some exceptions apply.
     *
     * @throws Exception
     */
    public void testBuilderStructure()
        throws Exception
    {

        //
        // Build map of type name to class name.
        //

        HashMap<String, String[]> typeMapFlat = new HashMap<String, String[]>();
        {
            List<Field> items = extractFields(EtsiTs102941BaseTypes.class, EtsiTs102941TypesAuthorization.class, EtsiTs102941TrustLists.class, EtsiTs102941TypesAuthorizationValidation.class, EtsiTs102941TypesCaManagement.class, EtsiTs102941TypesEnrolment.class, EtsiTs102941TypesLinkCertificate.class, Ieee1609Dot2Dot1EcaEeInterface.class, Ieee1609Dot2Dot1EeRaInterface.class, EtsiTs103097ExtensionModule.class, EtsiTs103097Module.class, Ieee1609Dot2BaseTypes.class, IEEE1609dot2.class);
            for (Field f : items)
            {
                OERDefinition.Builder builder = (OERDefinition.Builder)f.get(null);
                Element def = builder.build();


                String name = getTypeName(f, def.getTypeName());
                if (typeMapFlat.containsKey(f.getName()))
                {
                    // If it is here then we probably have a duplicate definition for the same thing.
                    throw new RuntimeException("Duplicate name: " + name);
                }

                typeMapFlat.put(f.getName(), new String[]{name});
            }

        }


        typeMapFlat.put(
            OERDefinition.BaseType.OCTET_STRING.name(),
            new String[]{ASN1OctetString.class.getName(), byte[].class.getName()});

        typeMapFlat.put(
            OERDefinition.BaseType.IA5String.name(),
            new String[]{DERIA5String.class.getName(), String.class.getName()});

        typeMapFlat.put(
            OERDefinition.BaseType.UTF8_STRING.name(),
            new String[]{DERUTF8String.class.getName(), String.class.getName()});

        typeMapFlat.put(
            OERDefinition.BaseType.INT.name(),
            new String[]{ASN1Integer.class.getName()});

        typeMapFlat.put(
            OERDefinition.BaseType.NULL.name(),
            new String[]{DERNull.class.getName()});

        typeMapFlat.put(
            OERDefinition.BaseType.BOOLEAN.name(),
            new String[]{ASN1Boolean.class.getName()});

        typeMapFlat.put(OERDefinition.BaseType.Switch.name(), new String[]{ASN1Encodable.class.getName()});

        HashMap<Class, Runnable> specificTesters = new HashMap<Class, Runnable>();

        loadSpecificTesters(specificTesters);


        List<Field> items = extractFields(EtsiTs102941TypesAuthorization.class, EtsiTs102941TrustLists.class, EtsiTs102941TypesAuthorizationValidation.class, EtsiTs102941TypesCaManagement.class, EtsiTs102941TypesEnrolment.class, EtsiTs102941TypesLinkCertificate.class, Ieee1609Dot2Dot1EcaEeInterface.class, Ieee1609Dot2Dot1EeRaInterface.class, EtsiTs103097ExtensionModule.class, EtsiTs103097Module.class, Ieee1609Dot2BaseTypes.class, IEEE1609dot2.class);
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
            // Resolve upper level class.
            //
            String name = def.getTypeName(); //  f.getName();
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
                return;
            }


            if (upperLevelClass == Extension.class || upperLevelClass == ContributedExtensionBlock.class)
            {
                // Does not have a builder, more like a choice.
                continue;
            }


            if (def.getBaseType() == OERDefinition.BaseType.CHOICE)
            {
                handleChoice(typeMapFlat, def, upperLevelClassName, upperLevelClass);
            }
            else if (def.getBaseType() == OERDefinition.BaseType.ENUM)
            {
                // Building is by a static instance per enum option.
                // This is enforced in the Extension test.
            }
            else if (def.getBaseType() == OERDefinition.BaseType.SEQ)
            {
                if (!ASN1Object.class.isAssignableFrom(upperLevelClass))
                {
                    fail(upperLevelClassName + " is not instance of ASN1Object");
                }

                //
                // Find public static Builder  builder() {}
                // method.
                //
                Method builderStaticMethod;

                try
                {
                    builderStaticMethod = upperLevelClass.getMethod("builder");
                }
                catch (Exception ex)
                {
                    throw new RuntimeException("Finding static builder() method on " + upperLevelClassName + " " + f, ex);
                }

                // Check public static
                if (!Modifier.isStatic(builderStaticMethod.getModifiers()) ||
                    !Modifier.isPublic(builderStaticMethod.getModifiers())
                )
                {
                    throw new RuntimeException("static builder method should be public static: " + upperLevelClassName);
                }

                Object builderObject = builderStaticMethod.invoke(null);
                Class builderClass = builderObject.getClass();


                if (builderObject == null)
                {
                    throw new RuntimeException("builder method returned null: " + upperLevelClassName);
                }

                // Does builder class have a build method that returns a class
                // that is either the type in question or matched a constructor of the type being examined.

                Method builderBuildMethod = null;
                String className = upperLevelClassName.substring(upperLevelClassName.lastIndexOf(".") + 1);
                String expectedMethodName = "create" + (className.toUpperCase().charAt(0)) + className.substring(1);

                try
                {
                    builderBuildMethod = builderObject.getClass().getMethod(expectedMethodName);
                }
                catch (Exception ex)
                {
                    // Ignored.
                }

                if (builderBuildMethod == null)
                {
                    throw new RuntimeException(builderObject.getClass().getName() + " does not have a build method " + expectedMethodName);
                }

                Class builderReturnType = builderBuildMethod.getReturnType();


                //
                // Do specific testing if the class requires it.
                //
                if (specificTesters.containsKey(upperLevelClass))
                {
                    specificTesters.get(upperLevelClass).run();

                }


                for (Element option : def.getChildren())
                {
                    //
                    // EXTENSTION is used as a marker when the type defines the possibility of an extension
                    // but does not actually define any extensions.
                    //
                    if (option.getBaseType() == OERDefinition.BaseType.EXTENSION)
                    {
                        continue;
                    }

                    Field field = null;
                    Class target = upperLevelClass;
                    do
                    {
                        try
                        {
                            field = target.getDeclaredField(option.getLabel());
                        }
                        catch (NoSuchFieldException nfe)
                        {
                            //
                            // Field may be declared in super class.
                            //
                            target = target.getSuperclass();
                        }
                    }
                    while (field == null && target != null);

                    if (target == null)
                    {
                        throw new RuntimeException("could not find field " + option.getLabel() + "  in " + upperLevelClass.getSimpleName() + " or in ancestors");
                    }

                    int mod = field.getModifiers();
                    if ((Modifier.isFinal(mod) && (Modifier.isProtected(mod) || Modifier.isPrivate(mod))))
                    {
                        List<Element> expandedOptions = new ArrayList<Element>();
                        if (option.getBaseType() == OERDefinition.BaseType.Switch)
                        {
                            for (ASN1Encodable item : option.getaSwitch().keys())
                            {
                                expandedOptions.add(option.getaSwitch().result(new SwitchIndexer.FixedValueIndexer(item)));
                            }
                        }
                        else
                        {
                            expandedOptions.add(option);
                        }

                        HashMap<String, Boolean> dups = new HashMap<String, Boolean>();
                        for (Element expanded : expandedOptions)
                        {
                            if (dups.containsKey(expanded.getLabel()))
                            {
                                dups.put(expanded.getLabel(), true);
                            }
                            else
                            {
                                dups.put(expanded.getLabel(), false);
                            }
                        }


                        for (Element expandedOption : expandedOptions)
                        {
                            if (expandedOption.getElementSupplier() != null) {
                                expandedOption = expandedOption.getElementSupplier().build();
                            }

                            // Look for appropriate setter type method in builder
                            for (String typeName : typeMapFlat.get(expandedOption.getDerivedTypeName()))
                            {
                                String l = expandedOption.getLabel();

                                if (upperLevelClass == DeltaCtl.class && l.equalsIgnoreCase("isFullCtl"))
                                {
                                    continue;
                                }


                                String setter;

                                if (dups.get(l))
                                {
                                    l = typeName.substring(typeName.lastIndexOf(".") + 1);
                                    setter = "set" + l.toUpperCase().charAt(0) + l.substring(1);
                                }
                                else
                                {
                                    setter = "set" + l.toUpperCase().charAt(0) + l.substring(1);
                                }

                                Class setterParam = Class.forName(typeName);

                                Method setterMethod;
                                if (setterParam.equals(DERNull.class))
                                {
                                    try
                                    {
                                        setterMethod = builderClass.getMethod(setter);
                                    }
                                    catch (Exception ex)
                                    {
                                        System.out.println("Missing from builder:");
                                        System.out.println(String.format("public Builder %s(){}", setter));
                                        System.out.println();

                                        throw new RuntimeException(upperLevelClass.getName() + " builder does not have " + setter);
                                    }
                                }
                                else
                                {
                                    try
                                    {
                                        setterMethod = builderClass.getMethod(setter, Class.forName(typeName));
                                    }
                                    catch (Exception ex)
                                    {

                                        System.out.println("Missing from builder:");
                                        System.out.println(String.format("public Builder %s(%s value){}", setter, typeName));
                                        System.out.println();

                                        throw new RuntimeException(upperLevelClass.getName() + " builder does not have " + setter);
                                    }
                                }
                                // Setter returns instance of builder

                                if (setterMethod.getReturnType() != builderClass)
                                {
                                    throw new RuntimeException(setter + " on " + builderReturnType.getName() + " does not return builder type");
                                }

                                //
                                // Set value on setter.
                                //
                                Object param;
                                if (setterParam.equals(DERNull.class))
                                {
                                    param = DERNull.INSTANCE;
                                    setterMethod.invoke(builderObject);
                                }
                                else
                                {
                                    param = ExpansionTest.create(setterParam, expandedOption);
                                    setterMethod.invoke(builderObject, param);
                                }
                                //
                                // Build an instance with that value set.
                                // Check it is actually set.
                                //


                                if (specificTesters.containsKey(upperLevelClass))
                                {
                                    // We skip these as there is some specific testing that
                                    // cannot be simply done with reflection.
                                    continue;
                                }
                                else
                                {
                                    Object builtInstance = builderBuildMethod.invoke(builderObject);
                                    String getterName = "get" + l.toUpperCase().charAt(0) + l.substring(1);
                                    Method getter = builtInstance.getClass().getMethod(getterName);
                                    Object value = getter.invoke(builtInstance);

                                    if (param instanceof byte[])
                                    {
                                        param = new DEROctetString((byte[])param);
                                    }
                                    else if (param instanceof String)
                                    {
                                        if (option.getBaseType() == OERDefinition.BaseType.IA5String)
                                        {
                                            param = new DERIA5String((String)param);
                                        }
                                        else if (option.getBaseType() == OERDefinition.BaseType.UTF8_STRING)
                                        {
                                            param = new DERUTF8String((String)param);
                                        }
                                        else
                                        {
                                            throw new IllegalArgumentException("unhandled string type in builder set return test.");
                                        }
                                    }

                                    if (value == null || !value.equals(param))
                                    {
                                        throw new RuntimeException("value did not match ");
                                    }
                                }
                            }
                        }
                    }
                }
            }

        }

    }

    private void loadSpecificTesters(HashMap<Class, Runnable> specificTesters)
    {
        specificTesters.put(Point256.class, new Runnable()
        {
            public void run()
            {
                try
                {
                    Point256.builder().setY(new DEROctetString(new byte[32])).createPoint256();
                    fail("expected exception");
                }
                catch (Exception ignored)
                {
                }
                try
                {
                    Point256.builder().setX(new DEROctetString(new byte[32])).createPoint256();
                    fail("expected exception");
                }
                catch (Exception ignored)
                {
                }

                try
                {
                    Point256.builder().setY(new DEROctetString(new byte[31])).createPoint256();
                    fail("expected exception");
                }
                catch (Exception ignored)
                {
                }

                try
                {
                    Point256.builder().setX(new DEROctetString(new byte[31])).createPoint256();
                    fail("expected exception");
                }
                catch (Exception ignored)
                {
                }

                Point256.builder().setX(new DEROctetString(new byte[32])).setY(new DEROctetString(
                    new byte[32]
                )).createPoint256();
            }
        });


        specificTesters.put(Point384.class, new Runnable()
        {
            public void run()
            {
                try
                {
                    Point384.builder().setY(new DEROctetString(new byte[48])).createPoint384();
                    fail("expected exception");
                }
                catch (Exception ignored)
                {
                }
                try
                {
                    Point384.builder().setX(new DEROctetString(new byte[48])).createPoint384();
                    fail("expected exception");
                }
                catch (Exception ignored)
                {
                }

                try
                {
                    Point384.builder().setY(new DEROctetString(new byte[47])).createPoint384();
                    fail("expected exception");
                }
                catch (Exception ignored)
                {
                }

                try
                {
                    Point384.builder().setX(new DEROctetString(new byte[47])).createPoint384();
                    fail("expected exception");
                }
                catch (Exception ignored)
                {
                }

                Point384.builder().setX(new DEROctetString(new byte[48])).setY(new DEROctetString(
                    new byte[48]
                )).createPoint384();
            }
        });


        specificTesters.put(GroupLinkageValue.class, new Runnable()
        {
            public void run()
            {
                try
                {
                    GroupLinkageValue.builder().createGroupLinkageValue();
                    throw new RuntimeException("should fail");
                }
                catch (IllegalArgumentException ilex)
                {

                }

                try
                {
                    GroupLinkageValue.builder().setJValue(new byte[5]).setValue(new byte[9]).createGroupLinkageValue();
                    throw new RuntimeException("should fail");
                }
                catch (IllegalArgumentException ilex)
                {

                }

                try
                {
                    GroupLinkageValue.builder().setJValue(new byte[4]).setValue(new byte[7]).createGroupLinkageValue();
                    throw new RuntimeException("should fail");
                }
                catch (IllegalArgumentException ilex)
                {

                }


                GroupLinkageValue.builder().setJValue(new byte[4]).setValue(new byte[9]).createGroupLinkageValue();


            }
        });

    }

    private void handleChoice(HashMap<String, String[]> typeMapFlat, Element def, String upperLevelClassName, Class upperLevelClass)
        throws Exception
    {

        if (!ASN1Choice.class.isAssignableFrom(upperLevelClass))
        {
            fail(upperLevelClassName + " is not instance of ASN1Choice");
        }

        printMissingChoiceMethods(typeMapFlat, upperLevelClass, def);

        for (Element options : def.getChildren())
        {

            if (options.getBaseType() == OERDefinition.BaseType.EXTENSION)
            {
                continue;
            }

            String label = options.getLabel().replace("-", "");
//            label = cleanLabel(label,false);

            Field field = null;

            // Caseless field search.
            for (Field f : upperLevelClass.getFields())
            {
                if (f.getName().equalsIgnoreCase(label))
                {
                    field = f;
                    break;
                }
            }

            // check for Option field, eg public static final int name = 0;
            if (field == null)
            {
                throw new RuntimeException(
                    upperLevelClass.getName() + " could not find field " + label);
            }

            int mod = field.getModifiers();
            if (Modifier.isFinal(mod) && Modifier.isStatic(mod) && Modifier.isPublic(mod))
            {

                if (options.getElementSupplier() != null) {
                    options = options.getElementSupplier().build();
                }

                String[] expectedTypes = typeMapFlat.get(options.getDerivedTypeName());

                for (String expectedType : expectedTypes)
                {

                    //
                    // Test for creator method's single parameter type.
                    //
                    Class expectedParamType;
                    try
                    {
                        expectedParamType = Class.forName(expectedType);
                    }
                    catch (Exception ex)
                    {
                        throw new RuntimeException("Resolving static creator single param type: " + options.getTypeName() + " for " + upperLevelClassName, ex);
                    }

                    //
                    //  Look for static method that creates the choice but for that value.
                    // eg public static MyChoice theOption(TheOption value)
                    //
                    Method creator = null;

                    if (expectedParamType.equals(DERNull.class))
                    {
                        for (Method m : upperLevelClass.getMethods())
                        {
                            if (m.getParameterTypes().length == 0)
                            {
                                if (m.getName().equalsIgnoreCase(label))
                                {
                                    creator = m;
                                    break;
                                }
                            }
                        }
                    }
                    else
                    {
                        for (Method m : upperLevelClass.getMethods())
                        {
                            if (m.getParameterTypes().length == 1 && m.getParameterTypes()[0] == expectedParamType)
                            {
                                if (m.getName().equalsIgnoreCase(label))
                                {
                                    creator = m;
                                    break;
                                }
                            }
                        }
                    }

                    if (creator == null)
                    {
                        System.out.println("Expected:");

                        if (expectedParamType.equals(DERNull.class))
                        {
                            System.out.println("public static " + upperLevelClassName + " " + label + "()\n{\n}\n");

                        }
                        else
                        {
                            System.out.println("public static " + upperLevelClassName + " " + label + "(" + expectedParamType.getName() + ")\n{\n}\n");
                        }
                        throw new RuntimeException("Resolving static creator method with single param: " + label + " for " + upperLevelClassName);
                    }

                    //label = cleanLabel(options.getLabel());
//                    try
//                    {
//                        creator = upperLevelClass.getMethod(label, expectedParamType);
//                    }
//                    catch (Exception ex)
//                    {
//                        System.out.println("Expected:");
//                        System.out.println("public static " + upperLevelClassName + " " + label + "(" + expectedParamType.getName() + ")\n{\n}\n");
//
//                        throw new RuntimeException("Resolving static creator method with single param: " + label + " for " + upperLevelClassName, ex);
//                    }

                    //
                    // Find the getter for the set value.
                    //

                    Method getter = null;
                    String className = upperLevelClass.getName().substring(upperLevelClass.getName().lastIndexOf(".") + 1).toLowerCase();
                    for (Method m : upperLevelClass.getMethods())
                    {
                        String methodName = m.getName().substring(m.getName().lastIndexOf(".") + 1).toLowerCase();
                        if (methodName.equalsIgnoreCase("get" + className))
                        {
                            getter = m;
                            break;
                        }
                    }

                    if (getter == null)
                    {
                        throw new RuntimeException(String.format("unable to find value getter for %s", upperLevelClassName));
                    }


                    //
                    // Invoke the creator..
                    //

                    Object param;
                    Object choice;

                    if (expectedParamType.equals(DERNull.class))
                    {
                        param = DERNull.INSTANCE;
                        choice = creator.invoke(null);
                    }
                    else
                    {
                        param = ExpansionTest.create(expectedParamType, options);
                        choice = creator.invoke(null, param);
                    }
                    if (choice.getClass() != upperLevelClass)
                    {
                        throw new RuntimeException("Got incorrect return type for " + creator);
                    }

                    Object setValue = null;
                    try
                    {
                        setValue = getter.invoke(choice);
                    }
                    catch (IllegalArgumentException argumentException)
                    {
                        throw new RuntimeException(getter.getName() + " " + argumentException.getMessage(), argumentException);
                    }
                    if (param instanceof byte[])
                    {

                        //
                        // special case for passed in byte array.
                        //
                        if (!Arrays.areEqual(ASN1OctetString.getInstance(setValue).getOctets(), (byte[])param))
                        {
                            throw new RuntimeException("set value did not equal param");
                        }
                    }
                    else
                    {
                        if (!setValue.equals(param))
                        {
                            throw new RuntimeException("set value did not equal param");
                        }
                    }

                }

            }
            else
            {
                fail("expected choice constant " + options.getLabel() + " in " + upperLevelClassName);
            }


        }
    }


    private static void printMissingChoiceMethods(HashMap<String, String[]> typeMapFlat, Class upperLevelClass, Element def)
    {


        for (Element options : def.getChildren())
        {

            if (options.getBaseType() == OERDefinition.BaseType.EXTENSION)
            {
                continue;
            }

            String label = options.getLabel().replace("-", "");
//            label = cleanLabel(label,false);

            Field field = null;

            // Caseless field search.
            for (Field f : upperLevelClass.getFields())
            {
                if (f.getName().equalsIgnoreCase(label))
                {
                    field = f;
                    break;
                }
            }

            // check for Option field, eg public static final int name = 0;
            if (field == null)
            {
                continue;
            }

            int mod = field.getModifiers();
            if (Modifier.isFinal(mod) && Modifier.isStatic(mod) && Modifier.isPublic(mod))
            {

                if (options.getElementSupplier() != null)
                {
                    options = options.getElementSupplier().build();
                }

                String[] expectedTypes = typeMapFlat.get(options.getDerivedTypeName());

                for (String expectedType : expectedTypes)
                {

                    //
                    // Test for creator method's single parameter type.
                    //
                    Class expectedParamType;
                    try
                    {
                        expectedParamType = Class.forName(expectedType);
                    }
                    catch (Exception ex)
                    {
                        continue;
                    }

                    //
                    //  Look for static method that creates the choice but for that value.
                    // eg public static MyChoice theOption(TheOption value)
                    //
                    Method creator = null;

                    if (expectedParamType.equals(DERNull.class))
                    {
                        for (Method m : upperLevelClass.getMethods())
                        {
                            if (m.getParameterTypes().length == 0)
                            {
                                if (m.getName().equalsIgnoreCase(label))
                                {
                                    creator = m;
                                    break;
                                }
                            }
                        }
                    }
                    else
                    {
                        for (Method m : upperLevelClass.getMethods())
                        {
                            if (m.getParameterTypes().length == 1 && m.getParameterTypes()[0] == expectedParamType)
                            {
                                if (m.getName().equalsIgnoreCase(label))
                                {
                                    creator = m;
                                    break;
                                }
                            }
                        }
                    }

                    String clName = upperLevelClass.getName();
                    if (clName.lastIndexOf(".") > -1)
                    {
                        clName = clName.substring(clName.lastIndexOf(".") + 1);
                    }


                    if (creator == null)
                    {
                        if (expectedParamType.equals(DERNull.class))
                        {
                            System.out.println("public static " + clName + " " + label + "()\n{\n" +
                                "return new " + clName + "(" + clName + "." + label + ", DERNull.INSTANCE);\n" +
                                "}\n");

                        }
                        else
                        {

                            String exName = expectedParamType.getName();
                            if (exName.lastIndexOf(".") > 0)
                            {
                                exName = exName.substring(exName.lastIndexOf(".") + 1);
                            }

                            System.out.println("public static " + clName + " " + label + "(" + exName + " " + label + ")\n{\n" +
                                "return new " + clName + "(" + clName + "." + label + "," + label + " );\n" +
                                "}\n");
                        }

                    }


                }
            }
        }


    }


    private static Method findMethodEndsWithIgnoreCase(Class cl, String name)
    {
        for (Method m : cl.getMethods())
        {
            if (Strings.toLowerCase(m.getName()).endsWith(name))
            {
                return m;
            }
        }
        return null;
    }


    /*
       Class builderClass = null;
                //
                // Look for builder class.
                //
                String builderClassName = upperLevelClassName + ".Builder";
                builderClass = Class.forName(builderClassName);

                //
                // Look for builder() static method.
                //

                Method builderMethod = upperLevelClass.getMethod("builder");
                if (!Modifier.isPublic(builderMethod.getModifiers()) || !Modifier.isStatic(builderMethod.getModifiers())) {
                    fail(upperLevelClassName+" builder() method is not public static");
                }

                //
                // Does it actually return an instance
                //

                Object j =  builderMethod.invoke(null);
                if (builderClass != j) {
                    fail("builder() method did not return instance of "+upperLevelClassName+".Builder");
                }

     */


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


    private static String getTypeName(Field f, String name)
    {
        if (name == null)
        {
            name = f.getName();
        }
        String pack = f.getDeclaringClass().getPackage().getName();
        pack = pack.replace("template.", "");
        String upperLevelClassName = (pack + "." + name).replace("/", ".");
        try
        {
            Class.forName(upperLevelClassName);
        }
        catch (Throwable ex)
        {
            if (ex instanceof ExceptionInInitializerError)
            {
                ex = ((ExceptionInInitializerError)ex).getException();
            }
            fail("unable to load " + upperLevelClassName + " " + ex.getMessage());

        }
        return upperLevelClassName;
    }

}
