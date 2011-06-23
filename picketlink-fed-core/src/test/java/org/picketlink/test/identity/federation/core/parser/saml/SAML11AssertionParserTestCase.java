/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketlink.test.identity.federation.core.parser.saml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.InputStream;
import java.net.URI;

import org.junit.Test;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AssertionType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AuthenticationStatementType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11ConditionsType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11SubjectConfirmationType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11SubjectType;

/**
 * Unit Test the parsing of SAML 1.1 assertion
 * @author Anil.Saldhana@redhat.com
 * @since Jun 21, 2011
 */
public class SAML11AssertionParserTestCase
{
   @Test
   public void testSAML11Assertion() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream configStream = tcl.getResourceAsStream("parser/saml1/saml1-assertion.xml");

      SAMLParser parser = new SAMLParser();
      SAML11AssertionType assertion = (SAML11AssertionType) parser.parse(configStream);
      assertNotNull(assertion);

      //Validate assertion
      assertEquals(1, assertion.getMajorVersion());
      assertEquals(1, assertion.getMinorVersion());
      assertEquals("buGxcG4gILg5NlocyLccDz6iXrUa", assertion.getID());
      assertEquals("https://idp.example.org/saml", assertion.getIssuer());
      assertEquals(XMLTimeUtil.parse("2002-06-19T17:05:37.795Z"), assertion.getIssueInstant());

      SAML11ConditionsType conditions = assertion.getConditions();
      assertEquals(XMLTimeUtil.parse("2002-06-19T17:00:37.795Z"), conditions.getNotBefore());
      assertEquals(XMLTimeUtil.parse("2002-06-19T17:10:37.795Z"), conditions.getNotOnOrAfter());

      SAML11AuthenticationStatementType stat = (SAML11AuthenticationStatementType) assertion.getStatements().get(0);
      assertEquals("urn:oasis:names:tc:SAML:1.0:am:password", stat.getAuthenticationMethod().toString());
      assertEquals(XMLTimeUtil.parse("2002-06-19T17:05:17.706Z"), stat.getAuthenticationInstant());

      SAML11SubjectType subject = stat.getSubject();
      SAML11SubjectType.SAML11SubjectTypeChoice choice = subject.getChoice();
      assertEquals("user@idp.example.org", choice.getNameID().getNameQualifier());
      assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", choice.getNameID().getFormat().toString());

      SAML11SubjectConfirmationType subjectConfirm = subject.getSubjectConfirmation();
      URI confirmationMethod = subjectConfirm.getConfirmationMethod().get(0);
      assertEquals("urn:oasis:names:tc:SAML:1.0:cm:bearer", confirmationMethod.toString());
   }
}