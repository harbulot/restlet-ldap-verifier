/**

Copyright (c) 2009, The University of Manchester, United Kingdom.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
 * Neither the name of the The University of Manchester nor the names of 
      its contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

  Author: Bruno Harbulot
  
 */
package uk.ac.manchester.rcs.bruno.project220;

import java.util.Properties;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.restlet.security.SecretVerifier;

/**
 * LDAP Verifier for Restlet 1.2/2.0. (Work in progress...)
 * 
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public class LdapVerifier extends SecretVerifier {
	private final String ldapServerUrl;
	private final String ldapBaseDN;

	/**
	 * @param ldapServerUrl
	 *            URL of the LDAP server, for example
	 *            <code>ldaps://ldap.example.com/</code>
	 * @param ldapBaseDN
	 *            LDAP base DN, for example <code>ou=exampleorg,o=ac,c=uk</code>
	 */
	public LdapVerifier(String ldapServerUrl, String ldapBaseDN) {
		this.ldapServerUrl = ldapServerUrl;
		this.ldapBaseDN = ldapBaseDN;
	}

	@Override
	public boolean verify(String identifier, char[] inputSecret) {
		Properties env = new Properties();
		env.put(Context.INITIAL_CONTEXT_FACTORY,
				"com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, this.ldapServerUrl);
		env.put(Context.SECURITY_AUTHENTICATION, "none");

		SearchControls searchCtrls = new SearchControls();
		searchCtrls.setReturningAttributes(new String[] {});
		searchCtrls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		String filter = "(&(cn=" + identifier + "))";

		DirContext ctx = null;
		try {
			ctx = new InitialDirContext(env);
			NamingEnumeration<SearchResult> answer = ctx.search(
					this.ldapBaseDN, filter, searchCtrls);

			String fullname = null;
			if (answer.hasMore()) {
				fullname = answer.next().getNameInNamespace();
			}

			ctx.close();
			ctx = null;

			env.put(Context.SECURITY_AUTHENTICATION, "simple");
			env.put(Context.SECURITY_PRINCIPAL, fullname);
			env.put(Context.SECURITY_CREDENTIALS, inputSecret);

			ctx = new InitialDirContext(env);
			return true;
		} catch (AuthenticationException e) {
			// TODO
		} catch (NamingException e) {
			// TODO
		} finally {
			if (ctx != null) {
				try {
					ctx.close();
				} catch (NamingException e) {
					// TODO
				}
			}
		}

		return false;
	}
}
