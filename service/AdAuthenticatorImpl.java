package com.ntt.myzone.service;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.springframework.stereotype.Service;

import com.ntt.myzone.model.AuthResponse;
import com.ntt.myzone.model.UserInfo;


@Service
public class AdAuthenticatorImpl implements AdAuthenticator {

	private String domain;
	private String ldapHost;
	private String searchBase;

	public AdAuthenticatorImpl() {
		this.domain = "AU";
		this.ldapHost = "ldap://aumcpsvpdc01:389";
		this.searchBase = "DC=au,DC=didata,DC=local"; // YOUR SEARCH BASE IN
														// LDAP
	}

	public AdAuthenticatorImpl(String domain, String host, String dn) {
		this.domain = domain;
		this.ldapHost = host;
		this.searchBase = dn;
	}

	@Override
	public Map<String, Object> ldapAuthenticate(String user, String pass) {
		System.out.println(user + "\t" + pass);
		String returnedAtts[] = { "sn", "givenName", "name", "userPrincipalName", "displayName", "memberOf" };
		String searchFilter = "(&(objectClass=user)(sAMAccountName=" + user + "))";

		// Create the search controls
		SearchControls searchCtls = new SearchControls();
		searchCtls.setReturningAttributes(returnedAtts);

		// Specify the search scope
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapHost);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PRINCIPAL, user + "@" + domain);
		env.put(Context.SECURITY_CREDENTIALS, pass);

		LdapContext ctxGC = null;

		try {

			// This is the actual Authentication piece. Will throw
			// javax.naming.AuthenticationException
			// if the users password is not correct. Other exceptions may
			// include IO (server
			// not found) etc.
			ctxGC = new InitialLdapContext(env, null);

			// Now try a simple search and get some attributes as defined in
			// returnedAtts
			NamingEnumeration<SearchResult> answer = ctxGC.search(searchBase, searchFilter, searchCtls);
			while (answer.hasMoreElements()) {
				SearchResult sr = (SearchResult) answer.next();
				Attributes attrs = sr.getAttributes();
				Map<String, Object> amap = null;
				if (attrs != null) {
					amap = new HashMap<String, Object>();
					NamingEnumeration<?> ne = attrs.getAll();
					while (ne.hasMore()) {
						Attribute attr = (Attribute) ne.next();
						if (attr.size() == 1) {
							amap.put(attr.getID(), attr.get());
						} else {
							HashSet<String> s = new HashSet<String>();
							NamingEnumeration n = attr.getAll();
							while (n.hasMoreElements()) {
								s.add((String) n.nextElement());
							}
							amap.put(attr.getID(), s);
						}
					}
					ne.close();
				}
				ctxGC.close(); // Close and clean up
				return amap;
			}
		} catch (NamingException nex) {
			nex.printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	@Override
	public AuthResponse ldapAuthenticate(UserInfo userInfo) {

		System.out.println("Testing good password...");
		Map<String, Object> attrs = ldapAuthenticate(userInfo.getUserName(), userInfo.getPassword());

		AuthResponse authResponse = new AuthResponse();
		if (attrs != null) {
			for (String attrKey : attrs.keySet()) {
				if (attrs.get(attrKey) instanceof String) {
					System.out.println(attrKey + ": " + attrs.get(attrKey));
				} else {
					System.out.println(attrKey + ": (Multiple Values)");
					for (Object o : (HashSet) attrs.get(attrKey)) {
						System.out.println("\t value: " + o);
					}
				}
			}
			authResponse.setResponse("true");
			return authResponse;
		} else {
			System.out.println("Attributes are null!");
			authResponse.setResponse("false");
			return authResponse;
		}
	}

}
