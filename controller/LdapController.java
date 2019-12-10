package com.ntt.myzone.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.ntt.myzone.model.AuthResponse;
import com.ntt.myzone.model.UserInfo;
import com.ntt.myzone.service.AdAuthenticator;

@RestController
@RequestMapping(path = "/Ldap")

public class LdapController {

	@Autowired
	private AdAuthenticator adAuthenticatorImpl;

	@RequestMapping(path = "/authenticate", method = RequestMethod.POST)
	public AuthResponse ldapAuthenticate(@RequestBody UserInfo userInfo) {
		System.out.println("================>" +userInfo.getUserName());
		return adAuthenticatorImpl.ldapAuthenticate(userInfo);
	}

}
