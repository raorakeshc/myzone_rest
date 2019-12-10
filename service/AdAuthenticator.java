package com.ntt.myzone.service;

import java.util.Map;

import com.ntt.myzone.model.AuthResponse;
import com.ntt.myzone.model.UserInfo;

public interface AdAuthenticator {

	Map<String, Object> ldapAuthenticate(String userName, String password);

	AuthResponse ldapAuthenticate(UserInfo userInfo);

}
