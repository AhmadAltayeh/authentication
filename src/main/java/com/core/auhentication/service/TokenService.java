package com.core.auhentication.service;

import java.util.Map;

public interface TokenService {

    String generateToken(Map<String,Object> claims, String userName);

    Boolean isTokenValid(String token);

    String refreshToken(String token);
}
