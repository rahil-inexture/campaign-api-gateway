package com.campaign.gateway.util;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.campaign.gateway.repository.UserAuthRepository;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultClaims;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class TokenUtil {
	
	@Autowired
	private UserAuthRepository userAuthRepository;
	
	public Claims extractAllClaims(String token) throws ParseException {
		JWT jwt = JWTParser.parse(token);
		Map<String,Object> claims=jwt.getJWTClaimsSet().getClaims();
		Claims jwtClaims = new DefaultClaims(claims);
		return jwtClaims;		
	}
	
	public boolean isTokenValid(String token) throws ParseException {
		boolean existsByAccessToken = userAuthRepository.existsByAccessToken(token);
		log.info("existsByAccessToken: "+existsByAccessToken);
		return (existsByAccessToken && !isTokenExpired(token));
	}
	
	private boolean isTokenExpired(String token) throws ParseException {
		long expiration = extractExpiration(token);
		Instant expirationInstant = Instant.ofEpochSecond(expiration);
		boolean isExpired = expirationInstant.isBefore(Instant.now());
		return isExpired;
	}
	
	public long extractExpiration(String token) throws ParseException {
		return (long) extractClaim(token, "exp");
	}
	
	public Object extractClaim(String token, String claim) throws ParseException {
		final Claims claims = extractAllClaims(token);
		return claims.get(claim, Object.class);
	}

}
