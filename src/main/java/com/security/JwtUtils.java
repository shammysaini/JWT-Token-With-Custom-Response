package com.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;


@Component
@Slf4j
public class JwtUtils {

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration}")
	private long expiration;



	private SecretKey getSigningKey() {
		return Keys.hmacShaKeyFor(secret.getBytes());
	}

	public String generateToken(Authentication authentication, String username) {
		log.info("calling generateToken method {}",authentication);

		return Jwts.builder()
				.subject(username)
				.issuedAt(new Date())
				.expiration(new Date(System.currentTimeMillis() + expiration))
				.signWith(getSigningKey()) // ✅ No need to pass `SignatureAlgorithm`
				.compact();
	}
	public String getUsernameFromToken(String token) {
		return getClaims(token).getSubject();
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parser()
					.verifyWith(getSigningKey()) // ✅ New method replacing `setSigningKey()`
					.build()
					.parseSignedClaims(token);
			return true;
		} catch (JwtException e) {
			log.error("Invalid JWT Token: {}", e.getMessage());
			return false;
		}
	}

	public String extractToken(HttpServletRequest request) {
		String header = request.getHeader("Authorization");
		if (header != null && header.startsWith("Bearer ")) {
			return header.substring(7);
		}
		return null;
	}

	private Claims getClaims(String token) {
		return Jwts.parser()
				.verifyWith(getSigningKey()) // ✅ Updated method
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}


}