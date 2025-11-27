package com.posgrado.intranet.common.utils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.posgrado.intranet.common.config.CustomUserDetails;
import com.posgrado.intranet.common.properties.JwtProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtUtil {
  private final JwtProperties jwtProperties;

  private SecretKey getSecretKey() {
    return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
  }

  public String generateAccessToken(Authentication authentication, String jti) {
    CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
    List<String> roles = userDetails.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.toList());
    return Jwts.builder()
        .subject(userDetails.getUsername())
        .claim("carrera", userDetails.getCarrera())
        .claim("especialidad", userDetails.getEspecialidad())
        .claim("curricula", userDetails.getCurricula())
        .claim("roles", roles)
        .claim("jti", jti)
        .issuedAt(Date.from(Instant.now()))
        .expiration(Date.from(Instant.now().plus(jwtProperties.getAccessExpiration(), ChronoUnit.MILLIS)))
        .signWith(getSecretKey())
        .compact();
  }

  public String generateRefreshToken(String username) {
    String jti = UUID.randomUUID().toString();
    return Jwts.builder()
        .subject(username)
        .claim("type", "refresh")
        .claim("jti", jti)
        .issuedAt(Date.from(Instant.now()))
        .expiration(Date.from(Instant.now().plus(jwtProperties.getRefreshExpiration(), ChronoUnit.MILLIS)))
        .signWith(getSecretKey())
        .compact();
  }

  public String generatePassResetToken(String username) {
    return Jwts.builder()
        .subject(username)
        .issuedAt(Date.from(Instant.now()))
        .expiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
        .signWith(getSecretKey())
        .compact();
  }

  public Claims getClaimsFromToken(String token) {
    return Jwts.parser().verifyWith(getSecretKey()).build().parseSignedClaims(token).getPayload();
  }

  public Claims getClaimsFromExpiredToken(String token) {
    try {
      return Jwts.parser().verifyWith(getSecretKey()).build().parseSignedClaims(token).getPayload();
    } catch (ExpiredJwtException e) {
      return e.getClaims();
    }
  }

  public String getUsernameFromToken(String token) {
    return getClaimsFromToken(token).getSubject();
  }

  public String getCarreraFromToken(String token) {
    return getClaimsFromToken(token).get("carrera", String.class);
  }

  public String getEspecialidadFromToken(String token) {
    return getClaimsFromToken(token).get("especialidad", String.class);
  }

  public Integer getCurriculaFromToken(String token) {
    return getClaimsFromToken(token).get("curricula", Integer.class);
  }

  public List<String> getRolesFromToken(String token) {
    List<?> rawRoles = getClaimsFromToken(token).get("roles", List.class);
    List<String> roles = rawRoles.stream().map(Object::toString).collect(Collectors.toList());
    return roles;
  }

  public String getJtiFromToken(String token) {
    return getClaimsFromExpiredToken(token).get("jti", String.class);
  }

  public boolean validateToken(String token) {
    try {
      getClaimsFromToken(token);
      return true;
    } catch (MalformedJwtException e) {
      log.error("JWT token malformado: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      log.error("JWT token expirado: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      log.error("JWT token no soportado: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      log.error("JWT claims vacío: {}", e.getMessage());
    }
    return false;
  }

  public boolean validateExpiredToken(String token) {
    try {
      getClaimsFromToken(token);
      return true;
    } catch (MalformedJwtException e) {
      log.error("JWT token malformado: {}", e.getMessage());
      return false;
    } catch (ExpiredJwtException e) {
      return true;
    } catch (UnsupportedJwtException e) {
      log.error("JWT token no soportado: {}", e.getMessage());
      return false;
    } catch (IllegalArgumentException e) {
      log.error("JWT claims vacío: {}", e.getMessage());
      return false;
    }
  }

  public boolean isRefreshToken(String token) {
    try {
      String type = getClaimsFromToken(token).get("type", String.class);
      return "refresh".equals(type);
    } catch (Exception e) {
      return false;
    }
  }

  public boolean compareJti(String accessToken, String refreshToken) {
    String accessTokenJti = getJtiFromToken(accessToken);
    String refreshTokenJti = getJtiFromToken(refreshToken);
    return accessTokenJti == refreshTokenJti;
  }

  public String getAccessTokenFromRequest(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");
    if (StringUtils.hasText(bearerToken) && bearerToken != null && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7);
    }
    return null;
  }
}
