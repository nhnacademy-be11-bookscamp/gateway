package store.bookscamp.gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;

    private final String secretKeyStr = "test-secret-key-must-be-at-least-32-chars-long-12345";
    private SecretKey secretKey;

    @BeforeEach
    void setUp() {
        jwtTokenProvider = new JwtTokenProvider(secretKeyStr);
        secretKey = Keys.hmacShaKeyFor(secretKeyStr.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("유효한 토큰에서 Claims를 정상적으로 추출한다")
    void getClaims_Success() {
        Long memberId = 1L;
        String role = "ROLE_USER";
        String token = Jwts.builder()
                .claim("id", memberId)
                .claim("role", role)
                .signWith(secretKey)
                .compact();

        Claims claims = jwtTokenProvider.getClaims(token);

        assertThat(claims.get("id", Long.class)).isEqualTo(memberId);
        assertThat(claims.get("role", String.class)).isEqualTo(role);
    }

    @Test
    @DisplayName("잘못된 서명 키로 만들어진 토큰은 예외를 발생시킨다")
    void getClaims_Invalid_Signature() {
        String otherKeyStr = "another-secret-key-must-be-at-least-32-chars-long-54321";
        SecretKey otherKey = Keys.hmacShaKeyFor(otherKeyStr.getBytes(StandardCharsets.UTF_8));

        String invalidToken = Jwts.builder()
                .claim("id", 1L)
                .signWith(otherKey)
                .compact();

        assertThatThrownBy(() -> jwtTokenProvider.getClaims(invalidToken))
                .isInstanceOf(io.jsonwebtoken.security.SignatureException.class);
    }

    @Test
    @DisplayName("만료된 토큰은 예외를 발생시킨다")
    void getClaims_Expired() {
        String expiredToken = Jwts.builder()
                .claim("id", 1L)
                .setExpiration(new Date(System.currentTimeMillis() - 1000))
                .signWith(secretKey)
                .compact();

        assertThatThrownBy(() -> jwtTokenProvider.getClaims(expiredToken))
                .isInstanceOf(io.jsonwebtoken.ExpiredJwtException.class);
    }

    @Test
    @DisplayName("형식이 잘못된 토큰(Malformed)은 예외를 발생시킨다")
    void getClaims_Malformed() {
        String malformedToken = "this.is.not.a.valid.jwt";

        assertThatThrownBy(() -> jwtTokenProvider.getClaims(malformedToken))
                .isInstanceOf(io.jsonwebtoken.MalformedJwtException.class);
    }
}