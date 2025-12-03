package store.bookscamp.gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationFilterTest {

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private GatewayFilterChain chain;

    @InjectMocks
    private AuthorizationFilter authorizationFilter;

    @BeforeEach
    void setUp() {
        lenient().when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());
    }

    @Test
    @DisplayName("제외된(Excluded) 경로는 토큰 검증 없이 통과한다")
    void filter_ExcludedPath() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api-server/books").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        Mono<Void> result = authorizationFilter.filter(exchange, chain);

        StepVerifier.create(result).verifyComplete();
        verify(chain).filter(exchange);
        verify(jwtTokenProvider, never()).getClaims(anyString());
    }

    @Test
    @DisplayName("Header에 유효한 Bearer 토큰이 있으면 사용자 정보를 헤더에 추가한다")
    void filter_ValidToken_In_Header() {
        String token = "valid.jwt.token";
        MockServerHttpRequest request = MockServerHttpRequest.get("/api-server/orders")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        Claims claims = new DefaultClaims(Map.of("id", 100L, "role", "USER"));
        given(jwtTokenProvider.getClaims(token)).willReturn(claims);

        authorizationFilter.filter(exchange, chain).block();

        verify(chain).filter(argThat(ex -> {
            HttpHeaders headers = ex.getRequest().getHeaders();
            return "100".equals(headers.getFirst("X-User-ID")) &&
                    "USER".equals(headers.getFirst("X-User-Role"));
        }));
    }

    @Test
    @DisplayName("헤더가 없지만 Cookie에 유효한 토큰이 있으면 인증에 성공한다")
    void filter_ValidToken_In_Cookie_NoHeader() {
        String token = "valid.jwt.token";
        MockServerHttpRequest request = MockServerHttpRequest.get("/api-server/orders")
                .cookie(new HttpCookie("Authorization", token))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        Claims claims = new DefaultClaims(Map.of("id", 200L, "role", "ADMIN"));
        given(jwtTokenProvider.getClaims(token)).willReturn(claims);

        authorizationFilter.filter(exchange, chain).block();

        verify(chain).filter(argThat(ex -> {
            HttpHeaders headers = ex.getRequest().getHeaders();
            return "200".equals(headers.getFirst("X-User-ID")) &&
                    "ADMIN".equals(headers.getFirst("X-User-Role"));
        }));
    }

    @Test
    @DisplayName("헤더가 있지만 Bearer 타입이 아닌 경우 쿠키를 확인하여 인증한다")
    void filter_HeaderNotBearer_CheckCookie() {
        String token = "valid.jwt.token";
        MockServerHttpRequest request = MockServerHttpRequest.get("/api-server/orders")
                .header(HttpHeaders.AUTHORIZATION, "Basic some_auth_key") // Bearer 아님
                .cookie(new HttpCookie("Authorization", token))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        Claims claims = new DefaultClaims(Map.of("id", 300L, "role", "USER"));
        given(jwtTokenProvider.getClaims(token)).willReturn(claims);

        authorizationFilter.filter(exchange, chain).block();

        verify(jwtTokenProvider).getClaims(token);
    }

    @Test
    @DisplayName("유효하지 않은 토큰(예외 발생)일 경우 401 Unauthorized를 반환한다")
    void filter_InvalidToken() {
        String token = "invalid.token";
        MockServerHttpRequest request = MockServerHttpRequest.get("/api-server/orders")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        given(jwtTokenProvider.getClaims(token)).willThrow(new RuntimeException("Invalid Token"));

        Mono<Void> result = authorizationFilter.filter(exchange, chain);

        StepVerifier.create(result).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("토큰이 아예 없는 경우 그대로 필터 체인을 통과한다")
    void filter_NoToken() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api-server/orders").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        authorizationFilter.filter(exchange, chain).block();

        verify(chain).filter(exchange);
        verify(jwtTokenProvider, never()).getClaims(any());
    }

    @Test
    @DisplayName("getOrder는 -1을 반환한다")
    void getOrder() {
        assertThat(authorizationFilter.getOrder()).isEqualTo(-1);
    }
}