package store.bookscamp.gateway;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.util.List;

@Component
@RequiredArgsConstructor
public class AuthorizationFilter implements GlobalFilter, Ordered {

    private final JwtTokenProvider jwtTokenProvider;
    private static final List<String> EXCLUDED_PATHS = List.of(
            "/auth-server/login",
            "/api-server/sign-up",
            "/public",
            "/login",
            "/api-server/member/check-id", 
            "/api-server/categories"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        if (EXCLUDED_PATHS.stream().anyMatch(path::contains)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, "토큰이 없거나 형식이 잘못되었습니다.", HttpStatus.UNAUTHORIZED);
        }

        String jwtToken = authHeader.substring(7);

        try {
            Claims claims = jwtTokenProvider.getClaims(jwtToken);
            Long memberId = claims.get("memberId", Long.class);
            String role = claims.get("role", String.class);

            ServerHttpRequest authorizedRequest = request.mutate()
                    .header("X-User-ID", String.valueOf(memberId))
                    .header("X-User-Role", role)
                    .build();

            return chain.filter(exchange.mutate().request(authorizedRequest).build());

        } catch (Exception e) {
            return onError(exchange, "JWT 토큰이 유효하지 않습니다.", HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        return response.writeWith(Mono.just(response.bufferFactory().wrap(err.getBytes())));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
