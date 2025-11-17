package store.bookscamp.gateway;

import io.jsonwebtoken.Claims;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.util.List;

@Component
@RequiredArgsConstructor
public class AuthorizationFilter implements GlobalFilter, Ordered {

    private final JwtTokenProvider jwtTokenProvider;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private static final Map<HttpMethod, List<String>> EXCLUDED_PATTERNS = Map.of(
            HttpMethod.GET, List.of(
                    "/api-server/books",
                    "/api-server/bookDetail/**",
                    "/api-server/books/**",
                    "/api-server/categories",
                    "/api-server/member/check-id",
                    "/api-server/allBooks",
                    "/api-server/coupon-issue/downloadable",
                    "/api-server/coupon-issue/issue"
            ),
            HttpMethod.POST, List.of(
                    "/auth-server/reissue",
                    "/auth-server/login",
                    "/auth-server/admin/login",
                    "/api-server/member/sign-up"
            )
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        HttpMethod method = request.getMethod();

        if (EXCLUDED_PATTERNS.getOrDefault(method, List.of()).stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path))) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst("Authorization");
        String jwtToken = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwtToken = authHeader.substring(7);
        }
        else if (request.getCookies().getFirst("Authorization") != null) {
            jwtToken = request.getCookies().getFirst("Authorization").getValue();
        }

        if (jwtToken == null) {
            return chain.filter(exchange);
        }

        try {
            Claims claims = jwtTokenProvider.getClaims(jwtToken);
            Long memberId = claims.get("id", Long.class);
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
