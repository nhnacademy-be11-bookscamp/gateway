package store.bookscamp.gateway;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LoggingGlobalFilterTest {

    @InjectMocks
    private LoggingGlobalFilter loggingGlobalFilter;

    @Mock
    private GatewayFilterChain chain;

    @Test
    @DisplayName("정상적인 상태 코드일 때 로그 로직이 수행된다")
    void filter_WithStatusCode() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/test/uri").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        exchange.getResponse().setStatusCode(HttpStatus.OK);

        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        Mono<Void> result = loggingGlobalFilter.filter(exchange, chain);

        StepVerifier.create(result).verifyComplete();
        verify(chain).filter(exchange);
    }

    @Test
    @DisplayName("상태 코드가 null인 경우에도 예외 없이 수행된다(0으로 처리)")
    void filter_WithNullStatusCode() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/test/uri").build();

        MockServerWebExchange exchange = spy(MockServerWebExchange.from(request));

        ServerHttpResponse response = spy(exchange.getResponse());

        doReturn(null).when(response).getStatusCode(); // Spy 객체에는 doReturn이 더 안전함

        doReturn(response).when(exchange).getResponse();

        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        Mono<Void> result = loggingGlobalFilter.filter(exchange, chain);

        StepVerifier.create(result).verifyComplete();
        verify(chain).filter(exchange);
    }
}