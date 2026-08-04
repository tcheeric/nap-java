package xyz.tcheeric.nap.spring.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import xyz.tcheeric.nap.core.ChallengeStore;
import xyz.tcheeric.nap.core.SessionStore;
import xyz.tcheeric.nap.server.AclResolver;
import xyz.tcheeric.nap.server.AllowAllAclResolver;
import xyz.tcheeric.nap.server.EventReplayGuard;
import xyz.tcheeric.nap.server.NapServer;
import xyz.tcheeric.nap.server.NapServerOptions;
import xyz.tcheeric.nap.server.MetricsRecorder;
import xyz.tcheeric.nap.server.RateLimiter;
import xyz.tcheeric.nap.server.InMemoryRateLimiter;
import xyz.tcheeric.nap.server.acl.PermissionRegistry;
import xyz.tcheeric.nap.server.store.InMemoryChallengeStore;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;
import xyz.tcheeric.nap.spring.AudienceResolver;
import xyz.tcheeric.nap.spring.RawBodyExtractor;
import xyz.tcheeric.nap.spring.controller.NapAuthController;
import xyz.tcheeric.nap.spring.filter.NapPermissionInterceptor;

import java.time.Clock;

@AutoConfiguration(after = JacksonAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "nap", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(NapProperties.class)
public class NapAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ChallengeStore challengeStore() {
        return new InMemoryChallengeStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionStore sessionStore() {
        return new InMemorySessionStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public AclResolver aclResolver() {
        return new AllowAllAclResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public NapServer napServer(ChallengeStore challengeStore, SessionStore sessionStore,
                               AclResolver aclResolver,
                               NapProperties properties,
                               ObjectProvider<EventReplayGuard> replayGuardProvider,
                               ObjectProvider<RateLimiter> rateLimiterProvider,
                               ObjectProvider<MetricsRecorder> metricsProvider) {
        return NapServer.create(NapServerOptions.builder()
                .challengeStore(challengeStore)
                .sessionStore(sessionStore)
                .aclResolver(aclResolver)
                .eventReplayGuard(replayGuardProvider.getIfAvailable(EventReplayGuard::inMemory))
                // An application-supplied RateLimiter wins; otherwise the in-memory one at
                // the configured window, unless nap.rate-limit-enabled=false opts out. That
                // opt-out is deliberate: the response floor holds every unauthenticated
                // request open, which without a limiter amplifies concurrency.
                .rateLimiter(rateLimiterProvider.getIfAvailable(() ->
                        properties.rateLimitEnabled()
                                ? InMemoryRateLimiter.create(
                                        properties.rateLimitWindowSeconds(),
                                        properties.rateLimitMaxPerWindow(),
                                        Clock.systemUTC())
                                : null))
                .challengeTtlSeconds(properties.challengeTtlSeconds())
                .sessionTtlSeconds(properties.sessionTtlSeconds())
                .sessionIdleTtlSeconds(properties.sessionIdleTtlSeconds())
                .sessionAbsoluteTtlSeconds(properties.sessionAbsoluteTtlSeconds())
                .resultCacheTtlSeconds(properties.resultCacheTtlSeconds())
                .maxClockSkewSeconds(properties.maxClockSkewSeconds())
                .metrics(metricsProvider.getIfAvailable())
                .stepUpTtlSeconds(properties.stepUpTtlSeconds())
                .refreshTtlSeconds(properties.refreshTtlSeconds())
                .maxOutstandingChallengesPerNpub(properties.maxOutstandingChallengesPerNpub())
                .maxOutstandingChallengesPerIp(properties.maxOutstandingChallengesPerIp())
                .maxFailuresPerChallenge(properties.maxFailuresPerChallenge())
                .minAuthResponseMillis(properties.minAuthResponseMillis())
                .responseJitterMillis(properties.responseJitterMillis())
                .build());
    }

    // No NapServletFilter / NapSessionFilter bean here, deliberately: both are registered by
    // the application (usually through a FilterRegistrationBean, which ConditionalOnMissingBean
    // would not see), and a second registration would consume the request body twice. The
    // matching knobs — nap.max-body-bytes, nap.protected-path-prefixes — are read at that site,
    // so the registration has to pass them:
    //
    //     new NapServletFilter("/auth/complete", properties.maxBodyBytes())
    //
    // Neither filter has a constructor that defaults them, so leaving one out is a compile
    // error rather than a configured value the app silently never applies.

    @Bean
    @ConditionalOnMissingBean
    public NapAuthController napAuthController(NapServer napServer, SessionStore sessionStore,
                                               NapProperties properties,
                                               com.fasterxml.jackson.databind.ObjectMapper objectMapper,
                                               ObjectProvider<AudienceResolver> audienceResolverProvider,
                                               ObjectProvider<RawBodyExtractor> rawBodyExtractorProvider) {
        // Both null unless the application supplies one; nap.external-base-url stays the
        // shorthand for the common case (RFC §20.2).
        return new NapAuthController(napServer, sessionStore, properties, objectMapper,
                audienceResolverProvider.getIfAvailable(),
                rawBodyExtractorProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean(name = "napPermissionInterceptor")
    public HandlerInterceptor napPermissionInterceptor(ObjectProvider<PermissionRegistry> registryProvider) {
        // With a registry present, a permission declared stepUp is enforced everywhere it is
        // required, without @RequiresStepUp having to be repeated at every call site.
        return new NapPermissionInterceptor(registryProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean(name = "napPermissionWebMvcConfigurer")
    public WebMvcConfigurer napPermissionWebMvcConfigurer(HandlerInterceptor napPermissionInterceptor) {
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                registry.addInterceptor(napPermissionInterceptor);
            }
        };
    }
}
