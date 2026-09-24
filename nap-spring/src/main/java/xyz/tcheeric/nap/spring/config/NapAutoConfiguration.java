package xyz.tcheeric.nap.spring.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import xyz.tcheeric.nap.spring.ClientIpResolver;
import xyz.tcheeric.nap.spring.RawBodyExtractor;
import xyz.tcheeric.nap.spring.controller.NapAuthController;
import xyz.tcheeric.nap.spring.filter.NapPermissionInterceptor;

import java.time.Clock;

@AutoConfiguration(after = JacksonAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "nap", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(NapProperties.class)
public class NapAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(NapAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public ChallengeStore challengeStore() {
        log.warn("nap_in_memory_challenge_store: challenges are lost on restart and are not "
                + "shared between instances. Supply a JdbcChallengeStore bean for any "
                + "multi-instance or production deployment.");
        return new InMemoryChallengeStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionStore sessionStore() {
        // Warned rather than refused: the in-memory stores are genuinely useful for local
        // development, so failing here would be the wrong trade. What was wrong was that a
        // deployment could reach production on them without ever being told, and the
        // revocation consequence is a security one rather than only an availability one.
        log.warn("nap_in_memory_session_store: sessions are lost on restart and are not shared "
                + "between instances, so revokeByPrincipal reaches only this node and a "
                + "suspended principal keeps working elsewhere until their session expires. "
                + "Supply a JdbcSessionStore bean for any multi-instance or production "
                + "deployment.");
        return new InMemorySessionStore();
    }

    /**
     * There is deliberately no default {@link AclResolver}.
     *
     * <p>The previous default was {@link AllowAllAclResolver}, which authorizes every principal
     * who can prove key control. That is indistinguishable from a working configuration: an
     * operator wires NAP, logs in with their own key, sees a session, and ships, with nothing
     * reporting that the authorization layer is a no-op.
     *
     * <p>The escape hatch remains, as a written decision rather than an omission. This mirrors
     * what {@code createAudienceHostAllowlist()} and {@code createMintAllowlist()} already do on
     * the TypeScript side: refuse at wiring time rather than accept a configuration that permits
     * everything, because an allowlist that allows everything is the state they exist to make
     * unrepresentable.
     */
    @Bean
    @ConditionalOnMissingBean
    public AclResolver aclResolver(NapProperties properties) {
        if (!properties.allowAllPrincipals()) {
            throw new IllegalStateException(
                    "NAP requires an AclResolver bean. Supply RegistryAclResolver (or your own), "
                            + "or set nap.allow-all-principals=true to authorize every principal "
                            + "who proves key control, which is what the previous default did "
                            + "silently.");
        }
        log.warn("nap_acl_allow_all_enabled: every principal proving key control is authorized, "
                + "with no roles or permissions. This is nap.allow-all-principals=true.");
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
                // Bounded, and sized from the same skew allowance the timestamp check uses:
                // once an event is too old to be accepted, its id no longer needs remembering.
                // The old unbounded default grew for the life of the process, at a rate the
                // caller controls.
                .eventReplayGuard(replayGuardProvider.getIfAvailable(
                        () -> EventReplayGuard.inMemory(Math.max(1, properties.maxClockSkewSeconds()))))
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
                                               ObjectProvider<RawBodyExtractor> rawBodyExtractorProvider,
                                               ObjectProvider<ClientIpResolver> clientIpResolverProvider) {
        // All null unless the application supplies one; nap.external-base-url stays the
        // shorthand for the common case (RFC §20.2).
        //
        // The client-IP resolver defaults to getRemoteAddr(), which is correct only when nothing
        // sits between the client and this process. Behind a proxy that address is the proxy's,
        // so every caller shares one rate-limit bucket and thirty requests lock everyone out.
        // nap.trusted-proxies is the shorthand: set it and the resolver walks X-Forwarded-For
        // back to the first hop those proxies actually observed.
        ClientIpResolver clientIpResolver = clientIpResolverProvider.getIfAvailable();
        if (clientIpResolver == null && !properties.trustedProxies().isEmpty()) {
            clientIpResolver = ClientIpResolver.forwardedFor(properties.trustedProxies());
        }
        return new NapAuthController(napServer, sessionStore, properties, objectMapper,
                audienceResolverProvider.getIfAvailable(),
                rawBodyExtractorProvider.getIfAvailable(),
                clientIpResolver);
    }

    @Bean
    @ConditionalOnMissingBean(name = "napPermissionInterceptor")
    public HandlerInterceptor napPermissionInterceptor(ObjectProvider<PermissionRegistry> registryProvider,
                                                      NapProperties properties) {
        // With a registry present, a permission declared stepUp is enforced everywhere it is
        // required, without @RequiresStepUp having to be repeated at every call site.
        //
        // nap.require-annotation-on-protected-paths turns an undeclared handler under a protected
        // prefix into a startup-visible error instead of an open endpoint.
        return new NapPermissionInterceptor(registryProvider.getIfAvailable(),
                properties.protectedPathPrefixes(),
                properties.requireAnnotationOnProtectedPaths());
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
