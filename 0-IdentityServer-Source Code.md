IdentityServer4 Source Code
============================

```C#
//------------------V
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddIdentityServer();  // <-------------------------
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        // ...

        app.UseRouting();

        app.UseIdentityServer();  // <-------------------------a0

        app.UseEndpoints(...);
    }
}
//------------------Ʌ
```


* How does `.well-known/openid-configuration` response get generated? Inside `IdentityServerMiddleware` q1

=====================================================================================================================

## Source Code

```json
{
    "issuer": "https://localhost:5001",
    "jwks_uri": "https://localhost:5001/.well-known/openid-configuration/jwks",
    "authorization_endpoint": "https://localhost:5001/connect/authorize",
    "token_endpoint": "https://localhost:5001/connect/token",
    "userinfo_endpoint": "https://localhost:5001/connect/userinfo",
    "end_session_endpoint": "https://localhost:5001/connect/endsession",
    "check_session_iframe": "https://localhost:5001/connect/checksession",
    "revocation_endpoint": "https://localhost:5001/connect/revocation",
    "introspection_endpoint": "https://localhost:5001/connect/introspect",
    "device_authorization_endpoint": "https://localhost:5001/connect/deviceauthorization",
    "backchannel_authentication_endpoint": "https://localhost:5001/connect/ciba",
    "pushed_authorization_request_endpoint": "https://localhost:5001/connect/par",
    "require_pushed_authorization_requests": false,
    "frontchannel_logout_supported": true,
    "frontchannel_logout_session_supported": true,
    "backchannel_logout_supported": true,
    "backchannel_logout_session_supported": true,
    "scopes_supported": [
        "api1",
        "offline_access"
    ],
    "claims_supported": [],
    "grant_types_supported": [
        "authorization_code",
        "client_credentials",
        "refresh_token",
        "implicit",
        "urn:ietf:params:oauth:grant-type:device_code",
        "urn:openid:params:grant-type:ciba"
    ],
    "response_types_supported": [
        "code",
        "token",
        "id_token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
    ],
    "response_modes_supported": [
        "form_post",
        "query",
        "fragment"
    ],
    "token_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "subject_types_supported": [
        "public"
    ],
    "code_challenge_methods_supported": [
        "plain",
        "S256"
    ],
    "request_parameter_supported": true,
    "request_object_signing_alg_values_supported": [
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "HS256",
        "HS384",
        "HS512"
    ],
    "prompt_values_supported": [
        "none",
        "login",
        "consent",
        "select_account"
    ],
    "authorization_response_iss_parameter_supported": true,
    "backchannel_token_delivery_modes_supported": [
        "poll"
    ],
    "backchannel_user_code_parameter_supported": true,
    "dpop_signing_alg_values_supported": [
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512"
    ]
}
```

```C#
//-----------------------------------------------------------V
public static class IdentityServerServiceCollectionExtensions
{
    public static IIdentityServerBuilder AddIdentityServerBuilder(this IServiceCollection services)
    {
        return new IdentityServerBuilder(services);
    }

    public static IIdentityServerBuilder AddIdentityServer(this IServiceCollection services)
    {
        var builder = services.AddIdentityServerBuilder();
 
        builder
            .AddRequiredPlatformServices()
            .AddCookieAuthentication()
            .AddCoreServices()
            .AddDefaultEndpoints()
            .AddPluggableServices()
            .AddValidators()
            .AddResponseGenerators()
            .AddDefaultSecretParsers()
            .AddDefaultSecretValidators();
 
        // provide default in-memory implementation, not suitable for most production scenarios
        builder.AddInMemoryPersistedGrants();
 
        return builder;
    }

    public static IIdentityServerBuilder AddIdentityServer(this IServiceCollection services, Action<IdentityServerOptions> setupAction)
    {
        services.Configure(setupAction);
        return services.AddIdentityServer();
    }

    public static IIdentityServerBuilder AddIdentityServer(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<IdentityServerOptions>(configuration);
        return services.AddIdentityServer();
    }

    public static IServiceCollection AddOidcStateDataFormatterCache(this IServiceCollection services, params string[] schemes)
    {
        services.AddSingleton<IPostConfigureOptions<OpenIdConnectOptions>>(
            svcs => new ConfigureOpenIdConnectOptions(
                schemes,
                svcs.GetRequiredService<IHttpContextAccessor>())
        );
 
        return services;
    }
}
//-----------------------------------------------------------Ʌ

//-----------------------------------------------------V
public static class IdentityServerBuilderExtensionsCore
{
    public static IIdentityServerBuilder AddRequiredPlatformServices(this IIdentityServerBuilder builder)
    {
        builder.Services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();            
        builder.Services.AddOptions();
        builder.Services.AddSingleton(
            resolver => resolver.GetRequiredService<IOptions<IdentityServerOptions>>().Value);
        builder.Services.AddHttpClient();
 
        return builder;
    }

    public static IIdentityServerBuilder AddCookieAuthentication(this IIdentityServerBuilder builder)
    {
        builder.Services
            .AddAuthentication(IdentityServerConstants.DefaultCookieAuthenticationScheme)  // AddAuthentication is from Microsoft which indirectly call AddAuthenticationCore()
            .AddCookie(IdentityServerConstants.DefaultCookieAuthenticationScheme)
            .AddCookie(IdentityServerConstants.ExternalCookieAuthenticationScheme);
 
        builder.Services.AddSingleton<IConfigureOptions<CookieAuthenticationOptions>, ConfigureInternalCookieOptions>();
        builder.Services.AddSingleton<IPostConfigureOptions<CookieAuthenticationOptions>, PostConfigureInternalCookieOptions>();
        builder.Services.AddTransientDecorator<IAuthenticationService, IdentityServerAuthenticationService>();
        builder.Services.AddTransientDecorator<IAuthenticationHandlerProvider, FederatedSignoutAuthenticationHandlerProvider>();
 
        return builder;
    }

    public static IIdentityServerBuilder AddDefaultEndpoints(this IIdentityServerBuilder builder)
    {
        builder.Services.AddTransient<IEndpointRouter, EndpointRouter>();  // <---------------------------------q1, it is IdentityServer's own Router like UseRouting()
 
        builder.AddEndpoint<AuthorizeCallbackEndpoint>(EndpointNames.Authorize, ProtocolRoutePaths.AuthorizeCallback.EnsureLeadingSlash());
        builder.AddEndpoint<AuthorizeEndpoint>(EndpointNames.Authorize, ProtocolRoutePaths.Authorize.EnsureLeadingSlash());
        builder.AddEndpoint<CheckSessionEndpoint>(EndpointNames.CheckSession, ProtocolRoutePaths.CheckSession.EnsureLeadingSlash());
        builder.AddEndpoint<DeviceAuthorizationEndpoint>(EndpointNames.DeviceAuthorization, ProtocolRoutePaths.DeviceAuthorization.EnsureLeadingSlash());
        builder.AddEndpoint<DiscoveryKeyEndpoint>(EndpointNames.Discovery, ProtocolRoutePaths.DiscoveryWebKeys.EnsureLeadingSlash());
        builder.AddEndpoint<DiscoveryEndpoint>(EndpointNames.Discovery, ProtocolRoutePaths.DiscoveryConfiguration.EnsureLeadingSlash());  // <---------------q1
        builder.AddEndpoint<EndSessionCallbackEndpoint>(EndpointNames.EndSession, ProtocolRoutePaths.EndSessionCallback.EnsureLeadingSlash());
        builder.AddEndpoint<EndSessionEndpoint>(EndpointNames.EndSession, ProtocolRoutePaths.EndSession.EnsureLeadingSlash());
        builder.AddEndpoint<IntrospectionEndpoint>(EndpointNames.Introspection, ProtocolRoutePaths.Introspection.EnsureLeadingSlash());
        builder.AddEndpoint<TokenRevocationEndpoint>(EndpointNames.Revocation, ProtocolRoutePaths.Revocation.EnsureLeadingSlash());
        builder.AddEndpoint<TokenEndpoint>(EndpointNames.Token, ProtocolRoutePaths.Token.EnsureLeadingSlash());
        builder.AddEndpoint<UserInfoEndpoint>(EndpointNames.UserInfo, ProtocolRoutePaths.UserInfo.EnsureLeadingSlash());
 
        return builder;
    }

    public static IIdentityServerBuilder AddEndpoint<T>(this IIdentityServerBuilder builder, string name, PathString path) where T : class, IEndpointHandler
    {
        builder.Services.AddTransient<T>();
        builder.Services.AddSingleton(new IdentityServer4.Hosting.Endpoint(name, path, typeof(T)));
 
        return builder;
    }

    public static IIdentityServerBuilder AddCoreServices(this IIdentityServerBuilder builder)
    {
        builder.Services.AddTransient<ISecretsListParser, SecretParser>();
        builder.Services.AddTransient<ISecretsListValidator, SecretValidator>();
        builder.Services.AddTransient<ExtensionGrantValidator>();
        builder.Services.AddTransient<BearerTokenUsageValidator>();
        builder.Services.AddTransient<JwtRequestValidator>();
 
        builder.Services.AddTransient<ReturnUrlParser>();
        builder.Services.AddTransient<BearerTokenUsageValidator>();
 
        builder.Services.AddTransient<IReturnUrlParser, OidcReturnUrlParser>();
        builder.Services.AddScoped<IUserSession, DefaultUserSession>();
        builder.Services.AddTransient(typeof(MessageCookie<>));
 
        builder.Services.AddCors();
        builder.Services.AddTransientDecorator<ICorsPolicyProvider, CorsPolicyProvider>();
 
        return builder;
    }

    public static IIdentityServerBuilder AddPluggableServices(this IIdentityServerBuilder builder)
    {
        builder.Services.TryAddTransient<IPersistedGrantService, DefaultPersistedGrantService>();
        builder.Services.TryAddTransient<IKeyMaterialService, DefaultKeyMaterialService>();
        builder.Services.TryAddTransient<ITokenService, DefaultTokenService>();  // <---------------------------------------------------------------
        builder.Services.TryAddTransient<ITokenCreationService, DefaultTokenCreationService>();
        builder.Services.TryAddTransient<IClaimsService, DefaultClaimsService>();
        builder.Services.TryAddTransient<IRefreshTokenService, DefaultRefreshTokenService>();
        builder.Services.TryAddTransient<IDeviceFlowCodeService, DefaultDeviceFlowCodeService>();
        builder.Services.TryAddTransient<IConsentService, DefaultConsentService>();
        builder.Services.TryAddTransient<ICorsPolicyService, DefaultCorsPolicyService>();
        builder.Services.TryAddTransient<IProfileService, DefaultProfileService>();
        builder.Services.TryAddTransient<IConsentMessageStore, ConsentMessageStore>();
        builder.Services.TryAddTransient<IMessageStore<LogoutMessage>, ProtectedDataMessageStore<LogoutMessage>>();
        builder.Services.TryAddTransient<IMessageStore<LogoutNotificationContext>, ProtectedDataMessageStore<LogoutNotificationContext>>();
        builder.Services.TryAddTransient<IMessageStore<ErrorMessage>, ProtectedDataMessageStore<ErrorMessage>>();
        builder.Services.TryAddTransient<IIdentityServerInteractionService, DefaultIdentityServerInteractionService>();
        builder.Services.TryAddTransient<IDeviceFlowInteractionService, DefaultDeviceFlowInteractionService>();
        builder.Services.TryAddTransient<IAuthorizationCodeStore, DefaultAuthorizationCodeStore>();
        builder.Services.TryAddTransient<IRefreshTokenStore, DefaultRefreshTokenStore>();
        builder.Services.TryAddTransient<IReferenceTokenStore, DefaultReferenceTokenStore>();
        builder.Services.TryAddTransient<IUserConsentStore, DefaultUserConsentStore>();
        builder.Services.TryAddTransient<IHandleGenerationService, DefaultHandleGenerationService>();
        builder.Services.TryAddTransient<IPersistentGrantSerializer, PersistentGrantSerializer>();
        builder.Services.TryAddTransient<IEventService, DefaultEventService>();
        builder.Services.TryAddTransient<IEventSink, DefaultEventSink>();
        builder.Services.TryAddTransient<IUserCodeService, DefaultUserCodeService>();
        builder.Services.TryAddTransient<IUserCodeGenerator, NumericUserCodeGenerator>();
        builder.Services.TryAddTransient<ILogoutNotificationService, LogoutNotificationService>();
        builder.Services.TryAddTransient<IBackChannelLogoutService, DefaultBackChannelLogoutService>();
        builder.Services.TryAddTransient<IResourceValidator, DefaultResourceValidator>();
        builder.Services.TryAddTransient<IScopeParser, DefaultScopeParser>();
 
        builder.AddJwtRequestUriHttpClient();
        builder.AddBackChannelLogoutHttpClient();
 
        builder.Services.AddTransient<IClientSecretValidator, ClientSecretValidator>();
        builder.Services.AddTransient<IApiSecretValidator, ApiSecretValidator>();
 
        builder.Services.TryAddTransient<IDeviceFlowThrottlingService, DistributedDeviceFlowThrottlingService>();
        builder.Services.AddDistributedMemoryCache();
 
        return builder;
    }

    public static IIdentityServerBuilder AddValidators(this IIdentityServerBuilder builder)
    {
        // core
        builder.Services.TryAddTransient<IEndSessionRequestValidator, EndSessionRequestValidator>();
        builder.Services.TryAddTransient<ITokenRevocationRequestValidator, TokenRevocationRequestValidator>();
        builder.Services.TryAddTransient<IAuthorizeRequestValidator, AuthorizeRequestValidator>();
        builder.Services.TryAddTransient<ITokenRequestValidator, TokenRequestValidator>();
        builder.Services.TryAddTransient<IRedirectUriValidator, StrictRedirectUriValidator>();
        builder.Services.TryAddTransient<ITokenValidator, TokenValidator>();
        builder.Services.TryAddTransient<IIntrospectionRequestValidator, IntrospectionRequestValidator>();
        builder.Services.TryAddTransient<IResourceOwnerPasswordValidator, NotSupportedResourceOwnerPasswordValidator>();
        builder.Services.TryAddTransient<ICustomTokenRequestValidator, DefaultCustomTokenRequestValidator>();
        builder.Services.TryAddTransient<IUserInfoRequestValidator, UserInfoRequestValidator>();
        builder.Services.TryAddTransient<IClientConfigurationValidator, DefaultClientConfigurationValidator>();
        builder.Services.TryAddTransient<IDeviceAuthorizationRequestValidator, DeviceAuthorizationRequestValidator>();
        builder.Services.TryAddTransient<IDeviceCodeValidator, DeviceCodeValidator>();
 
        // optional
        builder.Services.TryAddTransient<ICustomTokenValidator, DefaultCustomTokenValidator>();
        builder.Services.TryAddTransient<ICustomAuthorizeRequestValidator, DefaultCustomAuthorizeRequestValidator>();
            
        return builder;
    }

    public static IIdentityServerBuilder AddResponseGenerators(this IIdentityServerBuilder builder)
    {
        builder.Services.TryAddTransient<ITokenResponseGenerator, TokenResponseGenerator>();  // <--------------
        builder.Services.TryAddTransient<IUserInfoResponseGenerator, UserInfoResponseGenerator>();
        builder.Services.TryAddTransient<IIntrospectionResponseGenerator, IntrospectionResponseGenerator>();
        builder.Services.TryAddTransient<IAuthorizeInteractionResponseGenerator, AuthorizeInteractionResponseGenerator>();
        builder.Services.TryAddTransient<IAuthorizeResponseGenerator, AuthorizeResponseGenerator>();
        builder.Services.TryAddTransient<IDiscoveryResponseGenerator, DiscoveryResponseGenerator>();
        builder.Services.TryAddTransient<ITokenRevocationResponseGenerator, TokenRevocationResponseGenerator>();
        builder.Services.TryAddTransient<IDeviceAuthorizationResponseGenerator, DeviceAuthorizationResponseGenerator>();
 
        return builder;
    }

    public static IIdentityServerBuilder AddDefaultSecretParsers(this IIdentityServerBuilder builder)
    {
        builder.Services.AddTransient<ISecretParser, BasicAuthenticationSecretParser>();
        builder.Services.AddTransient<ISecretParser, PostBodySecretParser>();
 
        return builder;
    }

    public static IIdentityServerBuilder AddDefaultSecretValidators(this IIdentityServerBuilder builder)
    {
        builder.Services.AddTransient<ISecretValidator, HashedSharedSecretValidator>();
 
        return builder;
    }

    // ...
}
//-----------------------------------------------------Ʌ

//------------------------------------------------------------V
public static class IdentityServerApplicationBuilderExtensions
{
    public static IApplicationBuilder UseIdentityServer(this IApplicationBuilder app, IdentityServerMiddlewareOptions options = null)
    {
        app.Validate();
 
        app.UseMiddleware<BaseUrlMiddleware>();  // <---------------------------------------a0.1
 
        app.ConfigureCors();
 
           
        if (options == null) options = new IdentityServerMiddlewareOptions();
        options.AuthenticationMiddleware(app);
 
        app.UseMiddleware<MutualTlsEndpointMiddleware>();  // <---------------------------------------a0.2
        app.UseMiddleware<IdentityServerMiddleware>();     // <--------------------------------------!a0.3., q1
 
        return app;
    }

    // ...
}
//------------------------------------------------------------Ʌ

//-----------------------------------V
public class IdentityServerMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger _logger;

    public IdentityServerMiddleware(RequestDelegate next, ILogger<IdentityServerMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context, IEndpointRouter router, IUserSession session, IEventService events, IBackChannelLogoutService backChannelLogoutService)  // a1.0
    {
        // this will check the authentication session and from it emit the check session cookie needed from JS-based signout clients.
        await session.EnsureSessionIdCookieAsync();

        context.Response.OnStarting(async () =>
        {
            if (context.GetSignOutCalled())
            { 
                // this clears our session id cookie so JS clients can detect the user has signed out
                await session.RemoveSessionIdCookieAsync();
 
                // back channel logout
                var logoutContext = await session.GetLogoutNotificationContext();
                if (logoutContext != null)
                {
                    await backChannelLogoutService.SendLogoutNotificationsAsync(logoutContext);
                }
            }
        });

        try
        {
            var endpoint = router.Find(context);   // <-----------------------a1.1, q1
            if (endpoint != null)
            { 
                var result = await endpoint.ProcessAsync(context);  // <--------------------a1.2
 
                if (result != null)
                {
                    await result.ExecuteAsync(context);  // <--------------------a1.3
                }
 
                return;
            }
        }
        catch (Exception ex)
        {
            await events.RaiseAsync(new UnhandledExceptionEvent(ex));
            throw;
        }
 
        await _next(context);
    }
}
//-----------------------------------Ʌ

//---------------------------V

internal class EndpointRouter : IEndpointRouter
{
    private readonly IEnumerable<Endpoint> _endpoints;   // <---------------q1, registered in AddDefaultEndpoints
    private readonly IdentityServerOptions _options;
    private readonly ILogger _logger;

    public EndpointRouter(IEnumerable<Endpoint> endpoints, IdentityServerOptions options, ILogger<EndpointRouter> logger)
    {
        _endpoints = endpoints;
        _options = options;
        _logger = logger;
    }

    public IEndpointHandler Find(HttpContext context)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));

        foreach(var endpoint in _endpoints)   // q1
        {
            var path = endpoint.Path;
            if (context.Request.Path.Equals(path, StringComparison.OrdinalIgnoreCase))
            {
                var endpointName = endpoint.Name;
                _logger.LogDebug("Request path {path} matched to endpoint type {endpoint}", context.Request.Path, endpointName);

                return GetEndpointHandler(endpoint, context);
            }
        }

        _logger.LogTrace("No endpoint entry found for request path: {path}", context.Request.Path);

        return null;
    }

    private IEndpointHandler GetEndpointHandler(Endpoint endpoint, HttpContext context)
    {
        if (_options.Endpoints.IsEndpointEnabled(endpoint))
        {
            if (context.RequestServices.GetService(endpoint.Handler) is IEndpointHandler handler)
            {
                _logger.LogDebug("Endpoint enabled: {endpoint}, successfully created handler: {endpointHandler}", endpoint.Name, endpoint.Handler.FullName);
                return handler;
            }

            _logger.LogDebug("Endpoint enabled: {endpoint}, failed to create handler: {endpointHandler}", endpoint.Name, endpoint.Handler.FullName);
        }
        else
        {
            _logger.LogWarning("Endpoint disabled: {endpoint}", endpoint.Name);
        }

        return null;
    }
}
//---------------------------Ʌ

//--------------------------------V
public class IdentityServerOptions
{
    public string IssuerUri { get; set; }
    public bool LowerCaseIssuerUri { get; set; } = true;
    public string AccessTokenJwtType { get; set; } = "at+jwt";
    public bool EmitStaticAudienceClaim { get; set; } = false;
    public bool EmitScopesAsSpaceDelimitedStringInJwt { get; set; } = false;
    public bool StrictJarValidation { get; set; } = false;
    public EndpointsOptions Endpoints { get; set; } = new EndpointsOptions();
    public DiscoveryOptions Discovery { get; set; } = new DiscoveryOptions();
    public AuthenticationOptions Authentication { get; set; } = new AuthenticationOptions();
    public EventsOptions Events { get; set; } = new EventsOptions();
    public InputLengthRestrictions InputLengthRestrictions { get; set; } = new InputLengthRestrictions();
    public UserInteractionOptions UserInteraction { get; set; } = new UserInteractionOptions();
    public CachingOptions Caching { get; set; } = new CachingOptions();
    public CorsOptions Cors { get; set; } = new CorsOptions();
    public CspOptions Csp { get; set; } = new CspOptions();
    public ValidationOptions Validation { get; set; } = new ValidationOptions();
    public DeviceFlowOptions DeviceFlow { get; set; } = new DeviceFlowOptions();
    public LoggingOptions Logging { get; set; } = new LoggingOptions();
    public MutualTlsOptions MutualTls { get; set; } = new MutualTlsOptions();
}
//--------------------------------Ʌ

//---------------------------V
public static class GrantType
{
    public const string Implicit = "implicit";
    public const string Hybrid = "hybrid";
    public const string AuthorizationCode = "authorization_code";
    public const string ClientCredentials = "client_credentials";
    public const string ResourceOwnerPassword = "password";
    public const string DeviceFlow = "urn:ietf:params:oauth:grant-type:device_code";
}
//---------------------------Ʌ
```

```C#
//----------------------------V
public abstract class Resource
{
    private string DebuggerDisplay => Name ?? $"{{{typeof(Resource)}}}";

    public bool Enabled { get; set; } = true; 

    public string Name { get; set; }  
    public string DisplayName { get; set; }

    public string Description { get; set; }

    public bool ShowInDiscoveryDocument { get; set; } = true;  

    public ICollection<string> UserClaims { get; set; } = new HashSet<string>();  

    public IDictionary<string, string> Properties { get; set; } = new Dictionary<string, string>();
}
//----------------------------Ʌ

//---------------------------V
public class IdentityResource : Resource
{
    private string DebuggerDisplay => Name ?? $"{{{typeof(IdentityResource)}}}";

    public IdentityResource() { }

    public IdentityResource(string name, IEnumerable<string> userClaims) : this(name, name, userClaims) { }

    public IdentityResource(string name, string displayName, IEnumerable<string> userClaims)
    {      
        Name = name;
        DisplayName = displayName;

        foreach(var type in userClaims)
        {
            UserClaims.Add(type);
        }
    } 

    public bool Required { get; set; } = false;
    
    public bool Emphasize { get; set; } = false;
}
//---------------------------Ʌ
```

```C#
//---------------------------->>
public interface ITokenService
{
    Task<Token> CreateIdentityTokenAsync(TokenCreationRequest request);
    Task<Token> CreateAccessTokenAsync(TokenCreationRequest request);
    Task<string> CreateSecurityTokenAsync(Token token);
}
//----------------------------<<

//------------------------------V
public class DefaultTokenService : ITokenService
{
    protected readonly ILogger Logger;
    protected readonly IHttpContextAccessor ContextAccessor;
    protected readonly IClaimsService ClaimsProvider;
    protected readonly IReferenceTokenStore ReferenceTokenStore;
    protected readonly ITokenCreationService CreationService;
    protected readonly ISystemClock Clock;
    protected readonly IKeyMaterialService KeyMaterialService;
    protected readonly IdentityServerOptions Options;

    public DefaultTokenService( 
        IClaimsService claimsProvider,
        IReferenceTokenStore referenceTokenStore,
        ITokenCreationService creationService,
        IHttpContextAccessor contextAccessor,
        ISystemClock clock,
        IKeyMaterialService keyMaterialService,
        IdentityServerOptions options,
        ILogger<DefaultTokenService> logger)
    {
        ContextAccessor = contextAccessor;
        ClaimsProvider = claimsProvider;
        ReferenceTokenStore = referenceTokenStore;
        CreationService = creationService;
        Clock = clock;
        KeyMaterialService = keyMaterialService;
        Options = options;
        Logger = logger;
    }

    public virtual async Task<Token> CreateIdentityTokenAsync(TokenCreationRequest request)
    {
         request.Validate();
 
         var credential = await KeyMaterialService.GetSigningCredentialsAsync(request.ValidatedRequest.Client.AllowedIdentityTokenSigningAlgorithms);

         var signingAlgorithm = credential.Algorithm;
 
         // host provided claims
         var claims = new List<Claim>();
 
         // if nonce was sent, must be mirrored in id token
         if (request.Nonce.IsPresent())
         {
            claims.Add(new Claim(JwtClaimTypes.Nonce, request.Nonce));
         }
 
         // add iat claim
         claims.Add(new Claim(JwtClaimTypes.IssuedAt, Clock.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));
 
         // add at_hash claim
         if (request.AccessTokenToHash.IsPresent())
         {
            claims.Add(new Claim(JwtClaimTypes.AccessTokenHash, CryptoHelper.CreateHashClaimValue(request.AccessTokenToHash, signingAlgorithm)));
         }
 
         // add c_hash claim
         if (request.AuthorizationCodeToHash.IsPresent())
         {
            claims.Add(new Claim(JwtClaimTypes.AuthorizationCodeHash, CryptoHelper.CreateHashClaimValue(request.AuthorizationCodeToHash, signingAlgorithm)));
         }
 
         // add s_hash claim
         if (request.StateHash.IsPresent())
         {
            claims.Add(new Claim(JwtClaimTypes.StateHash, request.StateHash));
         }

         // add sid if present
        if (request.ValidatedRequest.SessionId.IsPresent())
        {
            claims.Add(new Claim(JwtClaimTypes.SessionId, request.ValidatedRequest.SessionId));
        }
 
        claims.AddRange(await ClaimsProvider.GetIdentityTokenClaimsAsync(
            request.Subject,
            request.ValidatedResources,
            request.IncludeAllIdentityClaims,
            request.ValidatedRequest));
 
        var issuer = ContextAccessor.HttpContext.GetIdentityServerIssuerUri();
 
        var token = new Token(OidcConstants.TokenTypes.IdentityToken)
        {
            CreationTime = Clock.UtcNow.UtcDateTime,
            Audiences = { request.ValidatedRequest.Client.ClientId },
            Issuer = issuer,
            Lifetime = request.ValidatedRequest.Client.IdentityTokenLifetime,
            Claims = claims.Distinct(new ClaimComparer()).ToList(),
            ClientId = request.ValidatedRequest.Client.ClientId,
            AccessTokenType = request.ValidatedRequest.AccessTokenType,
            AllowedSigningAlgorithms = request.ValidatedRequest.Client.AllowedIdentityTokenSigningAlgorithms
        };
 
        return token;
    }

    public virtual async Task<Token> CreateAccessTokenAsync(TokenCreationRequest request)
    {
        request.Validate();
 
        var claims = new List<Claim>();
        claims.AddRange(await ClaimsProvider.GetAccessTokenClaimsAsync(
            request.Subject,
            request.ValidatedResources,
            request.ValidatedRequest));
 
        if (request.ValidatedRequest.Client.IncludeJwtId)
        {
            claims.Add(new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId(16, CryptoRandom.OutputFormat.Hex)));
        }
 
        if (request.ValidatedRequest.SessionId.IsPresent())
        {
            claims.Add(new Claim(JwtClaimTypes.SessionId, request.ValidatedRequest.SessionId));
        }
            
        // iat claim as required by JWT profile
        claims.Add(new Claim(JwtClaimTypes.IssuedAt, Clock.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));
 
        var issuer = ContextAccessor.HttpContext.GetIdentityServerIssuerUri();
        var token = new Token(OidcConstants.TokenTypes.AccessToken)
        {
            CreationTime = Clock.UtcNow.UtcDateTime,
            Issuer = issuer,
            Lifetime = request.ValidatedRequest.AccessTokenLifetime,
            Claims = claims.Distinct(new ClaimComparer()).ToList(),
            ClientId = request.ValidatedRequest.Client.ClientId,
            Description = request.Description,
            AccessTokenType = request.ValidatedRequest.AccessTokenType,
            AllowedSigningAlgorithms = request.ValidatedResources.Resources.ApiResources.FindMatchingSigningAlgorithms()
        };
 
        // add aud based on ApiResources in the validated request
        foreach (var aud in request.ValidatedResources.Resources.ApiResources.Select(x => x.Name).Distinct())
        {
            token.Audiences.Add(aud);
        }
 
        if (Options.EmitStaticAudienceClaim)
        {
            token.Audiences.Add(string.Format(IdentityServerConstants.AccessTokenAudience, issuer.EnsureTrailingSlash()));
        }
 
        // add cnf if present
        if (request.ValidatedRequest.Confirmation.IsPresent())
        {
            token.Confirmation = request.ValidatedRequest.Confirmation;
        }
        else
        {
            if (Options.MutualTls.AlwaysEmitConfirmationClaim)
            {
                var clientCertificate = await ContextAccessor.HttpContext.Connection.GetClientCertificateAsync();
                if (clientCertificate != null)
                {
                    token.Confirmation = clientCertificate.CreateThumbprintCnf();
                }
            }
        }
            
        return token;
    }

    public virtual async Task<string> CreateSecurityTokenAsync(Token token)
    {
        string tokenResult;
 
        if (token.Type == OidcConstants.TokenTypes.AccessToken)
        {
            if (token.AccessTokenType == AccessTokenType.Jwt)
            {
                Logger.LogTrace("Creating JWT access token");
 
                tokenResult = await CreationService.CreateTokenAsync(token);
            }
            else
            {
                Logger.LogTrace("Creating reference access token");
 
                var handle = await ReferenceTokenStore.StoreReferenceTokenAsync(token);
 
                tokenResult = handle;
            }
        }
        else if (token.Type == OidcConstants.TokenTypes.IdentityToken)
        {
            Logger.LogTrace("Creating JWT identity token");
 
            tokenResult = await CreationService.CreateTokenAsync(token);
        }
        else
        {
            throw new InvalidOperationException("Invalid token type.");
        }
 
        return tokenResult;
    }
}
//------------------------------Ʌ

//----------------------------->>
public interface IClaimsService
{
    Task<IEnumerable<Claim>> GetIdentityTokenClaimsAsync(ClaimsPrincipal subject, ResourceValidationResult resources, bool includeAllIdentityClaims, ValidatedRequest request);
    Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(ClaimsPrincipal subject, ResourceValidationResult resources, ValidatedRequest request);
}
//-----------------------------<<

//-------------------------------V
public class DefaultClaimsService : IClaimsService
{
    protected readonly ILogger Logger;
    protected readonly IProfileService Profile;

    public DefaultClaimsService(IProfileService profile, ILogger<DefaultClaimsService> logger)
    {
        Logger = logger;
        Profile = profile;
    }

    public DefaultClaimsService(IProfileService profile, ILogger<DefaultClaimsService> logger)
    {
        Logger = logger;
        Profile = profile;
    }

    public virtual async Task<IEnumerable<Claim>> GetIdentityTokenClaimsAsync(ClaimsPrincipal subject, ResourceValidationResult resources, bool includeAllIdentityClaims, ValidatedRequest request)
    {
        var outputClaims = new List<Claim>(GetStandardSubjectClaims(subject));
        outputClaims.AddRange(GetOptionalClaims(subject));
 
        // fetch all identity claims that need to go into the id token
        if (includeAllIdentityClaims || request.Client.AlwaysIncludeUserClaimsInIdToken)
        {
            var additionalClaimTypes = new List<string>();
 
            foreach (var identityResource in resources.Resources.IdentityResources)
            {
                foreach (var userClaim in identityResource.UserClaims)
                {
                    additionalClaimTypes.Add(userClaim);
                }
            }
 
            // filter so we don't ask for claim types that we will eventually filter out
            additionalClaimTypes = FilterRequestedClaimTypes(additionalClaimTypes).ToList();
 
            var context = new ProfileDataRequestContext(
                subject,
                request.Client,
                IdentityServerConstants.ProfileDataCallers.ClaimsProviderIdentityToken,
                additionalClaimTypes)
            {
                RequestedResources = resources,
                ValidatedRequest = request
            };
 
            await Profile.GetProfileDataAsync(context);
 
             var claims = FilterProtocolClaims(context.IssuedClaims);
            if (claims != null)
            {
                outputClaims.AddRange(claims);
            }
        }
        else
        {
            Logger.LogDebug("In addition to an id_token, an access_token was requested. No claims other than sub are included in the id_token. To obtain more user claims, either use the user info endpoint or set AlwaysIncludeUserClaimsInIdToken on the client configuration.");
        }
 
        return outputClaims;
    }

    public virtual async Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(ClaimsPrincipal subject, ResourceValidationResult resourceResult, ValidatedRequest request)
    {
        var outputClaims = new List<Claim> { new Claim(JwtClaimTypes.ClientId, request.ClientId) };
 
        // check for client claims
        if (request.ClientClaims != null && request.ClientClaims.Any())
        {
            if (subject == null || request.Client.AlwaysSendClientClaims)
            {
                foreach (var claim in request.ClientClaims)
                {
                    var claimType = claim.Type;
 
                    if (request.Client.ClientClaimsPrefix.IsPresent())
                    {
                        claimType = request.Client.ClientClaimsPrefix + claimType;
                    }
 
                    outputClaims.Add(new Claim(claimType, claim.Value, claim.ValueType));
                }
            }
        }
 
        // add scopes (filter offline_access)
        // we use the ScopeValues collection rather than the Resources.Scopes because we support dynamic scope values 
        // from the request, so this issues those in the token.
        foreach (var scope in resourceResult.RawScopeValues.Where(x => x != IdentityServerConstants.StandardScopes.OfflineAccess))
        {
             outputClaims.Add(new Claim(JwtClaimTypes.Scope, scope));
        }
 
        // a user is involved
        if (subject != null)
        {
            if (resourceResult.Resources.OfflineAccess)
            {
                outputClaims.Add(new Claim(JwtClaimTypes.Scope, IdentityServerConstants.StandardScopes.OfflineAccess));
            }
  
            outputClaims.AddRange(GetStandardSubjectClaims(subject));
            outputClaims.AddRange(GetOptionalClaims(subject));
 
            // fetch all resource claims that need to go into the access token
            var additionalClaimTypes = new List<string>();
            foreach (var api in resourceResult.Resources.ApiResources)
            {
                // add claims configured on api resource
                if (api.UserClaims != null)
                {
                    foreach (var claim in api.UserClaims)
                    {
                        additionalClaimTypes.Add(claim);
                    }
                }
            }
 
            foreach(var scope in resourceResult.Resources.ApiScopes)
            {
                // add claims configured on scopes
                if (scope.UserClaims != null)
                {
                    foreach (var claim in scope.UserClaims)
                    {
                        additionalClaimTypes.Add(claim);
                    }
                }
            }
 
            // filter so we don't ask for claim types that we will eventually filter out
            additionalClaimTypes = FilterRequestedClaimTypes(additionalClaimTypes).ToList();
 
            var context = new ProfileDataRequestContext(
                subject,
                request.Client,
                IdentityServerConstants.ProfileDataCallers.ClaimsProviderAccessToken,
                additionalClaimTypes.Distinct())
            {
                RequestedResources = resourceResult,
                ValidatedRequest = request
            };
 
            await Profile.GetProfileDataAsync(context);
 
            var claims = FilterProtocolClaims(context.IssuedClaims);
            if (claims != null)
            {
                outputClaims.AddRange(claims);
            }
        }
 
        return outputClaims;
    }

    protected virtual IEnumerable<Claim> GetStandardSubjectClaims(ClaimsPrincipal subject)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtClaimTypes.Subject, subject.GetSubjectId()),
            new Claim(JwtClaimTypes.AuthenticationTime, subject.GetAuthenticationTimeEpoch().ToString(), ClaimValueTypes.Integer64),
            new Claim(JwtClaimTypes.IdentityProvider, subject.GetIdentityProvider())
        };
 
        claims.AddRange(subject.GetAuthenticationMethods());
 
        return claims;
    }

    protected virtual IEnumerable<Claim> GetOptionalClaims(ClaimsPrincipal subject)
    {
        var claims = new List<Claim>();
 
        var acr = subject.FindFirst(JwtClaimTypes.AuthenticationContextClassReference);
        if (acr != null) claims.Add(acr);
 
        return claims;
    }

    protected virtual IEnumerable<Claim> FilterProtocolClaims(IEnumerable<Claim> claims)
    {
        var claimsToFilter = claims.Where(x => Constants.Filters.ClaimsServiceFilterClaimTypes.Contains(x.Type));
        if (claimsToFilter.Any())
        {
            var types = claimsToFilter.Select(x => x.Type);
            Logger.LogDebug("Claim types from profile service that were filtered: {claimTypes}", types);
        }
        return claims.Except(claimsToFilter);
    }

    protected virtual IEnumerable<string> FilterRequestedClaimTypes(IEnumerable<string> claimTypes)
    {
        var claimTypesToFilter = claimTypes.Where(x => Constants.Filters.ClaimsServiceFilterClaimTypes.Contains(x));
        return claimTypes.Except(claimTypesToFilter);
    }
}
//-------------------------------Ʌ

//------------------------------------------------V
internal class IdentityServerAuthenticationService : IAuthenticationService
{
    private readonly IAuthenticationService _inner;
    private readonly IAuthenticationSchemeProvider _schemes;
    private readonly ISystemClock _clock;
    private readonly IUserSession _session;
    private readonly IBackChannelLogoutService _backChannelLogoutService;
    private readonly IdentityServerOptions _options;
    private readonly ILogger<IdentityServerAuthenticationService> _logger;
 
    public IdentityServerAuthenticationService(
        Decorator<IAuthenticationService> decorator,
        IAuthenticationSchemeProvider schemes,
        ISystemClock clock,
        IUserSession session,
        IBackChannelLogoutService backChannelLogoutService,
        IdentityServerOptions options,
        ILogger<IdentityServerAuthenticationService> logger)
    {
        _inner = decorator.Instance;  // <--------------_inner contains Microsoft.AspNetCore.Authentication.AuthenticationService
            
        _schemes = schemes;
        _clock = clock;
        _session = session;
        _backChannelLogoutService = backChannelLogoutService;
        _options = options;
        _logger = logger;
     }

    public async Task SignInAsync(HttpContext context, string scheme, ClaimsPrincipal principal, AuthenticationProperties properties)
    {
        var defaultScheme = await _schemes.GetDefaultSignInSchemeAsync();
        var cookieScheme = await context.GetCookieAuthenticationSchemeAsync();
 
        if ((scheme == null && defaultScheme?.Name == cookieScheme) || scheme == cookieScheme)
        {
            AugmentPrincipal(principal);
 
            properties ??= new AuthenticationProperties();
            await _session.CreateSessionIdAsync(principal, properties);
        }
 
        await _inner.SignInAsync(context, scheme, principal, properties);
    }

    private void AugmentPrincipal(ClaimsPrincipal principal)
    { 
        AssertRequiredClaims(principal);
        AugmentMissingClaims(principal, _clock.UtcNow.UtcDateTime);
    }

    public async Task SignOutAsync(HttpContext context, string scheme, AuthenticationProperties properties)
    {
        var defaultScheme = await _schemes.GetDefaultSignOutSchemeAsync();
        var cookieScheme = await context.GetCookieAuthenticationSchemeAsync();
 
        if ((scheme == null && defaultScheme?.Name == cookieScheme) || scheme == cookieScheme)
        {
            // this sets a flag used by middleware to do post-signout work.
            context.SetSignOutCalled();
        }
 
        await _inner.SignOutAsync(context, scheme, properties);
    }

    public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string scheme)
    {
        return _inner.AuthenticateAsync(context, scheme);
    }
 
    public Task ChallengeAsync(HttpContext context, string scheme, AuthenticationProperties properties)
    {
        return _inner.ChallengeAsync(context, scheme, properties);
    }
 
    public Task ForbidAsync(HttpContext context, string scheme, AuthenticationProperties properties)
    {
        return _inner.ForbidAsync(context, scheme, properties);
    }
 
    private void AssertRequiredClaims(ClaimsPrincipal principal)
    {
        // for now, we don't allow more than one identity in the principal/cookie
        if (principal.Identities.Count() != 1) throw new InvalidOperationException("only a single identity supported");
        if (principal.FindFirst(JwtClaimTypes.Subject) == null) throw new InvalidOperationException("sub claim is missing");
    }
 
    private void AugmentMissingClaims(ClaimsPrincipal principal, DateTime authTime)
    {
        var identity = principal.Identities.First();
 
        // ASP.NET Identity issues this claim type and uses the authentication middleware name such as "Google" for the value. this code is trying to correct/convert that for
        // our scenario. IOW, we take their old AuthenticationMethod value of "Google" and issue it as the idp claim. we then also issue a amr with "external"
        var amr = identity.FindFirst(ClaimTypes.AuthenticationMethod);
        if (amr != null && identity.FindFirst(JwtClaimTypes.IdentityProvider) == null && identity.FindFirst(JwtClaimTypes.AuthenticationMethod) == null)
        {
            identity.RemoveClaim(amr);
            identity.AddClaim(new Claim(JwtClaimTypes.IdentityProvider, amr.Value));
            identity.AddClaim(new Claim(JwtClaimTypes.AuthenticationMethod, Constants.ExternalAuthenticationMethod));
        }
 
        if (identity.FindFirst(JwtClaimTypes.IdentityProvider) == null)
        {
            identity.AddClaim(new Claim(JwtClaimTypes.IdentityProvider, IdentityServerConstants.LocalIdentityProvider));
        }
 
        if (identity.FindFirst(JwtClaimTypes.AuthenticationMethod) == null)
        {
            if (identity.FindFirst(JwtClaimTypes.IdentityProvider).Value == IdentityServerConstants.LocalIdentityProvider)
            {
                identity.AddClaim(new Claim(JwtClaimTypes.AuthenticationMethod, OidcConstants.AuthenticationMethods.Password));
            }
            else
            {
                identity.AddClaim(new Claim(JwtClaimTypes.AuthenticationMethod, Constants.ExternalAuthenticationMethod));
            }
        }
 
        if (identity.FindFirst(JwtClaimTypes.AuthenticationTime) == null)
        {
            var time = new DateTimeOffset(authTime).ToUnixTimeSeconds().ToString();
 
            identity.AddClaim(new Claim(JwtClaimTypes.AuthenticationTime, time, ClaimValueTypes.Integer64));
        }
    }
}
//------------------------------------------------Ʌ

//---------------------------------V
public class TokenResponseGenerator : ITokenResponseGenerator
{
    protected readonly ILogger Logger;
    protected readonly ITokenService TokenService;  // <-----------------------
    protected readonly IRefreshTokenService RefreshTokenService;
    public IScopeParser ScopeParser { get; }
    protected readonly IResourceStore Resources;
    protected readonly IClientStore Clients;
    protected readonly ISystemClock Clock;

    public TokenResponseGenerator(
        ISystemClock clock, 
        ITokenService tokenService, 
        IRefreshTokenService refreshTokenService, 
        IScopeParser scopeParser, 
        IResourceStore resources, 
        IClientStore clients, 
        ILogger<TokenResponseGenerator> logger)
    {
        Clock = clock;
        TokenService = tokenService;  // <-----------
        RefreshTokenService = refreshTokenService;
        ScopeParser = scopeParser;
        Resources = resources;
        Clients = clients;
        Logger = logger;
    }

    public virtual async Task<TokenResponse> ProcessAsync(TokenRequestValidationResult request)
    {
        switch (request.ValidatedRequest.GrantType)
        {
            case OidcConstants.GrantTypes.ClientCredentials:
                return await ProcessClientCredentialsRequestAsync(request);
            case OidcConstants.GrantTypes.Password:
                return await ProcessPasswordRequestAsync(request);
            case OidcConstants.GrantTypes.AuthorizationCode:
                return await ProcessAuthorizationCodeRequestAsync(request);
            case OidcConstants.GrantTypes.RefreshToken:
                return await ProcessRefreshTokenRequestAsync(request);
            case OidcConstants.GrantTypes.DeviceCode:
                return await ProcessDeviceCodeRequestAsync(request);
            default:
                return await ProcessExtensionGrantRequestAsync(request);
        }
    }

    protected virtual Task<TokenResponse> ProcessClientCredentialsRequestAsync(TokenRequestValidationResult request)
        => ProcessTokenRequestAsync(request);

    protected virtual Task<TokenResponse> ProcessPasswordRequestAsync(TokenRequestValidationResult request)
        => return ProcessTokenRequestAsync(request);

    protected virtual async Task<TokenResponse> ProcessAuthorizationCodeRequestAsync(TokenRequestValidationResult request)
    {
        var (accessToken, refreshToken) = await CreateAccessTokenAsync(request.ValidatedRequest);
        var response = new TokenResponse
        {
            AccessToken = accessToken,
            AccessTokenLifetime = request.ValidatedRequest.AccessTokenLifetime,
            Custom = request.CustomResponse,
            Scope = request.ValidatedRequest.AuthorizationCode.RequestedScopes.ToSpaceSeparatedString()
        };

        if (refreshToken.IsPresent())
        {
            response.RefreshToken = refreshToken;  // <-------------------------refresh token
        }

        if (request.ValidatedRequest.AuthorizationCode.IsOpenId)
        {
            // load the client that belongs to the authorization code
            Client client = null;
            if (request.ValidatedRequest.AuthorizationCode.ClientId != null)
            {
                client = await Clients.FindEnabledClientByIdAsync(request.ValidatedRequest.AuthorizationCode.ClientId);
            }
            if (client == null)
            {
                throw new InvalidOperationException("Client does not exist anymore.");
            }
 
            var parsedScopesResult = ScopeParser.ParseScopeValues(request.ValidatedRequest.AuthorizationCode.RequestedScopes);
            var validatedResources = await Resources.CreateResourceValidationResult(parsedScopesResult);
 
            var tokenRequest = new TokenCreationRequest
            {
                Subject = request.ValidatedRequest.AuthorizationCode.Subject,
                ValidatedResources = validatedResources,
                Nonce = request.ValidatedRequest.AuthorizationCode.Nonce,
                AccessTokenToHash = response.AccessToken,
                StateHash = request.ValidatedRequest.AuthorizationCode.StateHash,
                ValidatedRequest = request.ValidatedRequest
            };
 
            var idToken = await TokenService.CreateIdentityTokenAsync(tokenRequest);
            var jwt = await TokenService.CreateSecurityTokenAsync(idToken);
            response.IdentityToken = jwt;
        }
 
        return response;
    }

    protected virtual async Task<TokenResponse> ProcessRefreshTokenRequestAsync(TokenRequestValidationResult request)
    {
        var oldAccessToken = request.ValidatedRequest.RefreshToken.AccessToken;
        string accessTokenString;
 
        if (request.ValidatedRequest.Client.UpdateAccessTokenClaimsOnRefresh)
        {
            var subject = request.ValidatedRequest.RefreshToken.Subject;
 
            // todo: do we want to just parse here and build up validated result or do we want to fully re-run validation here.
            var parsedScopesResult = ScopeParser.ParseScopeValues(oldAccessToken.Scopes);
            var validatedResources = await Resources.CreateResourceValidationResult(parsedScopesResult);
 
            var creationRequest = new TokenCreationRequest
            {
                Subject = subject,
                Description = request.ValidatedRequest.RefreshToken.Description,
                ValidatedRequest = request.ValidatedRequest,
                ValidatedResources = validatedResources
            };
 
            var newAccessToken = await TokenService.CreateAccessTokenAsync(creationRequest);
            accessTokenString = await TokenService.CreateSecurityTokenAsync(newAccessToken);
        }
        else
        {
            oldAccessToken.CreationTime = Clock.UtcNow.UtcDateTime;
            oldAccessToken.Lifetime = request.ValidatedRequest.AccessTokenLifetime;
 
            accessTokenString = await TokenService.CreateSecurityTokenAsync(oldAccessToken);
        }
 
        var handle = 
            await RefreshTokenService.UpdateRefreshTokenAsync(request.ValidatedRequest.RefreshTokenHandle, request.ValidatedRequest.RefreshToken, request.ValidatedRequest.Client);
 
        return new TokenResponse
        {
            IdentityToken = await CreateIdTokenFromRefreshTokenRequestAsync(request.ValidatedRequest, accessTokenString),
            AccessToken = accessTokenString,
            AccessTokenLifetime = request.ValidatedRequest.AccessTokenLifetime,
            RefreshToken = handle,
            Custom = request.CustomResponse,
            Scope = request.ValidatedRequest.RefreshToken.Scopes.ToSpaceSeparatedString()
        };
    }
    
    protected virtual async Task<TokenResponse> ProcessDeviceCodeRequestAsync(TokenRequestValidationResult request)
    {
        var (accessToken, refreshToken) = await CreateAccessTokenAsync(request.ValidatedRequest);
        var response = new TokenResponse
        {
                AccessToken = accessToken,
                AccessTokenLifetime = request.ValidatedRequest.AccessTokenLifetime,
                Custom = request.CustomResponse,
                Scope = request.ValidatedRequest.DeviceCode.AuthorizedScopes.ToSpaceSeparatedString()
        };
 
        if (refreshToken.IsPresent())
        {
            response.RefreshToken = refreshToken;
        }
 
        if (request.ValidatedRequest.DeviceCode.IsOpenId)
        {
            // load the client that belongs to the device code
            Client client = null;
            if (request.ValidatedRequest.DeviceCode.ClientId != null)
            {
                client = await Clients.FindEnabledClientByIdAsync(request.ValidatedRequest.DeviceCode.ClientId);
            }
            if (client == null)
            {
                throw new InvalidOperationException("Client does not exist anymore.");
            }
 
            var parsedScopesResult = ScopeParser.ParseScopeValues(request.ValidatedRequest.DeviceCode.AuthorizedScopes);
            var validatedResources = await Resources.CreateResourceValidationResult(parsedScopesResult);
                
            var tokenRequest = new TokenCreationRequest
            {
                Subject = request.ValidatedRequest.DeviceCode.Subject,
                ValidatedResources = validatedResources,
                AccessTokenToHash = response.AccessToken,
                ValidatedRequest = request.ValidatedRequest
            };
 
            var idToken = await TokenService.CreateIdentityTokenAsync(tokenRequest);
            var jwt = await TokenService.CreateSecurityTokenAsync(idToken);
            response.IdentityToken = jwt;
        }
 
        return response;
    }

    protected virtual Task<TokenResponse> ProcessExtensionGrantRequestAsync(TokenRequestValidationResult request)
        => ProcessTokenRequestAsync(request);
    
    protected virtual async Task<TokenResponse> ProcessTokenRequestAsync(TokenRequestValidationResult validationResult)
    {
        (var accessToken, var refreshToken) = await CreateAccessTokenAsync(validationResult.ValidatedRequest);
        var response = new TokenResponse
        {
            AccessToken = accessToken,
            AccessTokenLifetime = validationResult.ValidatedRequest.AccessTokenLifetime,
            Custom = validationResult.CustomResponse,
            Scope = validationResult.ValidatedRequest.ValidatedResources.RawScopeValues.ToSpaceSeparatedString()
        };
 
        if (refreshToken.IsPresent())
        {
            response.RefreshToken = refreshToken;
        }
 
        return response;
    }

    protected virtual async Task<(string accessToken, string refreshToken)> CreateAccessTokenAsync(ValidatedTokenRequest request)
    {
        TokenCreationRequest tokenRequest;
        bool createRefreshToken;
 
        if (request.AuthorizationCode != null)
        {
            createRefreshToken = request.AuthorizationCode.RequestedScopes.Contains(IdentityServerConstants.StandardScopes.OfflineAccess);
 
            // load the client that belongs to the authorization code
            Client client = null;
            if (request.AuthorizationCode.ClientId != null)
            {
                client = await Clients.FindEnabledClientByIdAsync(request.AuthorizationCode.ClientId);
            }
            if (client == null)
            {
                throw new InvalidOperationException("Client does not exist anymore.");
            }
 
            var parsedScopesResult = ScopeParser.ParseScopeValues(request.AuthorizationCode.RequestedScopes);
            var validatedResources = await Resources.CreateResourceValidationResult(parsedScopesResult);
 
            tokenRequest = new TokenCreationRequest
            {
                    Subject = request.AuthorizationCode.Subject,
                    Description = request.AuthorizationCode.Description,
                    ValidatedResources = validatedResources,
                    ValidatedRequest = request
            };
        }
        else if (request.DeviceCode != null)
        {
            createRefreshToken = request.DeviceCode.AuthorizedScopes.Contains(IdentityServerConstants.StandardScopes.OfflineAccess);
 
            Client client = null;
            if (request.DeviceCode.ClientId != null)
            {
                client = await Clients.FindEnabledClientByIdAsync(request.DeviceCode.ClientId);
            }
            if (client == null)
            {
                throw new InvalidOperationException("Client does not exist anymore.");
            }
 
            var parsedScopesResult = ScopeParser.ParseScopeValues(request.DeviceCode.AuthorizedScopes);
            var validatedResources = await Resources.CreateResourceValidationResult(parsedScopesResult);
 
            tokenRequest = new TokenCreationRequest
            {
                Subject = request.DeviceCode.Subject,
                Description = request.DeviceCode.Description,
                ValidatedResources = validatedResources,
                ValidatedRequest = request
             };
        }
        else
        {
            createRefreshToken = request.ValidatedResources.Resources.OfflineAccess;
 
            tokenRequest = new TokenCreationRequest
            {
                Subject = request.Subject,
                ValidatedResources = request.ValidatedResources,
                ValidatedRequest = request
            };
        }
 
        var at = await TokenService.CreateAccessTokenAsync(tokenRequest);
        var accessToken = await TokenService.CreateSecurityTokenAsync(at);
 
        if (createRefreshToken)
        {
            var refreshToken = await RefreshTokenService.CreateRefreshTokenAsync(tokenRequest.Subject, at, request.Client);
            return (accessToken, refreshToken);
        }
 
        return (accessToken, null);
    }

    protected virtual async Task<string> CreateIdTokenFromRefreshTokenRequestAsync(ValidatedTokenRequest request, string newAccessToken)
    {
        if (request.RefreshToken.Scopes.Contains(OidcConstants.StandardScopes.OpenId))
        {
            var oldAccessToken = request.RefreshToken.AccessToken;
 
            var parsedScopesResult = ScopeParser.ParseScopeValues(oldAccessToken.Scopes);
            var validatedResources = await Resources.CreateResourceValidationResult(parsedScopesResult);
 
            var tokenRequest = new TokenCreationRequest
            {
                Subject = request.RefreshToken.Subject,
                ValidatedResources = validatedResources,
                ValidatedRequest = request,
                AccessTokenToHash = newAccessToken
            };
 
            var idToken = await TokenService.CreateIdentityTokenAsync(tokenRequest);
            return await TokenService.CreateSecurityTokenAsync(idToken);
        }
 
        return null;
    }
}
//---------------------------------Ʌ

//------------------------------->>
public interface IEndpointHandler
{
    Task<IEndpointResult> ProcessAsync(HttpContext context);
}
//-------------------------------<<

//-------------------------------------------V
internal abstract class AuthorizeEndpointBase : IEndpointHandler
{
    private readonly IAuthorizeResponseGenerator _authorizeResponseGenerator;
 
    private readonly IEventService _events;
    private readonly IdentityServerOptions _options;
 
    private readonly IAuthorizeInteractionResponseGenerator _interactionGenerator;
 
    private readonly IAuthorizeRequestValidator _validator;
 
    protected AuthorizeEndpointBase(
        IEventService events,
        ILogger<AuthorizeEndpointBase> logger,
        IdentityServerOptions options,
        IAuthorizeRequestValidator validator,
        IAuthorizeInteractionResponseGenerator interactionGenerator,
        IAuthorizeResponseGenerator authorizeResponseGenerator,
        IUserSession userSession)
    {
        _events = events;
        _options = options;
        Logger = logger;
        _validator = validator;
        _interactionGenerator = interactionGenerator;
        _authorizeResponseGenerator = authorizeResponseGenerator;
        UserSession = userSession;
    }

    protected ILogger Logger { get; private set; }
 
    protected IUserSession UserSession { get; private set; }
 
    public abstract Task<IEndpointResult> ProcessAsync(HttpContext context);

    internal async Task<IEndpointResult> ProcessAuthorizeRequestAsync(NameValueCollection parameters, ClaimsPrincipal user, ConsentResponse consent)
    {          
        var result = await _validator.ValidateAsync(parameters, user);
        if (result.IsError)
        {
            return await CreateErrorResultAsync("Request validation failed", result.ValidatedRequest, result.Error, result.ErrorDescription);
        }
 
        var request = result.ValidatedRequest;
 
        // determine user interaction
        var interactionResult = await _interactionGenerator.ProcessInteractionAsync(request, consent);
        if (interactionResult.IsError)
        {
            return await CreateErrorResultAsync("Interaction generator error", request, interactionResult.Error, interactionResult.ErrorDescription, false);
        }
        if (interactionResult.IsLogin)
        {
            return new LoginPageResult(request);
        }
        if (interactionResult.IsConsent)
        {
            return new ConsentPageResult(request);
        }
        if (interactionResult.IsRedirect)
        {
            return new CustomRedirectResult(request, interactionResult.RedirectUrl);
        }
 
        var response = await _authorizeResponseGenerator.CreateResponseAsync(request);
 
        await RaiseResponseEventAsync(response);
 
 
        return new AuthorizeResult(response);
    }

    protected async Task<IEndpointResult> CreateErrorResultAsync(
        string logMessage, 
        ValidatedAuthorizeRequest request = null, 
        string error = OidcConstants.AuthorizeErrors.ServerError,
        string errorDescription = null,
        bool logError = true)
    {   
        if (request != null)
        {
                var details = new AuthorizeRequestValidationLog(request, _options.Logging.AuthorizeRequestSensitiveValuesFilter);
                Logger.LogInformation("{@validationDetails}", details);
        }
 
        await RaiseFailureEventAsync(request, error, errorDescription);
 
        return new AuthorizeResult(new AuthorizeResponse
        {
            Request = request,
            Error = error,
            ErrorDescription = errorDescription,
            SessionState = request?.GenerateSessionStateValue()
         });
    }

    // ...
}
//-------------------------------------------Ʌ

//--------------------------------------V
internal class AuthorizeCallbackEndpoint : AuthorizeEndpointBase
{
    private readonly IConsentMessageStore _consentResponseStore;
    private readonly IAuthorizationParametersMessageStore _authorizationParametersMessageStore;
 
    public AuthorizeCallbackEndpoint(
        IEventService events,
        ILogger<AuthorizeCallbackEndpoint> logger,
        IdentityServerOptions options,
        IAuthorizeRequestValidator validator,
        IAuthorizeInteractionResponseGenerator interactionGenerator,
        IAuthorizeResponseGenerator authorizeResponseGenerator,
        IUserSession userSession,
        IConsentMessageStore consentResponseStore,
        IAuthorizationParametersMessageStore authorizationParametersMessageStore = null)
        : base(events, logger, options, validator, interactionGenerator, authorizeResponseGenerator, userSession)
    {
        _consentResponseStore = consentResponseStore;
        _authorizationParametersMessageStore = authorizationParametersMessageStore;
    }

    public override async Task<IEndpointResult> ProcessAsync(HttpContext context)
    {
        if (!HttpMethods.IsGet(context.Request.Method))
        {
            Logger.LogWarning("Invalid HTTP method for authorize endpoint.");
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }
 
        Logger.LogDebug("Start authorize callback request");
 
        var parameters = context.Request.Query.AsNameValueCollection();
        if (_authorizationParametersMessageStore != null)
        {
            var messageStoreId = parameters[Constants.AuthorizationParamsStore.MessageStoreIdParameterName];
            var entry = await _authorizationParametersMessageStore.ReadAsync(messageStoreId);
            parameters = entry?.Data.FromFullDictionary() ?? new NameValueCollection();
 
            await _authorizationParametersMessageStore.DeleteAsync(messageStoreId);
        }
 
        var user = await UserSession.GetUserAsync();
        var consentRequest = new ConsentRequest(parameters, user?.GetSubjectId());
        var consent = await _consentResponseStore.ReadAsync(consentRequest.Id);
 
        if (consent != null && consent.Data == null)
        {
            return await CreateErrorResultAsync("consent message is missing data");
        }
 
        try
        {
            var result = await ProcessAuthorizeRequestAsync(parameters, user, consent?.Data);
 
            Logger.LogTrace("End Authorize Request. Result type: {0}", result?.GetType().ToString() ?? "-none-");
 
            return result;
        }
        finally
        {
            if (consent != null)
            {
                await _consentResponseStore.DeleteAsync(consentRequest.Id);
            }
        }
    }
}
//--------------------------------------Ʌ

//--------------------------V
internal class TokenEndpoint : IEndpointHandler
{
    private readonly IClientSecretValidator _clientValidator;
    private readonly ITokenRequestValidator _requestValidator;
    private readonly ITokenResponseGenerator _responseGenerator;  // <----------------------
    private readonly IEventService _events;
    private readonly ILogger _logger;

    public TokenEndpoint(
        IClientSecretValidator clientValidator, 
        ITokenRequestValidator requestValidator, 
        ITokenResponseGenerator responseGenerator, 
        IEventService events, 
        ILogger<TokenEndpoint> logger)
    {
        _clientValidator = clientValidator;
        _requestValidator = requestValidator;
        _responseGenerator = responseGenerator;
        _events = events;
        _logger = logger;
    }

    public async Task<IEndpointResult> ProcessAsync(HttpContext context)
    {
        _logger.LogTrace("Processing token request.");
 
         // validate HTTP
        if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.HasApplicationFormContentType())
        {
            _logger.LogWarning("Invalid HTTP request for token endpoint");
            return Error(OidcConstants.TokenErrors.InvalidRequest);
        }
 
        return await ProcessTokenRequestAsync(context);
    }

    private async Task<IEndpointResult> ProcessTokenRequestAsync(HttpContext context)
    {
        _logger.LogDebug("Start token request.");
 
        // validate client
        var clientResult = await _clientValidator.ValidateAsync(context);
 
        if (clientResult.Client == null)
        {
            return Error(OidcConstants.TokenErrors.InvalidClient);
        }
 
        // validate request
        var form = (await context.Request.ReadFormAsync()).AsNameValueCollection();
        _logger.LogTrace("Calling into token request validator: {type}", _requestValidator.GetType().FullName);
        var requestResult = await _requestValidator.ValidateRequestAsync(form, clientResult);
 
        if (requestResult.IsError)
        {
            await _events.RaiseAsync(new TokenIssuedFailureEvent(requestResult));
            return Error(requestResult.Error, requestResult.ErrorDescription, requestResult.CustomResponse);
        }
 
        // create response
        _logger.LogTrace("Calling into token request response generator: {type}", _responseGenerator.GetType().FullName);
        var response = await _responseGenerator.ProcessAsync(requestResult);
 
        await _events.RaiseAsync(new TokenIssuedSuccessEvent(response, requestResult));
        LogTokens(response, requestResult);
 
        // return result
        _logger.LogDebug("Token request success.");

        return new TokenResult(response);
    }

    private TokenErrorResult Error(string error, string errorDescription = null, Dictionary<string, object> custom = null)
    {
        var response = new TokenErrorResponse
        {
            Error = error,
            ErrorDescription = errorDescription,
            Custom = custom
        };
 
        return new TokenErrorResult(response);
    }

    private void LogTokens(TokenResponse response, TokenRequestValidationResult requestResult)
    {
        var clientId = $"{requestResult.ValidatedRequest.Client.ClientId} ({requestResult.ValidatedRequest.Client?.ClientName ?? "no name set"})";
        var subjectId = requestResult.ValidatedRequest.Subject?.GetSubjectId() ?? "no subject";
 
        if (response.IdentityToken != null)
            _logger.LogTrace("Identity token issued for {clientId} / {subjectId}: {token}", clientId, subjectId, response.IdentityToken);
        if (response.RefreshToken != null)
                _logger.LogTrace("Refresh token issued for {clientId} / {subjectId}: {token}", clientId, subjectId, response.RefreshToken);
        if (response.AccessToken != null)
            _logger.LogTrace("Access token issued for {clientId} / {subjectId}: {token}", clientId, subjectId, response.AccessToken);
    }
}
//--------------------------Ʌ
```


## Helpers

```C# 
public static class UIConstants
{
    // the limit after which old messages are purged
    public const int CookieMessageThreshold = 2;
 
    public static class DefaultRoutePathParams
    {
        public const string Error = "errorId";
        public const string Login = "returnUrl";
        public const string Consent = "returnUrl";
        public const string Logout = "logoutId";
        public const string EndSessionCallback = "endSessionId";
        public const string Custom = "returnUrl";
        public const string UserCode = "userCode";
    }
 
    public static class DefaultRoutePaths
    {
        public const string Login = "/account/login";
        public const string Logout = "/account/logout";
        public const string Consent = "/consent";
        public const string Error = "/home/error";
        public const string DeviceVerification = "/device";
    }
}

public static class EndpointNames
{
    public const string Authorize = "Authorize";
    public const string Token = "Token";
    public const string DeviceAuthorization = "DeviceAuthorization";
    public const string Discovery = "Discovery";
    public const string Introspection = "Introspection";
    public const string Revocation = "Revocation";
    public const string EndSession = "Endsession";
    public const string CheckSession = "Checksession";
    public const string UserInfo = "Userinfo";
}

public static class ProtocolRoutePaths
{
    public const string ConnectPathPrefix       = "connect";
 
    public const string Authorize               = ConnectPathPrefix + "/authorize";
    public const string AuthorizeCallback       = Authorize + "/callback";
    public const string DiscoveryConfiguration  = ".well-known/openid-configuration";
    public const string DiscoveryWebKeys        = DiscoveryConfiguration + "/jwks";
    public const string Token                   = ConnectPathPrefix + "/token";
    public const string Revocation              = ConnectPathPrefix + "/revocation";
    public const string UserInfo                = ConnectPathPrefix + "/userinfo";
    public const string Introspection           = ConnectPathPrefix + "/introspect";
    public const string EndSession              = ConnectPathPrefix + "/endsession";
    public const string EndSessionCallback      = EndSession + "/callback";
    public const string CheckSession            = ConnectPathPrefix + "/checksession";
    public const string DeviceAuthorization     = ConnectPathPrefix + "/deviceauthorization";
 
    public const string MtlsPathPrefix          = ConnectPathPrefix + "/mtls";
    public const string MtlsToken               = MtlsPathPrefix + "/token";
    public const string MtlsRevocation          = MtlsPathPrefix + "/revocation";
    public const string MtlsIntrospection       = MtlsPathPrefix + "/introspect";
    public const string MtlsDeviceAuthorization = MtlsPathPrefix + "/deviceauthorization";
 
    public static readonly string[] CorsPaths =
    {
        DiscoveryConfiguration,
        DiscoveryWebKeys,
        Token,
        UserInfo,
        Revocation
    };
}

public static class TokenTypeHints
{
    public const string RefreshToken = "refresh_token";
    public const string AccessToken  = "access_token";
}
 
public static List<string> SupportedTokenTypeHints = new List<string>
{
    TokenTypeHints.RefreshToken,
    TokenTypeHints.AccessToken
};

internal class Decorator<TService>
{
    public TService Instance { get; set; }
 
    public Decorator(TService instance)
    {
        Instance = instance;
    }
}
 
internal class Decorator<TService, TImpl> : Decorator<TService> where TImpl : class, TService
{
    public Decorator(TImpl instance) : base(instance) { }
}
```




## IdentityModel Source Code


```C#
// IdentityModel.Client

public class DiscoveryPolicy
{

}

public class DiscoveryDocumentResponse
{

}

```

```C#
//------------------------V
public class TokenResponse : ProtocolResponse
{
    public string? AccessToken => TryGet(OidcConstants.TokenResponse.AccessToken);
    public string? IdentityToken => TryGet(OidcConstants.TokenResponse.IdentityToken);
    public string? Scope => TryGet(OidcConstants.TokenResponse.Scope);
    public string? IssuedTokenType => TryGet(OidcConstants.TokenResponse.IssuedTokenType);
    public string? TokenType => TryGet(OidcConstants.TokenResponse.TokenType);
    public string? RefreshToken => TryGet(OidcConstants.TokenResponse.RefreshToken);
    public string? ErrorDescription => TryGet(OidcConstants.TokenResponse.ErrorDescription);
    public int ExpiresIn => TryGet(OidcConstants.TokenResponse.ExpiresIn);
}
//------------------------Ʌ

```