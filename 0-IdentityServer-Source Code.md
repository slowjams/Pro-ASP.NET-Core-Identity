IdentityServer4 Source Code
============================

```C#
//------------------V
public class Program 
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddRazorPages();

        builder.Services
            .AddIdentityServer()
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryClients(Config.Clients)
            .AddTestUsers(TestUsers.Users);

        var app = builder.Build();

        // ...
        app.UseRouting();

        app.UseIdentityServer();   // <-------------------------a0

        app.UseAuthorization();

        app.MapRazorPages().RequireAuthorization();

        app.Run();
    }
}
//------------------Ʌ
```


* How does `.well-known/openid-configuration` or `/connect/authorize` response (`/Account/Login` page) get generated? Inside `IdentityServerMiddleware` q1, q2
* How does `/connect/authorize/callback?client_id=imagegalleryclient&redirect_uri=https%3A%2F%2Flocalhost%3A7184%2Fsignin-oidc&response_type=code&scope=openid%20profile&code_challenge=C65uIECsH4&code_challenge_method=S256XXX` request get handled? (c flag)

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
            .AddCookieAuthentication()  // <--------------------------------------!
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
        builder.Services.AddSingleton(resolver => resolver.GetRequiredService<IOptions<IdentityServerOptions>>().Value);
        builder.Services.AddTransient(resolver => resolver.GetRequiredService<IOptions<IdentityServerOptions>>().Value.PersistentGrants);
        builder.Services.AddHttpClient();

        return builder;
    }

    public static IIdentityServerBuilder AddCookieAuthentication(this IIdentityServerBuilder builder)
    {
        builder.Services
            .AddAuthentication(IdentityServerConstants.DefaultCookieAuthenticationScheme)  // idsrvexternal
            .AddCookie(IdentityServerConstants.DefaultCookieAuthenticationScheme)
            .AddCookie(IdentityServerConstants.ExternalCookieAuthenticationScheme);  // <--------------------------------------itpc
 
        builder.Services.AddSingleton<IConfigureOptions<CookieAuthenticationOptions>, ConfigureInternalCookieOptions>();
        builder.Services.AddSingleton<IPostConfigureOptions<CookieAuthenticationOptions>, PostConfigureInternalCookieOptions>();
        builder.Services.AddTransientDecorator<IAuthenticationService, IdentityServerAuthenticationService>();  // <---------this decorate original asp.net's AuthenticationService
        builder.Services.AddTransientDecorator<IAuthenticationHandlerProvider, FederatedSignoutAuthenticationHandlerProvider>();
 
        return builder;
    }

    public static IIdentityServerBuilder AddDefaultEndpoints(this IIdentityServerBuilder builder)
    {
        builder.Services.AddTransient<IEndpointRouter, EndpointRouter>();  // <---------------------------------q1, it is IdentityServer's own Router like UseRouting()
 
        builder.AddEndpoint<AuthorizeCallbackEndpoint>(EndpointNames.Authorize, ProtocolRoutePaths.AuthorizeCallback.EnsureLeadingSlash());   // <---------------------c1.0
        builder.AddEndpoint<AuthorizeEndpoint>(EndpointNames.Authorize, ProtocolRoutePaths.Authorize.EnsureLeadingSlash()); // <-------q1,q2 handles https://localhost:5001/connect/authorize
        builder.AddEndpoint<CheckSessionEndpoint>(EndpointNames.CheckSession, ProtocolRoutePaths.CheckSession.EnsureLeadingSlash());
        builder.AddEndpoint<DeviceAuthorizationEndpoint>(EndpointNames.DeviceAuthorization, ProtocolRoutePaths.DeviceAuthorization.EnsureLeadingSlash());
        builder.AddEndpoint<DiscoveryKeyEndpoint>(EndpointNames.Discovery, ProtocolRoutePaths.DiscoveryWebKeys.EnsureLeadingSlash());
        builder.AddEndpoint<DiscoveryEndpoint>(EndpointNames.Discovery, ProtocolRoutePaths.DiscoveryConfiguration.EnsureLeadingSlash());  // <---------------q1
        builder.AddEndpoint<EndSessionCallbackEndpoint>(EndpointNames.EndSession, ProtocolRoutePaths.EndSessionCallback.EnsureLeadingSlash());  //<----------so
        builder.AddEndpoint<EndSessionEndpoint>(EndpointNames.EndSession, ProtocolRoutePaths.EndSession.EnsureLeadingSlash());
        builder.AddEndpoint<IntrospectionEndpoint>(EndpointNames.Introspection, ProtocolRoutePaths.Introspection.EnsureLeadingSlash());
        builder.AddEndpoint<TokenRevocationEndpoint>(EndpointNames.Revocation, ProtocolRoutePaths.Revocation.EnsureLeadingSlash());  // handles https://localhost:5001/connect/revocation
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
        builder.Services.TryAddTransient<ITokenResponseGenerator, TokenResponseGenerator>();  // <-------------------------
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
 
           
        if (options == null) 1
            options = new IdentityServerMiddlewareOptions();
        options.AuthenticationMiddleware(app);   // <-------------call app.UseAuthentication() so it's not necessary to have both
 
        app.UseMiddleware<MutualTlsEndpointMiddleware>();  // <---------------------------------------a0.2
        app.UseMiddleware<IdentityServerMiddleware>();     // <--------------------------------------!a0.3., q1
 
        return app;
    }

    // ...
}
//------------------------------------------------------------Ʌ

//-------------------------------------------------V
public static class IdentityServerBuilderExtensions
{
    public static IIdentityServerBuilder AddTestUsers(this IIdentityServerBuilder builder, List<TestUser> users)
    {
        builder.Services.AddSingleton(new TestUserStore(users));
        builder.AddProfileService<TestUserProfileService>();
        builder.AddResourceOwnerValidator<TestUserResourceOwnerPasswordValidator>();
            
        builder.AddBackchannelAuthenticationUserValidator<TestBackchannelLoginUserValidator>();

        return builder;
    }
}
//-------------------------------------------------Ʌ

//----------------------------------------------------V
public static class AuthenticationPropertiesExtensions
{
    internal const string SessionIdKey = "session_id";
    internal const string ClientListKey = "client_list";

    public static string GetSessionId(this AuthenticationProperties properties)
    {
        if (properties?.Items.ContainsKey(SessionIdKey) == true)
        {
            return properties.Items[SessionIdKey];
        }

        return null;
    }

    public static void SetSessionId(this AuthenticationProperties properties, string sid)
    {
        properties.Items[SessionIdKey] = sid;
    }

    public static IEnumerable<string> GetClientList(this AuthenticationProperties properties)
    {
        if (properties?.Items.ContainsKey(ClientListKey) == true)
        {
            var value = properties.Items[ClientListKey];
            return DecodeList(value);
        }

        return Enumerable.Empty<string>();
    }

    public static void RemoveClientList(this AuthenticationProperties properties)
    {
        properties?.Items.Remove(ClientListKey);
    }

    public static void SetClientList(this AuthenticationProperties properties, IEnumerable<string> clientIds)
    {
        var value = EncodeList(clientIds);
        if (value == null)
        {
            properties.Items.Remove(ClientListKey);
        }
        else
        {
            properties.Items[ClientListKey] = value;
        }
    }

    public static void AddClientId(this AuthenticationProperties properties, string clientId)
    {
        if (clientId == null) throw new ArgumentNullException(nameof(clientId));

        var clients = properties.GetClientList();
        if (!clients.Contains(clientId))
        {
            var update = clients.ToList();
            update.Add(clientId);
                
            properties.SetClientList(update);
        }
    }

    private static IEnumerable<string> DecodeList(string value)
    {
        if (value.IsPresent())
        {
            var bytes = Base64Url.Decode(value);
            value = Encoding.UTF8.GetString(bytes);
            return ObjectSerializer.FromString<string[]>(value);
        }

        return Enumerable.Empty<string>();
    }

    private static string EncodeList(IEnumerable<string> list)
    {
        if (list != null && list.Any())
        {
            var value = ObjectSerializer.ToString(list);
            var bytes = Encoding.UTF8.GetBytes(value);
            value = Base64Url.Encode(bytes);
            return value;
        }

        return null;
    }
}
//----------------------------------------------------Ʌ

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
                var result = await endpoint.ProcessAsync(context);  // <--------------------a1.2, c3.1
 
                if (result != null)
                {
                    await result.ExecuteAsync(context);  // <--------------------a1.3, q1, q2, c3.2, p2         
                    // result is from abastract Duende.IdentityServer.Endpoints.Results.AuthorizeInteractionPageResult
                    // and it can be e.g Duende.IdentityServer.Endpoints.Results.LoginPageResult or AuthorizeResult (c3.1)
                    // ExecuteAsync will do a redirect to users with corrsponding Razor page
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

//------------------------------V  handle /connect/authorize
internal class AuthorizeEndpoint : AuthorizeEndpointBase
{
    public AuthorizeEndpoint(
        IEventService events,
        ILogger<AuthorizeEndpoint> logger,
        IdentityServerOptions options,
        IAuthorizeRequestValidator validator,
        IAuthorizeInteractionResponseGenerator interactionGenerator,
        IAuthorizeResponseGenerator authorizeResponseGenerator,
        IUserSession userSession,
        IConsentMessageStore consentResponseStore,
        IAuthorizationParametersMessageStore authorizationParametersMessageStore = null)
        : base(events, logger, options, validator, interactionGenerator, authorizeResponseGenerator, userSession, consentResponseStore, authorizationParametersMessageStore) { }

    public override async Task<IEndpointResult> ProcessAsync(HttpContext context)
    {
        using var activity = Tracing.BasicActivitySource.StartActivity(IdentityServerConstants.EndpointNames.Authorize + "Endpoint");

        Logger.LogDebug("Start authorize request");

        NameValueCollection values;

        if (HttpMethods.IsGet(context.Request.Method))
        {
            values = context.Request.Query.AsNameValueCollection();
        }
        else if (HttpMethods.IsPost(context.Request.Method))
        {
            if (!context.Request.HasApplicationFormContentType())
            {
                return new StatusCodeResult(HttpStatusCode.UnsupportedMediaType);
            }

            values = context.Request.Form.AsNameValueCollection();
        }
        else
        {
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var user = await UserSession.GetUserAsync();  // <---------------------------------------p1, ask CookieAuthenticationHandler to user from ticket
    
        var result = await ProcessAuthorizeRequestAsync(values, user);   // <--------------------------------------q2, p2
        /* result is Duende.IdentityServer.Endpoints.Results.LoginPageResult        
        { 
          RedirectUrl = "/Account/Login" // <---------------------------------------redirect users to the corresponding Razor pages
          Request = {Duende.IdentityServer.Validation.ValidatedAuthorizeRequest}
          ReturnUrlParameterName = "ReturnUrl"
        }
        */

        Logger.LogTrace("End authorize request. result type: {0}", result?.GetType().ToString() ?? "-none-");

        return result;
    }
}
//------------------------------Ʌ

//--------------------------------------V handle /connect/authorize/callback and generate the authCode
internal class AuthorizeCallbackEndpoint : AuthorizeEndpointBase
{
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
        : base(events, logger, options, validator, interactionGenerator, authorizeResponseGenerator, userSession, consentResponseStore, authorizationParametersMessageStore)
    {
    }

    public override async Task<IEndpointResult> ProcessAsync(HttpContext context)
    {
        using var activity = Tracing.BasicActivitySource.StartActivity(IdentityServerConstants.EndpointNames.Authorize + "CallbackEndpoint");
        
        if (!HttpMethods.IsGet(context.Request.Method))
        {
            Logger.LogWarning("Invalid HTTP method for authorize endpoint.");
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        Logger.LogDebug("Start authorize callback request");

        var parameters = context.Request.Query.AsNameValueCollection();
        var user = await UserSession.GetUserAsync();  // <-------------------ac0, calls HttpContext.GetCookieAuthenticationSchemeAsync() to use Cookie handler to get user
                                                      // this user (ClaimsPrinciple) will be used to generate authCode (actualluy it is a "primary key"),
                                                      //  so this user will be saved on IDP's end and the primary key as authCode will be returned to client
        var result = await ProcessAuthorizeRequestAsync(parameters, user, true);  // <--------------------------------ac1
        /*  result is Duende.IdentityServer.Endpoints.Results.AuthorizeResult}, the content is          
           {
              AccessToken = null
              AccessTokenLifetime = 0
              Code = "CFDB61434AA087352A7D8A743C81F544C0CBDB3E674AC6FFA7E0AE92FDFD967-1"
              IdentityToken = null
              Issuer = "https://localhost:5001"
              RedirectUri = "https://localhost:7184/signin-oidc"
              Request = {Duende.IdentityServer.Validation.ValidatedAuthorizeRequest}
              Scope = "openid profile"
              SessionState = "0A1p6zn4hcizfpMeipQEEgmOavZyi6IKFOR1D_UY.90CD968BDBEBFFD7839BD0AEA5E74CE"
              State = "CfDJ8Fr2n1UxboNJlI8uHVA4skobbheKboVu0uc-Sw82YrXv0FSfGKT7h0rLyCJv18oA_-76qioJpUgqSBOy64XArrHcs_bRqkg1q7ZSkFLeT..."
           }
        */

        /*  result can also be Duende.IdentityServer.Endpoints.Results.ConsentPageResult for itp flow
           
        */

        Logger.LogTrace("End Authorize Request. Result type: {0}", result?.GetType().ToString() ?? "-none-");

        return result;
    }
}
//--------------------------------------Ʌ

//-------------------------------------V
public class AuthorizeResponseGenerator : IAuthorizeResponseGenerator
{
    protected IdentityServerOptions Options;
    protected readonly ITokenService TokenService;
    protected readonly IAuthorizationCodeStore AuthorizationCodeStore;
    protected readonly IEventService Events;
    protected readonly ILogger Logger;
    protected readonly IClock Clock;
    protected readonly IKeyMaterialService KeyMaterialService;

    public AuthorizeResponseGenerator(
        IdentityServerOptions options,
        IClock clock,
        ITokenService tokenService,
        IKeyMaterialService keyMaterialService,
        IAuthorizationCodeStore authorizationCodeStore,
        ILogger<AuthorizeResponseGenerator> logger,
        IEventService events)
    {
        Options = options;
        Clock = clock;
        TokenService = tokenService;
        KeyMaterialService = keyMaterialService;
        AuthorizationCodeStore = authorizationCodeStore;
        Logger = logger;
        Events = events;
    }

    public virtual async Task<AuthorizeResponse> CreateResponseAsync(ValidatedAuthorizeRequest request)   // <----------------------ac2.2
    {
        using var activity = Tracing.BasicActivitySource.StartActivity("AuthorizeResponseGenerator.CreateResponse");

        if (request.GrantType == GrantType.AuthorizationCode)
        {
            return await CreateCodeFlowResponseAsync(request);   // <----------------------ac2.3
        }
        if (request.GrantType == GrantType.Implicit)
        {
            return await CreateImplicitFlowResponseAsync(request);
        }
        if (request.GrantType == GrantType.Hybrid)
        {
            return await CreateHybridFlowResponseAsync(request);
        }

        Logger.LogError("Unsupported grant type: " + request.GrantType);
        throw new InvalidOperationException("invalid grant type: " + request.GrantType);
    }

    protected virtual async Task<AuthorizeResponse> CreateHybridFlowResponseAsync(ValidatedAuthorizeRequest request)
    {
        Logger.LogDebug("Creating Hybrid Flow response.");

        var code = await CreateCodeAsync(request);
        var id = await AuthorizationCodeStore.StoreAuthorizationCodeAsync(code);

        var response = await CreateImplicitFlowResponseAsync(request, id);
        response.Code = id;

        return response;
    }

    protected virtual async Task<AuthorizeResponse> CreateCodeFlowResponseAsync(ValidatedAuthorizeRequest request)  // <----------------------ac2.4
    {
        Logger.LogDebug("Creating Authorization Code Flow response.");

        var code = await CreateCodeAsync(request);  // <----------------------ac2.5.  code contain user info
        var id = await AuthorizationCodeStore.StoreAuthorizationCodeAsync(code);  // <---------ac2.5. id might be the key for idp's internal database to local user when receiving
                                                                                  // https://localhost:7184/signin-oidc POST
        var response = new AuthorizeResponse
        {
            Issuer = request.IssuerName,
            Request = request,
            Code = id,
            SessionState = request.GenerateSessionStateValue()
        };

        return response;
    }

    protected virtual async Task<AuthorizeResponse> CreateImplicitFlowResponseAsync(ValidatedAuthorizeRequest request, string authorizationCode = null)
    {
        Logger.LogDebug("Creating Implicit Flow response.");

        string accessTokenValue = null;
        int accessTokenLifetime = 0;

        var responseTypes = request.ResponseType.FromSpaceSeparatedString();

        if (responseTypes.Contains(OidcConstants.ResponseTypes.Token))
        {
            var tokenRequest = new TokenCreationRequest
            {
                Subject = request.Subject,
                // implicit responses do not allow resource indicator, so no resource indicator filtering needed here
                ValidatedResources = request.ValidatedResources,

                ValidatedRequest = request
            };

            var accessToken = await TokenService.CreateAccessTokenAsync(tokenRequest);
            accessTokenLifetime = accessToken.Lifetime;

            accessTokenValue = await TokenService.CreateSecurityTokenAsync(accessToken);
        }

        string jwt = null;
        if (responseTypes.Contains(OidcConstants.ResponseTypes.IdToken))
        {
            string stateHash = null;
                
            if (Options.EmitStateHash && request.State.IsPresent())
            {
                var credential = await KeyMaterialService.GetSigningCredentialsAsync(request.Client.AllowedIdentityTokenSigningAlgorithms);
                if (credential == null)
                {
                    throw new InvalidOperationException("No signing credential is configured.");
                }

                var algorithm = credential.Algorithm;
                stateHash = CryptoHelper.CreateHashClaimValue(request.State, algorithm);
            }

            var tokenRequest = new TokenCreationRequest
            {
                ValidatedRequest = request,
                Subject = request.Subject,
                ValidatedResources = request.ValidatedResources,
                Nonce = request.Raw.Get(OidcConstants.AuthorizeRequest.Nonce),
                IncludeAllIdentityClaims = !request.AccessTokenRequested,
                AccessTokenToHash = accessTokenValue,
                AuthorizationCodeToHash = authorizationCode,
                StateHash = stateHash
            };

            var idToken = await TokenService.CreateIdentityTokenAsync(tokenRequest);
            jwt = await TokenService.CreateSecurityTokenAsync(idToken);
        }

        var response = new AuthorizeResponse
        {
            Request = request,
            AccessToken = accessTokenValue,
            AccessTokenLifetime = accessTokenLifetime,
            IdentityToken = jwt,
            SessionState = request.GenerateSessionStateValue()
        };

        return response;
    }

    protected virtual async Task<AuthorizationCode> CreateCodeAsync(ValidatedAuthorizeRequest request)   // <----------------------c3.3
    {
        string stateHash = null;
        if (Options.EmitStateHash && request.State.IsPresent())
        {
            var credential = await KeyMaterialService.GetSigningCredentialsAsync(request.Client.AllowedIdentityTokenSigningAlgorithms);
            if (credential == null)
            {
                throw new InvalidOperationException("No signing credential is configured.");
            }

            var algorithm = credential.Algorithm;
            stateHash = CryptoHelper.CreateHashClaimValue(request.State, algorithm);
        }

        var code = new AuthorizationCode   // <----------------------c3.4.! <-----------------that's how authCode generated
        {
            CreationTime = Clock.UtcNow.UtcDateTime,
            ClientId = request.Client.ClientId,
            Lifetime = request.Client.AuthorizationCodeLifetime,
            Subject = request.Subject,  // <-----------------------------user's ClaimsPrincipal is needed to create authCode
            SessionId = request.SessionId,
            Description = request.Description,
            CodeChallenge = request.CodeChallenge.Sha256(),
            CodeChallengeMethod = request.CodeChallengeMethod,
            DPoPKeyThumbprint = request.DPoPKeyThumbprint,

            IsOpenId = request.IsOpenIdRequest,
            RequestedScopes = request.ValidatedResources.RawScopeValues,
            RequestedResourceIndicators = request.RequestedResourceIndicators,
            RedirectUri = request.RedirectUri,
            Nonce = request.Nonce,
            StateHash = stateHash,

            WasConsentShown = request.WasConsentShown
        };

        return code;
    }
}
//-------------------------------------Ʌ

//-----------------------------V
internal class UserInfoEndpoint : IEndpointHandler    // handles /connect/userinfo
{
    private readonly BearerTokenUsageValidator _tokenUsageValidator;
    private readonly IUserInfoRequestValidator _requestValidator;
    private readonly IUserInfoResponseGenerator _responseGenerator;
    private readonly ILogger _logger;

    public UserInfoEndpoint(
        BearerTokenUsageValidator tokenUsageValidator, 
        IUserInfoRequestValidator requestValidator, 
        IUserInfoResponseGenerator responseGenerator, 
        ILogger<UserInfoEndpoint> logger)
    {
       // ....
    }

    public async Task<IEndpointResult> ProcessAsync(HttpContext context)
    {
        using var activity = Tracing.BasicActivitySource.StartActivity(IdentityServerConstants.EndpointNames.UserInfo + "Endpoint");
        
        if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsPost(context.Request.Method))
        {
            _logger.LogWarning("Invalid HTTP method for userinfo endpoint.");
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        return await ProcessUserInfoRequestAsync(context);   // <------------------------------u1
    }

    private async Task<IEndpointResult> ProcessUserInfoRequestAsync(HttpContext context)  // <------------------------------u1
    {
        _logger.LogDebug("Start userinfo request");

        // userinfo requires an access token on the request
        var tokenUsageResult = await _tokenUsageValidator.ValidateAsync(context);  // <------------------------------u1.1 userinfo requires an access token on the request
        if (tokenUsageResult.TokenFound == false)
        {
            var error = "No access token found.";

            _logger.LogError(error);
            return Error(OidcConstants.ProtectedResourceErrors.InvalidToken);
        }

        // validate the request
        _logger.LogTrace("Calling into userinfo request validator: {type}", _requestValidator.GetType().FullName);
        var validationResult = await _requestValidator.ValidateRequestAsync(tokenUsageResult.Token);  // <------------------------------u1.2
 
        if (validationResult.IsError)
        {
            //_logger.LogError("Error validating  validationResult.Error);
            return Error(validationResult.Error);
        }

        // generate response
        _logger.LogTrace("Calling into userinfo response generator: {type}", _responseGenerator.GetType().FullName);
        var response = await _responseGenerator.ProcessAsync(validationResult);  // <---------------------------------------u1.3

        _logger.LogDebug("End userinfo request");

        return new UserInfoResult(response);  // <----------------------u1.7
    }

    private IEndpointResult Error(string error, string description = null) => new ProtectedResourceErrorResult(error, description);
}
//-----------------------------Ʌ

//-------------------------------V // handle https://localhost:5001/connect/endsession
internal class EndSessionEndpoint : IEndpointHandler
{
    private readonly IEndSessionRequestValidator _endSessionRequestValidator;

    private readonly ILogger _logger;

    private readonly IUserSession _userSession;

    public EndSessionEndpoint(
        IEndSessionRequestValidator endSessionRequestValidator,
        IUserSession userSession,
        ILogger<EndSessionEndpoint> logger)
    {
        // ...
    }

    public async Task<IEndpointResult> ProcessAsync(HttpContext context)  // <---------------------------e0
    {
        try
        {
            return await ProcessEndSessionAsync(context);
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning(ex, "Invalid HTTP request for end session endpoint");
            return new StatusCodeResult(HttpStatusCode.BadRequest);
        }
    }

    async Task<IEndpointResult> ProcessEndSessionAsync(HttpContext context)  // <---------------------------e1
    {
        NameValueCollection parameters;
        if (HttpMethods.IsGet(context.Request.Method))
        {
            parameters = context.Request.Query.AsNameValueCollection();
        }
        else if (HttpMethods.IsPost(context.Request.Method))
        {
            parameters = (await context.Request.ReadFormAsync()).AsNameValueCollection();
        }
        else
        {
            _logger.LogWarning("Invalid HTTP method for end session endpoint.");
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var user = await _userSession.GetUserAsync();  // <---------------------------e1.1

        _logger.LogDebug("Processing signout request for {subjectId}", user?.GetSubjectId() ?? "anonymous");

        var result = await _endSessionRequestValidator.ValidateAsync(parameters, user);  // <---------------------------e1.2

        if (result.IsError)
            _logger.LogError("Error processing end session request {error}", result.Error);
        else
            _logger.LogDebug("Success validating end session request from {clientId}", result.ValidatedRequest?.Client?.ClientId);

        return new EndSessionResult(result);  // <--------------------e1.3
    }
}
//-------------------------------Ʌ

//---------------------------V
public class EndSessionResult : EndpointResult<EndSessionResult>
{
    public EndSessionValidationResult Result { get; }

    public EndSessionResult(EndSessionValidationResult result)
    {
        Result = result ?? throw new ArgumentNullException(nameof(result));
    }
}

class EndSessionHttpWriter : IHttpResponseWriter<EndSessionResult>
{
    public EndSessionHttpWriter(
        IdentityServerOptions options,
        IClock clock,
        IServerUrls urls,
        IMessageStore<LogoutMessage> logoutMessageStore)
    {
        _options = options;
        _clock = clock;
        _urls = urls;
        _logoutMessageStore = logoutMessageStore;
    }

    private IdentityServerOptions _options;
    private IClock _clock;
    private IServerUrls _urls;
    private IMessageStore<LogoutMessage> _logoutMessageStore;

    public async Task WriteHttpResponse(EndSessionResult result, HttpContext context)  // <--------------------e1.3
    {
        var validatedRequest = result.Result.IsError ? null : result.Result.ValidatedRequest;

        string id = null;

        if (validatedRequest != null)
        {
            var logoutMessage = new LogoutMessage(validatedRequest);
            if (logoutMessage.ContainsPayload)
            {
                var msg = new Message<LogoutMessage>(logoutMessage, _clock.UtcNow.UtcDateTime);
                id = await _logoutMessageStore.WriteAsync(msg);
            }
        }

        var redirect = _options.UserInteraction.LogoutUrl;  // redirect is "/Account/Logout" here  // <--------------------e1.4

        if (redirect.IsLocalUrl())
        {
            redirect = _urls.GetIdentityServerRelativeUrl(redirect);  // redirect is "https://localhost:5001/Account/Logout" here
        }

        if (id != null)
        {
            redirect = redirect.AddQueryString(_options.UserInteraction.LogoutIdParameter, id);  
            // redirect is https://localhost:5001/Account/Logout?logoutId=CfDJ8Fr2n1UxboNJlI8uHVA4skoft053fXDUzUXvku1K6jgfyhhxxx here
        }

        context.Response.Redirect(redirect);  // <--------------------e1.5.
    }
}
//---------------------------Ʌ

//---------------------------------------V
internal class EndSessionCallbackEndpoint : IEndpointHandler  // handles /connect/endsession/callback
{
    private readonly IEndSessionRequestValidator _endSessionRequestValidator;
    private readonly ILogger _logger;

    public EndSessionCallbackEndpoint(
        IEndSessionRequestValidator endSessionRequestValidator,
        ILogger<EndSessionCallbackEndpoint> logger)
    {
        // ...
    }

    public async Task<IEndpointResult> ProcessAsync(HttpContext context)  // <-------------------
    {
        using var activity = Tracing.BasicActivitySource.StartActivity(IdentityServerConstants.EndpointNames.EndSession + "CallbackEndpoint");
        
        if (!HttpMethods.IsGet(context.Request.Method))
        {
            _logger.LogWarning("Invalid HTTP method for end session callback endpoint.");
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        _logger.LogDebug("Processing signout callback request");

        var parameters = context.Request.Query.AsNameValueCollection();
        var result = await _endSessionRequestValidator.ValidateCallbackAsync(parameters);  // <-------------------

        if (!result.IsError)
        {
            _logger.LogInformation("Successful signout callback.");
        }
        else
        {
            _logger.LogError("Error validating signout callback: {error}", result.Error);
        }
            
        return new EndSessionCallbackResult(result);  // <-------------------
    }
}
//---------------------------------------Ʌ

//-----------------------------------V
public class EndSessionCallbackResult : EndpointResult<EndSessionCallbackResult>
{
    public EndSessionCallbackValidationResult Result { get; }
    public EndSessionCallbackResult(EndSessionCallbackValidationResult result) { Result = result ?? throw new ArgumentNullException(nameof(result)); }
}

class EndSessionCallbackHttpWriter : IHttpResponseWriter<EndSessionCallbackResult>
{
    public EndSessionCallbackHttpWriter(IdentityServerOptions options)
    {
        _options = options;
    }

    private IdentityServerOptions _options;

    public async Task WriteHttpResponse(EndSessionCallbackResult result, HttpContext context)  // <-------------------
    {
        if (result.Result.IsError)
        {
            context.Response.StatusCode = (int) HttpStatusCode.BadRequest;
        }
        else
        {
            context.Response.SetNoCache();
            AddCspHeaders(result, context);

            var html = GetHtml(result);
            await context.Response.WriteHtmlAsync(html);
        }
    }

    private void AddCspHeaders(EndSessionCallbackResult result, HttpContext context)
    {
        if (_options.Authentication.RequireCspFrameSrcForSignout)
        {
            var sb = new StringBuilder();
            var origins = result.Result.FrontChannelLogoutUrls?.Select(x => x.GetOrigin());
            if (origins != null)
            {
                foreach (var origin in origins.Distinct())
                {
                    sb.Append(origin);
                    if (sb.Length > 0) sb.Append(" ");
                }
            }

            // the hash matches the embedded style element being used below
            context.Response.AddStyleCspHeaders(_options.Csp, IdentityServerConstants.ContentSecurityPolicyHashes.EndSessionStyle, sb.ToString());
        }
    }

    private string GetHtml(EndSessionCallbackResult result)
    {
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><style>iframe{{display:none;width:0;height:0;}}</style><body>");

        if (result.Result.FrontChannelLogoutUrls != null)
        {
            foreach (var url in result.Result.FrontChannelLogoutUrls)
            {
                sb.AppendFormat("<iframe loading='eager' allow='' src='{0}'></iframe>", HtmlEncoder.Default.Encode(url));
                sb.AppendLine();
            }
        }

        return sb.ToString();
    }
}
//-----------------------------------Ʌ

//----------------------------------V
internal class IntrospectionEndpoint : IEndpointHandler  // handle POST https://localhost:5001/connect/introspect 
{
    private readonly IIntrospectionResponseGenerator _responseGenerator;
    private readonly IEventService _events;
    private readonly ILogger _logger;
    private readonly IIntrospectionRequestValidator _requestValidator;
    private readonly IApiSecretValidator _apiSecretValidator;
    private readonly IClientSecretValidator _clientValidator;

    public IntrospectionEndpoint(
        IApiSecretValidator apiSecretValidator,
        IClientSecretValidator clientValidator,
        IIntrospectionRequestValidator requestValidator,
        IIntrospectionResponseGenerator responseGenerator,
        IEventService events,
        ILogger<IntrospectionEndpoint> logger)
    {
        // ...
    }

    public async Task<IEndpointResult> ProcessAsync(HttpContext context)
    {
        using var activity = Tracing.BasicActivitySource.StartActivity(IdentityServerConstants.EndpointNames.Introspection + "Endpoint");
        
        _logger.LogTrace("Processing introspection request.");

        // validate HTTP
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            _logger.LogWarning("Introspection endpoint only supports POST requests");
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        if (!context.Request.HasApplicationFormContentType())
        {
            _logger.LogWarning("Invalid media type for introspection endpoint");
            return new StatusCodeResult(HttpStatusCode.UnsupportedMediaType);
        }

        try
        {
            return await ProcessIntrospectionRequestAsync(context);
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning(ex, "Invalid HTTP request for introspection endpoint");
            return new StatusCodeResult(HttpStatusCode.BadRequest);
        }
    }

    private async Task<IEndpointResult> ProcessIntrospectionRequestAsync(HttpContext context)
    {
        _logger.LogDebug("Starting introspection request.");

        // caller validation
        ClientSecretValidationResult clientResult = null;

        ApiResource api = null;
        Client client = null;

        var apiResult = await _apiSecretValidator.ValidateAsync(context);
        if (apiResult.IsError)
        {
            clientResult = await _clientValidator.ValidateAsync(context);
            if (clientResult.IsError)
            {
                _logger.LogError("Unauthorized call introspection endpoint. aborting.");
                return new StatusCodeResult(HttpStatusCode.Unauthorized);
            }
            else
            {
                client = clientResult.Client;
                _logger.LogDebug("Client making introspection request: {clientId}", client.ClientId);
            }
        }
        else
        {
            api = apiResult.Resource;
            _logger.LogDebug("ApiResource making introspection request: {apiId}", api.Name);
        }

        var callerName = api?.Name ?? client.ClientId;
       
        var body = await context.Request.ReadFormAsync();  // <------------------------------------itp
        /*
            {[token, 3FC7A32A760014ED8E35C99D81565713180F1E21BF626038D43FA366C54B7686-1]}
            {[token_type_hint, access_token]}
            {[client_id, imagegalleryapi]}
            {[client_secret, apisecret]}
        */

        if (body == null)
        {
            _logger.LogError("Malformed request body. aborting.");
            const string error = "Malformed request body";
            await _events.RaiseAsync(new TokenIntrospectionFailureEvent(callerName, error));
            
            return new StatusCodeResult(HttpStatusCode.BadRequest);
        }

        // request validation
        _logger.LogTrace("Calling into introspection request validator: {type}", _requestValidator.GetType().FullName);
        var validationRequest = new IntrospectionRequestValidationContext
        {
            Parameters = body.AsNameValueCollection(),
            Api = api,
            Client = client,
        };
           
        var validationResult = await _requestValidator.ValidateAsync(validationRequest);  // <------------------itp, eventually calls TokenValidator.ValidateReferenceAccessTokenAsync()
        /*  validationResult contains 
             Api = imagegalleryapi
             Claims = Count = 24   // contains all claims such as { "role" : "payinguser" }
             Token = "71780BC5B05DA756BDB153A04C7485FCB66E975F82E533C122EBC1E331F89F5A-1"
        */
        if (validationResult.IsError)
        {
            LogFailure(validationResult.Error, callerName);
            await _events.RaiseAsync(new TokenIntrospectionFailureEvent(callerName, validationResult.Error));

            return new BadRequestResult(validationResult.Error);
        }

        // response generation
        _logger.LogTrace("Calling into introspection response generator: {type}", _responseGenerator.GetType().FullName);

        var response = await _responseGenerator.ProcessAsync(validationResult);  // <-----------------------pass the reference-type access token 

        // render result
        LogSuccess(validationResult.IsActive, callerName);
        return new IntrospectionResult(response);
    }
}
//----------------------------------Ʌ

//------------------------------------------>>
public interface IEndSessionRequestValidator
{
    Task<EndSessionValidationResult> ValidateAsync(NameValueCollection parameters, ClaimsPrincipal subject);
    Task<EndSessionCallbackValidationResult> ValidateCallbackAsync(NameValueCollection parameters);
}
//------------------------------------------<<

//-------------------------------------V
public class EndSessionRequestValidator : IEndSessionRequestValidator
{
    protected readonly ILogger Logger;
    protected readonly IdentityServerOptions Options;
    protected readonly ITokenValidator TokenValidator;
    protected readonly IRedirectUriValidator UriValidator;
    protected readonly IUserSession UserSession;
    public ILogoutNotificationService LogoutNotificationService { get; }

    protected readonly IMessageStore<LogoutNotificationContext> EndSessionMessageStore;

    public EndSessionRequestValidator(
        IdentityServerOptions options,
        ITokenValidator tokenValidator,
        IRedirectUriValidator uriValidator,
        IUserSession userSession,
        ILogoutNotificationService logoutNotificationService,
        IMessageStore<LogoutNotificationContext> endSessionMessageStore,
        ILogger<EndSessionRequestValidator> logger)
    {
        // ...
    }

    public async Task<EndSessionValidationResult> ValidateAsync(NameValueCollection parameters, ClaimsPrincipal subject)  // <---------------------e1.2.1
    {
        var isAuthenticated = subject.IsAuthenticated();

        if (!isAuthenticated && Options.Authentication.RequireAuthenticatedUserForSignOutMessage)
        {
            return Invalid("User is anonymous. Ignoring end session parameters");
        }

        var validatedRequest = new ValidatedEndSessionRequest
        {
            Raw = parameters
        };

        var idTokenHint = parameters.Get(OidcConstants.EndSessionRequest.IdTokenHint);  // <------------------------------e1.2.2
        if (idTokenHint.IsPresent())
        {
            // validate id_token - no need to validate token life time
            var tokenValidationResult = await TokenValidator.ValidateIdentityTokenAsync(idTokenHint, null, false);
            if (tokenValidationResult.IsError)
            {
                return Invalid("Error validating id token hint", validatedRequest);
            }

            validatedRequest.SetClient(tokenValidationResult.Client);

            // validate sub claim against currently logged on user
            var subClaim = tokenValidationResult.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject);
            if (subClaim != null && isAuthenticated)
            {
                if (subject.GetSubjectId() != subClaim.Value)
                {
                    return Invalid("Current user does not match identity token", validatedRequest);
                }

                validatedRequest.Subject = subject;
                validatedRequest.SessionId = await UserSession.GetSessionIdAsync();
                validatedRequest.ClientIds = await UserSession.GetClientListAsync();
            }

            var redirectUri = parameters.Get(OidcConstants.EndSessionRequest.PostLogoutRedirectUri);  // <------------------------------e1.2.3
            //  redirectUri is https://localhost:7184/signout-callback-oidc

            if (redirectUri.IsPresent())
            {
                if (await UriValidator.IsPostLogoutRedirectUriValidAsync(redirectUri, validatedRequest.Client))
                {
                    validatedRequest.PostLogOutUri = redirectUri;
                }
                else
                {
                    Logger.LogWarning("Invalid PostLogoutRedirectUri: {postLogoutRedirectUri}", redirectUri);
                }
            }

            if (validatedRequest.PostLogOutUri != null)
            {
                var state = parameters.Get(OidcConstants.EndSessionRequest.State);
                if (state.IsPresent())
                {
                    validatedRequest.State = state;
                }
            }
        }
        else
        {
            // no id_token to authenticate the client, but we do have a user and a user session
            validatedRequest.Subject = subject;
            validatedRequest.SessionId = await UserSession.GetSessionIdAsync();
            validatedRequest.ClientIds = await UserSession.GetClientListAsync();
        }

        var uilocales = parameters.Get(OidcConstants.EndSessionRequest.UiLocales);
        if (uilocales.IsPresent())
        {
            if (uilocales.Length > Options.InputLengthRestrictions.UiLocale)
            {
                var log = new EndSessionRequestValidationLog(validatedRequest);
                Logger.LogWarning("UI locale too long. It will be ignored." + Environment.NewLine + "{@details}", log);
            }
            else
            {
                validatedRequest.UiLocales = uilocales;
            }
        }

        return new EndSessionValidationResult  // <------------------------------e1.2.4.
        {
            ValidatedRequest = validatedRequest,
            IsError = false
        };
    }

    protected virtual EndSessionValidationResult Invalid(string message, ValidatedEndSessionRequest request = null)
    {
        message = "End session request validation failure: " + message;
        if (request != null)
        {
            var log = new EndSessionRequestValidationLog(request);
            Logger.LogInformation(message + Environment.NewLine + "{@details}", log);
        }
        else
        {
            Logger.LogInformation(message);
        }

        return new EndSessionValidationResult
        {
            IsError = true,
            Error = "Invalid request",
            ErrorDescription = message
        };
    }

    public async Task<EndSessionCallbackValidationResult> ValidateCallbackAsync(NameValueCollection parameters)
    {
        var result = new EndSessionCallbackValidationResult
        {
            IsError = true
        };

        var endSessionId = parameters[Constants.UIConstants.DefaultRoutePathParams.EndSessionCallback];
        var endSessionMessage = await EndSessionMessageStore.ReadAsync(endSessionId);
        if (endSessionMessage?.Data?.ClientIds?.Any() == true)
        {
            result.IsError = false;
            result.FrontChannelLogoutUrls = await LogoutNotificationService.GetFrontChannelLogoutNotificationsUrlsAsync(endSessionMessage.Data);
        }
        else
        {
            result.Error = "Failed to read end session callback message";
        }

        return result;
    }
}
//-------------------------------------Ʌ
```

```C#
//-----------------------------------------V
public static class IdentityServerConstants
{
    public const string LocalIdentityProvider = "local";
    public const string DefaultCookieAuthenticationScheme = "idsrv";
    public const string SignoutScheme = "idsrv";
    public const string ExternalCookieAuthenticationScheme = "idsrv.external";
    public const string DefaultCheckSessionCookieName = "idsrv.session";
    public const string AccessTokenAudience = "{0}resources";
    public const string JwtRequestClientKey = "idsrv.jwtrequesturi.client";
    public const string PushedAuthorizationRequestUri = "urn:ietf:params:oauth:request_uri";

    public static class LocalApi
    {
        public const string AuthenticationScheme = "IdentityServerAccessToken";
        public const string ScopeName = "IdentityServerApi";
        public const string PolicyName = AuthenticationScheme;
    }

    public static class ProtocolTypes
    {
        public const string OpenIdConnect = "oidc";
        public const string WsFederation = "wsfed";
        public const string Saml2p = "saml2p";
    }

    public static class TokenTypes
    {
        public const string IdentityToken = "id_token";
        public const string AccessToken = "access_token";
        public const string LogoutToken = "logout_token";
    }

    public static class StandardScopes
    {
        public const string OpenId = "openid";
        public const string Profile = "profile";
        public const string Email = "email";
        public const string Address = "address";
        public const string Phone = "phone";
        public const string OfflineAccess = "offline_access";
    }

    // ...
}
//-----------------------------------------Ʌ

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

//---------------------V
public class GrantTypes
{
    public static ICollection<string> Implicit => new[] { GrantType.Implicit };

    public static ICollection<string> ImplicitAndClientCredentials => new[]  { GrantType.Implicit, GrantType.ClientCredentials };

    public static ICollection<string> Code => new[] { GrantType.AuthorizationCode };

    public static ICollection<string> CodeAndClientCredentials => new[] { GrantType.AuthorizationCode, GrantType.ClientCredentials };

    public static ICollection<string> Hybrid => new[] { GrantType.Hybrid };

    public static ICollection<string> HybridAndClientCredentials => new[] { GrantType.Hybrid, GrantType.ClientCredentials };

    public static ICollection<string> ClientCredentials => new[] { GrantType.ClientCredentials };

    public static ICollection<string> ResourceOwnerPassword => new[] { GrantType.ResourceOwnerPassword };

    public static ICollection<string> ResourceOwnerPasswordAndClientCredentials => new[] { GrantType.ResourceOwnerPassword, GrantType.ClientCredentials };

    public static ICollection<string> DeviceFlow => new[] { GrantType.DeviceFlow };

    public static ICollection<string> Ciba => new[] { OidcConstants.GrantTypes.Ciba };
}
//---------------------Ʌ

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

//-----------------------------------V
public static class IdentityResources
{
    public class OpenId : IdentityResource
    {
        public OpenId()
        {
            Name = IdentityServerConstants.StandardScopes.OpenId;
            DisplayName = "Your user identifier";
            Required = true;
            UserClaims.Add(JwtClaimTypes.Subject);
        }
    }

    public class Profile : IdentityResource
    {
        public Profile()
        {
            Name = IdentityServerConstants.StandardScopes.Profile;
            DisplayName = "User profile";
            Description = "Your user profile information (first name, last name, etc.)";
            Emphasize = true;
            UserClaims = Constants.ScopeToClaimsMapping[IdentityServerConstants.StandardScopes.Profile].ToList();
        }
    }

    public class Email : IdentityResource 
    { 
        public Email()
        {
            Name = IdentityServerConstants.StandardScopes.Email;
            DisplayName = "Your email address";
            Emphasize = true;
            UserClaims = (Constants.ScopeToClaimsMapping[IdentityServerConstants.StandardScopes.Email].ToList());
        }
    }

    public class Phone : IdentityResource { ... };
    public class Address : IdentityResource {...  };
}
//-----------------------------------Ʌ
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
            request.Subject,  // <-------------------------------------------!
            request.ValidatedResources,
            request.IncludeAllIdentityClaims,
            request.ValidatedRequest));
 
        var issuer = ContextAccessor.HttpContext.GetIdentityServerIssuerUri();
 
        var token = new Token(OidcConstants.TokenTypes.IdentityToken)
        {
            CreationTime = Clock.UtcNow.UtcDateTime,
            Audiences = { request.ValidatedRequest.Client.ClientId },  // <---------------------
            Issuer = issuer,
            Lifetime = request.ValidatedRequest.Client.IdentityTokenLifetime,
            Claims = claims.Distinct(new ClaimComparer()).ToList(),
            ClientId = request.ValidatedRequest.Client.ClientId,
            AccessTokenType = request.ValidatedRequest.AccessTokenType,
            AllowedSigningAlgorithms = request.ValidatedRequest.Client.AllowedIdentityTokenSigningAlgorithms
        };
 
        return token;
    }

    public virtual async Task<Token> CreateAccessTokenAsync(TokenCreationRequest request)   // <-----------------------------------att
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
        foreach (var aud in request.ValidatedResources.Resources.ApiResources.Select(x => x.Name).Distinct())  // <-----------------------idpaud
        {
            token.Audiences.Add(aud);  //  add "imagegalleryapi" as aud
        }
 
        if (Options.EmitStaticAudienceClaim)
        {
            token.Audiences.Add(string.Format(IdentityServerConstants.AccessTokenAudience, issuer.EnsureTrailingSlash()));  // add "https://localhost:5001/resources" as aud
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

//-------------------------------V
public class DefaultGrantStore<T>
{
    protected string GrantType { get; }
    protected ILogger Logger { get; }
    protected IPersistedGrantStore Store { get; }
    protected IPersistentGrantSerializer Serializer { get; }
    protected IHandleGenerationService HandleGenerationService { get; }

    protected DefaultGrantStore(string grantType,
        IPersistedGrantStore store,
        IPersistentGrantSerializer serializer,
        IHandleGenerationService handleGenerationService,
        ILogger logger)
    {
        if (grantType.IsMissing()) throw new ArgumentNullException(nameof(grantType));

        GrantType = grantType;
        Store = store;
        Serializer = serializer;
        HandleGenerationService = handleGenerationService;
        Logger = logger;
    }

    private const string KeySeparator = ":";
    protected const string HexEncodingFormatSuffix = "-1";

    protected async Task<string> CreateHandleAsync()
    {
        return await HandleGenerationService.GenerateAsync() + HexEncodingFormatSuffix;
    }

    protected virtual string GetHashedKey(string value)
    {
        var key = (value + KeySeparator + GrantType);

        if (value.EndsWith(HexEncodingFormatSuffix))
        {
            // newer format >= v6; uses hex encoding to avoid collation issues
            using (var sha = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(key);
                var hash = sha.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }

        // old format <= v5
        return key.Sha256();
    }

    protected virtual async Task<T> GetItemAsync(string key)
    {
        var hashedKey = GetHashedKey(key);
        var item = await GetItemByHashedKeyAsync(hashedKey);
        if (item == null)
        {
            Logger.LogDebug("{grantType} grant with value: {key} not found in store.", GrantType, key);
        }
        return item;
    }

    protected virtual async Task<T> GetItemByHashedKeyAsync(string hashedKey)
    {
        var grant = await Store.GetAsync(hashedKey);
        if (grant != null && grant.Type == GrantType)
        {
            try
            {
                return Serializer.Deserialize<T>(grant.Data);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Failed to deserialize JSON from grant store.");
            }
        }

        return default;
    }

    protected virtual async Task<IEnumerable<T>> GetAllAsync(PersistedGrantFilter filter)
    {
        filter.Type = GrantType;
        var items = await Store.GetAllAsync(filter);
        var result = items.Select(x => Serializer.Deserialize<T>(x.Data)).ToArray();
        return result;
    }

    protected virtual async Task<string> CreateItemAsync(T item, string clientId, string subjectId, string sessionId, string description, DateTime created, int lifetime)
    {
        var handle = await CreateHandleAsync();
        await StoreItemAsync(handle, item, clientId, subjectId, sessionId, description, created, created.AddSeconds(lifetime));
        return handle;
    }

    protected virtual Task StoreItemAsync(string key, T item, string clientId, string subjectId, string sessionId, string description, DateTime created, DateTime? expiration, DateTime? consumedTime = null)
    {
        key = GetHashedKey(key);
        return StoreItemByHashedKeyAsync(key, item, clientId, subjectId, sessionId, description, created, expiration, consumedTime);
    }

    protected virtual async Task StoreItemByHashedKeyAsync(string hashedKey, T item, string clientId, string subjectId, string sessionId, string description, DateTime created, DateTime? expiration, DateTime? consumedTime = null)
    {
        var json = Serializer.Serialize(item);

        var grant = new PersistedGrant
        {
            Key = hashedKey,
            Type = GrantType,
            ClientId = clientId,
            SubjectId = subjectId,
            SessionId = sessionId,
            Description = description,
            CreationTime = created,
            Expiration = expiration,
            ConsumedTime = consumedTime,
            Data = json
        };

        await Store.StoreAsync(grant);
    }

    protected virtual Task RemoveItemAsync(string key)
    {
        key = GetHashedKey(key);
        return RemoveItemByHashedKeyAsync(key);
    }
        
    protected virtual async Task RemoveItemByHashedKeyAsync(string key)
    {
        await Store.RemoveAsync(key);
    }

    protected virtual async Task RemoveAllAsync(string subjectId, string clientId, string sessionId = null)
    {
        await Store.RemoveAllAsync(new PersistedGrantFilter
        {
            SubjectId = subjectId,
            ClientId = clientId,
            SessionId = sessionId,
            Type = GrantType
        });
    }
}
//-------------------------------Ʌ

//----------------------------------------V
public class DefaultAuthorizationCodeStore : DefaultGrantStore<AuthorizationCode>, IAuthorizationCodeStore
{
    public DefaultAuthorizationCodeStore(
        IPersistedGrantStore store,
        IPersistentGrantSerializer serializer,
        IHandleGenerationService handleGenerationService,
        ILogger<DefaultAuthorizationCodeStore> logger)
        : base(IdentityServerConstants.PersistedGrantTypes.AuthorizationCode, store, serializer, handleGenerationService, logger) { }


    public Task<string> StoreAuthorizationCodeAsync(AuthorizationCode code) => return CreateItemAsync(code, code.ClientId, code.Subject.GetSubjectId(), code.SessionId, code.Description, code.CreationTime, code.Lifetime);
   
    public Task<AuthorizationCode> GetAuthorizationCodeAsync(string code) => return GetItemAsync(code);
   
    public Task RemoveAuthorizationCodeAsync(string code) => return RemoveItemAsync(code);
}
//----------------------------------------Ʌ

//-------------------------------------------------V  Extension methods for signin/out using the IdentityServer authentication scheme.
public static class AuthenticationManagerExtensions
{ 
    public static async Task SignInAsync(this HttpContext context, IdentityServerUser user)
    {
        await context.SignInAsync(await context.GetCookieAuthenticationSchemeAsync(), user.c());   // <-----------------------------i5
    }

    public static async Task SignInAsync(this HttpContext context, IdentityServerUser user, AuthenticationProperties properties)
    {
        await context.SignInAsync(await context.GetCookieAuthenticationSchemeAsync(), user.CreatePrincipal(), properties);
    }

    internal static async Task<string> GetCookieAuthenticationSchemeAsync(this HttpContext context)  // <-------------------idsrvexternal
    {
        var options = context.RequestServices.GetRequiredService<IdentityServerOptions>();  // normally options.Authentication.CookieAuthenticationScheme is "idsrv" because of
        if (options.Authentication.CookieAuthenticationScheme != null)                      // AddIdentityServer calls `AddCookieAuthentication` which uses "idsrv" as default scheme
        {
            return options.Authentication.CookieAuthenticationScheme;
        }

        var schemes = context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
        var scheme = await schemes.GetDefaultAuthenticateSchemeAsync();
        if (scheme == null)
        {
            throw new InvalidOperationException("No DefaultAuthenticateScheme found or no CookieAuthenticationScheme configured on IdentityServerOptions.");
        }

        return scheme.Name;
    }
}
//-------------------------------------------------Ʌ

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

    public async Task SignInAsync(HttpContext context, string scheme, ClaimsPrincipal principal, AuthenticationProperties properties)  // <-----------------i5
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

//--------------------------->>
public interface IUserSession
{
    Task<string> CreateSessionIdAsync(ClaimsPrincipal principal, AuthenticationProperties properties);
    Task<ClaimsPrincipal?> GetUserAsync();
    Task<string?> GetSessionIdAsync();
    Task EnsureSessionIdCookieAsync();
    Task RemoveSessionIdCookieAsync();
    Task AddClientIdAsync(string clientId);
    Task<IEnumerable<string>> GetClientListAsync();
}
//---------------------------<<

//-----------------------------V
public class DefaultUserSession : IUserSession  // this is not a database to store seesion, it relys on cookie by calls `AuthenticateAsync()` to get user session
{
    protected readonly IHttpContextAccessor HttpContextAccessor;
    protected readonly IAuthenticationHandlerProvider Handlers;
    protected readonly IdentityServerOptions Options;
    protected readonly IClock Clock;
    protected readonly IServerUrls Urls;
    protected readonly ILogger Logger;
    protected HttpContext HttpContext => HttpContextAccessor.HttpContext;
    protected string CheckSessionCookieName => Options.Authentication.CheckSessionCookieName;
    protected string CheckSessionCookieDomain => Options.Authentication.CheckSessionCookieDomain;
    protected SameSiteMode CheckSessionCookieSameSiteMode => Options.Authentication.CheckSessionCookieSameSiteMode;
    protected ClaimsPrincipal Principal;
    protected AuthenticationProperties Properties;

    public DefaultUserSession(
        IHttpContextAccessor httpContextAccessor,
        IAuthenticationHandlerProvider handlers,
        IdentityServerOptions options,
        IClock clock,
        IServerUrls urls,
        ILogger<IUserSession> logger)
    {
        // ...
    }

    // we need this helper (and can't call HttpContext.AuthenticateAsync) so we don't run claims transformation when we get the principal. this also ensures that we don't
    // re-issue a cookie that includes the claims from claims transformation. also, by caching the _principal/_properties it allows someone to issue a new
    // cookie (via HttpContext.SignInAsync) and we'll use those new values, rather than just reading the incoming cookie  this design requires this to be in DI as scoped
    protected virtual async Task AuthenticateAsync()
    {
        if (Principal == null || Properties == null)
        {
            var scheme = await HttpContext.GetCookieAuthenticationSchemeAsync();

            var handler = await Handlers.GetHandlerAsync(HttpContext, scheme);
            if (handler == null)
            {
                throw new InvalidOperationException($"No authentication handler is configured to authenticate for the scheme: {scheme}");
            }

            var result = await handler.AuthenticateAsync();
            if (result != null && result.Succeeded && result.Principal.Identity.IsAuthenticated)
            {
                Principal = result.Principal;
                Properties = result.Properties;
            }
        }
    }

    public virtual async Task<string> CreateSessionIdAsync(ClaimsPrincipal principal, AuthenticationProperties properties)
    {
        if (principal == null) throw new ArgumentNullException(nameof(principal));
        if (properties == null) throw new ArgumentNullException(nameof(properties));

        var currentSubjectId = (await GetUserAsync())?.GetSubjectId();
        var newSubjectId = principal.GetSubjectId();

        if (properties.GetSessionId() == null)
        {
            var currSid = await GetSessionIdAsync();
            if (newSubjectId == currentSubjectId && currSid != null)
            {
                properties.SetSessionId(currSid);
                var clients = Properties.GetClientList();
                if (clients.Any())
                {
                    properties.SetClientList(clients);
                }
            }
            else
            {
                properties.SetSessionId(CryptoRandom.CreateUniqueId(16, CryptoRandom.OutputFormat.Hex));
            }
        }

        var sid = properties.GetSessionId();
        IssueSessionIdCookie(sid);

        Principal = principal;
        Properties = properties;

        return sid;
    }

    public virtual async Task<ClaimsPrincipal> GetUserAsync()
    {
        await AuthenticateAsync();

        return Principal;
    }

    public virtual async Task<string> GetSessionIdAsync()
    {
        await AuthenticateAsync();

        return Properties?.GetSessionId();
    }

    public virtual async Task EnsureSessionIdCookieAsync()
    {
        var sid = await GetSessionIdAsync();
        if (sid != null)
        {
            IssueSessionIdCookie(sid);
        }
        else
        {
            await RemoveSessionIdCookieAsync();
        }
    }

    public virtual Task RemoveSessionIdCookieAsync()
    {
        if (HttpContext.Request.Cookies.ContainsKey(CheckSessionCookieName))
        {
            // only remove it if we have it in the request
            var options = CreateSessionIdCookieOptions();
            options.Expires = Clock.UtcNow.UtcDateTime.AddYears(-1);

            HttpContext.Response.Cookies.Append(CheckSessionCookieName, ".", options);
        }

        return Task.CompletedTask;
    }

    public virtual CookieOptions CreateSessionIdCookieOptions()
    {
        var secure = HttpContext.Request.IsHttps;
        var path = Urls.BasePath.CleanUrlPath();

        var options = new CookieOptions
        {
            HttpOnly = false,
            Secure = secure,
            Path = path,
            IsEssential = true,
            Domain = CheckSessionCookieDomain,
            SameSite = CheckSessionCookieSameSiteMode
        };

        return options;
    }

    public virtual void IssueSessionIdCookie(string sid)
    {
        if (Options.Endpoints.EnableCheckSessionEndpoint)
        {
            if (HttpContext.Request.Cookies[CheckSessionCookieName] != sid)
            {
                HttpContext.Response.Cookies.Append(
                    Options.Authentication.CheckSessionCookieName,
                    sid,
                    CreateSessionIdCookieOptions());
            }
        }
    }

    public virtual async Task AddClientIdAsync(string clientId)  // <--------------------------------c3.4
    {
        if (clientId == null) throw new ArgumentNullException(nameof(clientId));

        await AuthenticateAsync();
        if (Properties != null)
        {
            var clientIds = Properties.GetClientList();
            if (!clientIds.Contains(clientId))
            {
                Properties.AddClientId(clientId);
                await UpdateSessionCookie();  // <--------------------------------c3.4
            }
        }
    }

    public virtual async Task<IEnumerable<string>> GetClientListAsync()
    {
        await AuthenticateAsync();

        if (Properties != null)
        {
            try
            {
                return Properties.GetClientList();
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error decoding client list");
                // clear so we don't keep failing
                Properties.RemoveClientList();
                await UpdateSessionCookie();
            }
        }

        return Enumerable.Empty<string>();
    }

    private async Task UpdateSessionCookie()
    {
        await AuthenticateAsync();

        if (Principal == null || Properties == null) throw new InvalidOperationException("User is not currently authenticated");

        var scheme = await HttpContext.GetCookieAuthenticationSchemeAsync();
        await HttpContext.SignInAsync(scheme, Principal, Properties);
    }
}
//-----------------------------Ʌ

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
        var (accessToken, refreshToken) = await CreateAccessTokenAsync(request.ValidatedRequest);  // <--------------------att this is how access token get generated
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
 
            // 
            var idToken = await TokenService.CreateIdentityTokenAsync(tokenRequest);  // <--------------------idt, this is how id token get generated
            var jwt = await TokenService.CreateSecurityTokenAsync(idToken);
            //

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
    
    protected virtual async Task<(string accessToken, string refreshToken)> CreateAccessTokenAsync(ValidatedTokenRequest request) // <------------att, request contains scopes that
    {                                                                                                                             // user choose on the consent page
        TokenCreationRequest tokenRequest;
        bool createRefreshToken;
 
        if (request.AuthorizationCode != null)
        {
            createRefreshToken = request.AuthorizationCode.RequestedScopes.Contains(IdentityServerConstants.StandardScopes.OfflineAccess);  // <----------------ofa
 
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
 
            var parsedScopesResult = ScopeParser.ParseScopeValues(request.AuthorizationCode.RequestedScopes);  // <---------scopes are needed to generate access token
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
 
        var at = await TokenService.CreateAccessTokenAsync(tokenRequest);  // <--------------------------generate access token
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

//------------------------------------V
public class UserInfoResponseGenerator : IUserInfoResponseGenerator
{
    protected readonly ILogger Logger;
    protected readonly IProfileService Profile;
    protected readonly IResourceStore Resources;

    public UserInfoResponseGenerator(IProfileService profile, IResourceStore resourceStore, ILogger<UserInfoResponseGenerator> logger)
    {
        Profile = profile;
        Resources = resourceStore;
        Logger = logger;
    }

    public virtual async Task<Dictionary<string, object>> ProcessAsync(UserInfoRequestValidationResult validationResult)  // <---------------------u1.4
    {
        using var activity = Tracing.BasicActivitySource.StartActivity("UserInfoResponseGenerator.Process");
        
        Logger.LogDebug("Creating userinfo response");

        // this includes the scopes users choose in the consent page
        var scopes = validationResult.TokenValidationResult.Claims.Where(c => c.Type == JwtClaimTypes.Scope).Select(c => c.Value);  // <-------------------
        /*  scopes contains:
            "openid",
            "profile",
            "imagegalleryapi.fullaccess",
            "other.fullaccess",
            "roles"
        */

        var validatedResources = await GetRequestedResourcesAsync(scopes);  // calls Resources.FindEnabledIdentityResourcesByScopeAsync(scopes)
        /*  validatedResources contains                                     // so ApiResources are filtered out
           "openid",
           "profile",
            "roles"
        */

        var requestedClaimTypes = await GetRequestedClaimTypesAsync(validatedResources);  // <---------------------u1.5
        /* requestedClaimTypes contains
           "sub", "name", "given_name", "family_name", "profile", "role" and so on
        */
        Logger.LogDebug("Requested claim types: {claimTypes}", requestedClaimTypes.ToSpaceSeparatedString());

        // call profile service
        var context = new ProfileDataRequestContext(
            validationResult.Subject,
            validationResult.TokenValidationResult.Client,
            IdentityServerConstants.ProfileDataCallers.UserInfoEndpoint,
            requestedClaimTypes);
        context.RequestedResources = validatedResources;

        await Profile.GetProfileDataAsync(context);  // <---------------------------------u1.6
        var profileClaims = context.IssuedClaims;    //  IssuedClaims contains {role: PayingUser}, {given_name: Emma}, {family_name: Flagg}
       
        // construct outgoing claims
        var outgoingClaims = new List<Claim>();

        if (profileClaims == null)
        {
            Logger.LogInformation("Profile service returned no claims (null)");
        }
        else
        {
            outgoingClaims.AddRange(profileClaims);
            Logger.LogInformation("Profile service returned the following claim types: {types}", profileClaims.Select(c => c.Type).ToSpaceSeparatedString());
        }

        var subClaim = outgoingClaims.SingleOrDefault(x => x.Type == JwtClaimTypes.Subject);
        if (subClaim == null)
        {
            outgoingClaims.Add(new Claim(JwtClaimTypes.Subject, validationResult.Subject.GetSubjectId()));
        }
        else if (subClaim.Value != validationResult.Subject.GetSubjectId())
        {
            Logger.LogError("Profile service returned incorrect subject value: {sub}", subClaim);
            throw new InvalidOperationException("Profile service returned incorrect subject value");
        }

        return outgoingClaims.ToClaimsDictionary();
    }

    protected internal virtual async Task<ResourceValidationResult> GetRequestedResourcesAsync(IEnumerable<string> scopes)
    {
        if (scopes == null || !scopes.Any())
        {
            return null;
        }

        var scopeString = string.Join(" ", scopes);
        Logger.LogDebug("Scopes in access token: {scopes}", scopeString);

        // if we ever parameterized identity scopes, then we would need to invoke the resource validator's parse API here
        var identityResources = await Resources.FindEnabledIdentityResourcesByScopeAsync(scopes);
            
        var resources = new Resources(identityResources, Enumerable.Empty<ApiResource>(), Enumerable.Empty<ApiScope>());
        var result = new ResourceValidationResult(resources);
            
        return result;
    }

    protected internal virtual Task<IEnumerable<string>> GetRequestedClaimTypesAsync(ResourceValidationResult resourceValidationResult)
    {
        IEnumerable<string> result = null;

        if (resourceValidationResult == null)
        {
            result = Enumerable.Empty<string>();
        }
        else
        {
            var identityResources = resourceValidationResult.Resources.IdentityResources;
            result = identityResources.SelectMany(x => x.UserClaims).Distinct();
        }

        return Task.FromResult(result);
    }
}
//------------------------------------Ʌ

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

    internal async Task<IEndpointResult> ProcessAuthorizeRequestAsync(NameValueCollection parameters, ClaimsPrincipal user, bool checkConsentResponse = false)  // <----------------ac2.0
    {      
        if (checkConsentResponse && _authorizationParametersMessageStore != null)
        {
            var messageStoreId = parameters[Constants.AuthorizationParamsStore.MessageStoreIdParameterName];
            var entry = await _authorizationParametersMessageStore.ReadAsync(messageStoreId);
            parameters = entry?.Data.FromFullDictionary() ?? new NameValueCollection();

            await _authorizationParametersMessageStore.DeleteAsync(messageStoreId);
        }

        // validate request
        var result = await _validator.ValidateAsync(parameters, user);

        if (result.IsError)
        {
            return await CreateErrorResultAsync(
                "Request validation failed",
                result.ValidatedRequest,
                result.Error,
                result.ErrorDescription);
        }

        string consentRequestId = null;

        try
        {
            Message<ConsentResponse> consent = null;

            if (checkConsentResponse)
            {
                var consentRequest = new ConsentRequest(result.ValidatedRequest.Raw, user?.GetSubjectId());
                consentRequestId = consentRequest.Id;
                consent = await _consentResponseStore.ReadAsync(consentRequestId);

                if (consent != null && consent.Data == null)
                {
                    return await CreateErrorResultAsync("consent message is missing data", result.ValidatedRequest);
                }
            }

            var request = result.ValidatedRequest;
            LogRequest(request);

            // determine user interaction
            var interactionResult = await _interactionGenerator.ProcessInteractionAsync(request, consent?.Data);
            if (interactionResult.ResponseType == InteractionResponseType.Error)
            {
                return await CreateErrorResultAsync("Interaction generator error", request, interactionResult.Error, interactionResult.ErrorDescription, false);
            }
            
            if (interactionResult.ResponseType == InteractionResponseType.UserInteraction)
            {
                if (interactionResult.IsLogin)
                {
                    return new LoginPageResult(request, _options);
                }
                if (interactionResult.IsConsent)
                {
                    return new ConsentPageResult(request, _options);
                }
                if (interactionResult.IsRedirect)
                {
                    return new CustomRedirectResult(request, interactionResult.RedirectUrl, _options);
                }
                if (interactionResult.IsCreateAccount)
                {
                    return new CreateAccountPageResult(request, _options);
                }
            }

            AuthorizeResponse response = await _authorizeResponseGenerator.CreateResponseAsync(request);    // <----------------------------------ac2.1, generate authCode
            /*
            {
               AccessToken: null,
               IdentityToken: null,
               Code: "D5A19F5003457F4DAF1C0C1B67xxxx-1,
               issuer: "https://localhost:5001",
               RedirectUri: "https://localhost:7184/signin-oidc"
               Scope: "openid profile roles imagegalleryapi.read imagegalleryapi.write country offline_access other.fullaccess"  <------show scopes that chosen by user in consent page only
               SessionState: "Y8vD3_84cXdQZeLoo34sOmtBXhdkEwVwChmKIDYhytw.B53C8C34794A437D31C807FFA99D1EE2",
               State: CfDJ8Av8t8aEYQtIoPkZenx5Btx4Lh9asU-Rd5orrrda067ACEwN1xx0L8QdXCEfg021DCoU9xc0CBQr-mcIIxBKXwdputU9sB8GfFvfM0LTkxYGByWJ-Wqbvxxx
            }
            */

            await RaiseResponseEventAsync(response);

            LogResponse(response);

            return new AuthorizeResult(response);   // <----------------------------------ac3.
        }
        finally
        {
            if (consentRequestId != null)
            {
                await _consentResponseStore.DeleteAsync(consentRequestId);
            }
        }
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
        : base(events, logger, options, validator, interactionGenerator, authorizeResponseGenerator, userSession, consentResponseStore, authorizationParametersMessageStore)
    {
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
        var user = await UserSession.GetUserAsync();  // <------------------------usc

        var result = await ProcessAuthorizeRequestAsync(parameters, user, true);  // <------------conscope

        Logger.LogTrace("End Authorize Request. Result type: {0}", result?.GetType().ToString() ?? "-none-");

        return result;
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

    /* POST request from OpenIDConnectHandler.RedeemAuthorizationCodeAsync):

      {[client_id, imagegalleryclient]}
      {[client_secret, secret]}
      {[code, D25B015FE0ADAE97B433F354D0A49A8F208A32511F10B9DDEB57B29CEF2B74D4-1]}
      {[grant_type, authorization_code]}
      {[redirect_uri, https://localhost:7184/signin-oidc]}  // <------------not sure why it is needed as we already in the /signin-oidc request
      {[code_verifier, NK-Vskzz20wgh3vtmyIrx1aavewHUaT_EH8EFYk_llM]}
        
    */
    private async Task<IEndpointResult> ProcessTokenRequestAsync(HttpContext context)  // <----------------------------toks0
    {
        _logger.LogDebug("Start token request.");

        // validate client
        var clientResult = await _clientValidator.ValidateAsync(context);
        if (clientResult.IsError)
        {
            var errorMsg = clientResult.Error ?? OidcConstants.TokenErrors.InvalidClient;
            return Error(errorMsg);
        }

        // validate request
        var form = (await context.Request.ReadFormAsync()).AsNameValueCollection();
        _logger.LogTrace("Calling into token request validator: {type}", _requestValidator.GetType().FullName);

        var requestContext = new TokenRequestValidationContext
        {
            RequestParameters = form,
            ClientValidationResult = clientResult,
        };
        
        var error = await TryReadProofTokens(context, requestContext);
        if (error != null)
        {
            Telemetry.Metrics.TokenIssuedFailure(clientResult.Client.ClientId, null, null, error.Response.Error);
            return error;
        }

        TokenRequestValidationResult requestResult = 
            await _requestValidator.ValidateRequestAsync(requestContext);  // <-----toks1 retrieve user info based on auth code inside requestContext requestResult.ValidatedRequest.Subject 
                                                                           //  (ClaimsPrincipal) contains { IsAuthenticated = true, Name = Emma, Claims = 5 } which is used below
        if (requestResult.IsError)
        {
            await _events.RaiseAsync(new TokenIssuedFailureEvent(requestResult));
            Telemetry.Metrics.TokenIssuedFailure(
                clientResult.Client.ClientId, requestResult.ValidatedRequest?.GrantType, null, requestResult.Error);
            var err = Error(requestResult.Error, requestResult.ErrorDescription, requestResult.CustomResponse);
            err.Response.DPoPNonce = requestResult.DPoPNonce;
            return err;
        }

        // create response
        _logger.LogTrace("Calling into token request response generator: {type}", _responseGenerator.GetType().FullName);

        var response = await _responseGenerator.ProcessAsync(requestResult);  // <----------toks2! _responseGenerator is ITokenResponseGenerator which generates id token,  access token etc
                                                                              // based on the ClaimsPrincipal in requestResult generated at toks1 
        await _events.RaiseAsync(new TokenIssuedSuccessEvent(response, requestResult));
        Telemetry.Metrics.TokenIssued(clientResult.Client.ClientId, requestResult.ValidatedRequest.GrantType, null);
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

//----------------------------------V
internal class TokenRequestValidator : ITokenRequestValidator
{
    private readonly IdentityServerOptions _options;
    private readonly IIssuerNameService _issuerNameService;
    private readonly IServerUrls _serverUrls;
    private readonly IAuthorizationCodeStore _authorizationCodeStore;
    private readonly ExtensionGrantValidator _extensionGrantValidator;
    private readonly ICustomTokenRequestValidator _customRequestValidator;
    private readonly IResourceValidator _resourceValidator;
    private readonly IResourceStore _resourceStore;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IDPoPProofValidator _dPoPProofValidator;
    private readonly IEventService _events;
    private readonly IResourceOwnerPasswordValidator _resourceOwnerValidator;
    private readonly IProfileService _profile;
    private readonly IDeviceCodeValidator _deviceCodeValidator;
    private readonly IBackchannelAuthenticationRequestIdValidator _backchannelAuthenticationRequestIdValidator;
    private readonly IClock _clock;
    private readonly ILogger _logger;

    private ValidatedTokenRequest _validatedRequest;

    public TokenRequestValidator(
        IdentityServerOptions options,
        IIssuerNameService issuerNameService,
        IServerUrls serverUrls,
        IAuthorizationCodeStore authorizationCodeStore,
        IResourceOwnerPasswordValidator resourceOwnerValidator,
        IProfileService profile,
        IDeviceCodeValidator deviceCodeValidator,
        IBackchannelAuthenticationRequestIdValidator backchannelAuthenticationRequestIdValidator,
        ExtensionGrantValidator extensionGrantValidator,
        ICustomTokenRequestValidator customRequestValidator,
        IResourceValidator resourceValidator,
        IResourceStore resourceStore,
        IRefreshTokenService refreshTokenService,
        IDPoPProofValidator dPoPProofValidator,
        IEventService events,
        IClock clock,
        ILogger<TokenRequestValidator> logger)
    {
        // ...
    }

    public async Task<TokenRequestValidationResult> ValidateRequestAsync(TokenRequestValidationContext context)  // <-------------------------------toks1.1
    {   
        var parameters = context.RequestParameters;
        var clientValidationResult = context.ClientValidationResult;

        _validatedRequest = new ValidatedTokenRequest
        {
            IssuerName = await _issuerNameService.GetCurrentAsync(),
            Raw = parameters ?? throw new ArgumentNullException(nameof(context.RequestParameters)),
            Options = _options
        };

        if (clientValidationResult == null) throw new ArgumentNullException(nameof(context.ClientValidationResult));

        _validatedRequest.SetClient(clientValidationResult.Client, clientValidationResult.Secret, clientValidationResult.Confirmation);
        
        // ... check client protocol type , grant type, esource indicator and basic formatting
    
        _validatedRequest.RequestedResourceIndicator = resourceIndicators.SingleOrDefault();

        // proof token validation
        var proofResult = await ValidateProofToken(context);
        if (proofResult.IsError)
        {
            return proofResult;
        }

        // run specific logic for grants
        switch (grantType)
        {
            case OidcConstants.GrantTypes.AuthorizationCode:
                return await RunValidationAsync(ValidateAuthorizationCodeRequestAsync, parameters);  // <-------------------------------toks1.2
            case OidcConstants.GrantTypes.ClientCredentials:
                return await RunValidationAsync(ValidateClientCredentialsRequestAsync, parameters);
            case OidcConstants.GrantTypes.Password:
                return await RunValidationAsync(ValidateResourceOwnerCredentialRequestAsync, parameters);
            case OidcConstants.GrantTypes.RefreshToken:
                return await RunValidationAsync(ValidateRefreshTokenRequestAsync, parameters);
            case OidcConstants.GrantTypes.DeviceCode:
                return await RunValidationAsync(ValidateDeviceCodeRequestAsync, parameters);
            case OidcConstants.GrantTypes.Ciba:
                return await RunValidationAsync(ValidateCibaRequestRequestAsync, parameters);
            default:
                return await RunValidationAsync(ValidateExtensionGrantRequestAsync, parameters);
        }
    }

    private async Task<TokenRequestValidationResult> ValidateProofToken(TokenRequestValidationContext context)
    {
        // can't allow both both at once
        if (context.ClientCertificate != null && context.DPoPProofToken.IsPresent())
        {
            LogError("Only one confirmation mechanism is allowed at a time.");
            return Invalid(OidcConstants.TokenErrors.InvalidRequest, "Only one confirmation mechanism is allowed at a time");
        }

        // mTLS client cert processing
        if (context.ClientCertificate != null)
        {
            if (_options.MutualTls.AlwaysEmitConfirmationClaim && _validatedRequest.Confirmation.IsMissing())
            {
                // this would be an ephemeral client cert, so not already assigned previosuly via client authentication
                _validatedRequest.Confirmation = context.ClientCertificate.CreateThumbprintCnf();
            }

            _validatedRequest.ProofType = ProofType.ClientCertificate;
            _validatedRequest.ProofKeyThumbprint = context.ClientCertificate.GetSha256Thumbprint();
        }

        // DPoP
        if (context.DPoPProofToken.IsPresent())
        {
            IdentityServerLicenseValidator.Instance.ValidateDPoP();

            if (context.DPoPProofToken.Length > _options.InputLengthRestrictions.DPoPProofToken)
            {
                LogError("DPoP proof token is too long");
                return Invalid(OidcConstants.TokenErrors.InvalidDPoPProof);
            }

            var tokenUrl = _serverUrls.BaseUrl.EnsureTrailingSlash() + ProtocolRoutePaths.Token;
            var dpopContext = new DPoPProofValidatonContext
            {
                ExpirationValidationMode = _validatedRequest.Client.DPoPValidationMode,
                ClientClockSkew = _validatedRequest.Client.DPoPClockSkew,
                ProofToken = context.DPoPProofToken,
                Url = tokenUrl,
                Method = "POST",
            };
            var dpopResult = await _dPoPProofValidator.ValidateAsync(dpopContext);
            if (dpopResult.IsError)
            {
                LogError(dpopResult.ErrorDescription ?? dpopResult.Error);
                var err = Invalid(dpopResult.Error, dpopResult.ErrorDescription);
                err.DPoPNonce = dpopResult.ServerIssuedNonce;
                return err;
            }

            _validatedRequest.Confirmation = dpopResult.Confirmation;
            _validatedRequest.ProofType = ProofType.DPoP;
            _validatedRequest.ProofKeyThumbprint = dpopResult.JsonWebKeyThumbprint;
        }
        else if (_validatedRequest.Client.RequireDPoP)
        {
            LogError("Client requires DPoP and a DPoP header value was not provided.");
            return Invalid(OidcConstants.TokenErrors.InvalidDPoPProof, "Client requires DPoP and a DPoP header value was not provided.");
        }

        return Valid();
    }

    private async Task<TokenRequestValidationResult> RunValidationAsync(Func<NameValueCollection, Task<TokenRequestValidationResult>> validationFunc, NameValueCollection parameters)
    {
        // run standard validation
        var result = await validationFunc(parameters);
        if (result.IsError)
        {
            return result;
        }

        // run custom validation
        _logger.LogTrace("Calling into custom request validator: {type}", _customRequestValidator.GetType().FullName);

        var customValidationContext = new CustomTokenRequestValidationContext { Result = result };
        await _customRequestValidator.ValidateAsync(customValidationContext);

        if (customValidationContext.Result.IsError)
        {
            if (customValidationContext.Result.Error.IsPresent())
            {
                LogError("Custom token request validator", new { error = customValidationContext.Result.Error });
            }
            else
            {
                LogError("Custom token request validator error");
            }

            return customValidationContext.Result;
        }

        LogSuccess();

        IdentityServerLicenseValidator.Instance.ValidateClient(customValidationContext.Result.ValidatedRequest.ClientId);

        return customValidationContext.Result;
    }

    private async Task<TokenRequestValidationResult> ValidateAuthorizationCodeRequestAsync(NameValueCollection parameters)  // <--------------------------toks1.3
    {
        _logger.LogDebug("Start validation of authorization code token request");

        // check if client is authorized for grant type
        if (!_validatedRequest.Client.AllowedGrantTypes.ToList().Contains(GrantType.AuthorizationCode) &&
            !_validatedRequest.Client.AllowedGrantTypes.ToList().Contains(GrantType.Hybrid))
        {
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        // validate authorization code
        var code = parameters.Get(OidcConstants.TokenRequest.Code);
        if (code.IsMissing())
        {
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        if (code.Length > _options.InputLengthRestrictions.AuthorizationCode)
        {
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        _validatedRequest.AuthorizationCodeHandle = code;

        // code is the auth code from ClientApp and authZcode contains the scope that users choose on the consent page
        var authZcode =  await _authorizationCodeStore.GetAuthorizationCodeAsync(code); // <--------------toks1.4, conscope! this is how idp return user info by assoicating auth code  
                                                                                        // with user when user signin by ClientApp to idp in the first time
        // authZcode.Subject contains { IsAuthenticated = true, Name = Emma, Claims = 5 }
                                                                                      
        if (authZcode == null)
        {
            LogError("Invalid authorization code", new { code });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        // validate client binding
        if (authZcode.ClientId != _validatedRequest.Client.ClientId)
        {
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        // ...

        // remove code from store
        await _authorizationCodeStore.RemoveAuthorizationCodeAsync(code);  // <-------------------------------------------toks1.5

        if (authZcode.CreationTime.HasExceeded(authZcode.Lifetime, _clock.UtcNow.UtcDateTime))
        {
            LogError("Authorization code expired", new { code });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        // populate session id
        if (authZcode.SessionId.IsPresent())
        {
            _validatedRequest.SessionId = authZcode.SessionId;
        }

        // validate code expiration
        if (authZcode.CreationTime.HasExceeded(_validatedRequest.Client.AuthorizationCodeLifetime, _clock.UtcNow.UtcDateTime))
        {
            LogError("Authorization code is expired");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        _validatedRequest.AuthorizationCode = authZcode;
        _validatedRequest.Subject = authZcode.Subject;   // <-------------------------------------------toks1.6.

        // validate redirect_uri
        var redirectUri = parameters.Get(OidcConstants.TokenRequest.RedirectUri);
        if (redirectUri.IsMissing())
        {
            LogError("Redirect URI is missing");
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        if (redirectUri.Equals(_validatedRequest.AuthorizationCode.RedirectUri, StringComparison.Ordinal) == false)
        {
            LogError("Invalid redirect_uri", new { redirectUri, expectedRedirectUri = _validatedRequest.AuthorizationCode.RedirectUri });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        // validate scopes are present
        if (_validatedRequest.AuthorizationCode.RequestedScopes == null ||
            !_validatedRequest.AuthorizationCode.RequestedScopes.Any())
        {
            LogError("Authorization code has no associated scopes");
            return Invalid(OidcConstants.TokenErrors.InvalidRequest);
        }

        // resource indicator
        if (_validatedRequest.RequestedResourceIndicator != null &&
            _validatedRequest.AuthorizationCode.RequestedResourceIndicators?.Any() == true &&
            !_validatedRequest.AuthorizationCode.RequestedResourceIndicators.Contains(_validatedRequest.RequestedResourceIndicator))
        {
            return Invalid(OidcConstants.AuthorizeErrors.InvalidTarget, "Resource indicator does not match any resource indicator in the original authorize request.");
        }

        // resource and scope validation 
        var validatedResources = await _resourceValidator.ValidateRequestedResourcesAsync(new ResourceValidationRequest
        {
            Client = _validatedRequest.Client,
            Scopes = _validatedRequest.AuthorizationCode.RequestedScopes,
            ResourceIndicators = _validatedRequest.AuthorizationCode.RequestedResourceIndicators,
        });

        if (!validatedResources.Succeeded)
        {
            if (validatedResources.InvalidResourceIndicators.Any())
            {
                return Invalid(OidcConstants.AuthorizeErrors.InvalidTarget, "Invalid resource indicator.");
            }
            if (validatedResources.InvalidScopes.Any())
            {
                return Invalid(OidcConstants.AuthorizeErrors.InvalidScope, "Invalid scope.");
            }
        }

        IdentityServerLicenseValidator.Instance.ValidateResourceIndicators(_validatedRequest.RequestedResourceIndicator);
        _validatedRequest.ValidatedResources = validatedResources.FilterByResourceIndicator(_validatedRequest.RequestedResourceIndicator);

        // validate PKCE parameters
        var codeVerifier = parameters.Get(OidcConstants.TokenRequest.CodeVerifier);
        if (_validatedRequest.Client.RequirePkce || _validatedRequest.AuthorizationCode.CodeChallenge.IsPresent())
        {
            _logger.LogDebug("Client required a proof key for code exchange. Starting PKCE validation");

            var proofKeyResult = ValidateAuthorizationCodeWithProofKeyParameters(codeVerifier, _validatedRequest.AuthorizationCode);
            if (proofKeyResult.IsError)
            {
                return proofKeyResult;
            }

            _validatedRequest.CodeVerifier = codeVerifier;
        }
        else
        {
            if (codeVerifier.IsPresent())
            {
                LogError("Unexpected code_verifier: {codeVerifier}. This happens when the client is trying to use PKCE, but it is not enabled. Set RequirePkce to true.", codeVerifier);
                return Invalid(OidcConstants.TokenErrors.InvalidGrant);
            }
        }

        // make sure user is enabled
        var isActiveCtx = new IsActiveContext(_validatedRequest.AuthorizationCode.Subject, _validatedRequest.Client, IdentityServerConstants.ProfileIsActiveCallers.AuthorizationCodeValidation);
        await _profile.IsActiveAsync(isActiveCtx);

        if (isActiveCtx.IsActive == false)
        {
            LogError("User has been disabled", new { subjectId = _validatedRequest.AuthorizationCode.Subject.GetSubjectId() });
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        _logger.LogDebug("Validation of authorization code token request success");

        return Valid();
    }

    private async Task<TokenRequestValidationResult> ValidateClientCredentialsRequestAsync(NameValueCollection parameters)
    {
        _logger.LogDebug("Start client credentials token request validation");

        // check if client is authorized for grant type
        if (!_validatedRequest.Client.AllowedGrantTypes.ToList().Contains(GrantType.ClientCredentials))
        {
            LogError("Client not authorized for client credentials flow, check the AllowedGrantTypes setting", new { clientId = _validatedRequest.Client.ClientId });
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        // check if client is allowed to request scopes
        var scopeError = await ValidateRequestedScopesAndResourcesAsync(parameters, ignoreImplicitIdentityScopes: true, ignoreImplicitOfflineAccess: true);
        if (scopeError != null)
        {
            return Invalid(scopeError);
        }

        if (_validatedRequest.ValidatedResources.Resources.IdentityResources.Any())
        {
            LogError("Client cannot request OpenID scopes in client credentials flow", new { clientId = _validatedRequest.Client.ClientId });
            return Invalid(OidcConstants.TokenErrors.InvalidScope);
        }

        if (_validatedRequest.ValidatedResources.Resources.OfflineAccess)
        {
            LogError("Client cannot request a refresh token in client credentials flow", new { clientId = _validatedRequest.Client.ClientId });
            return Invalid(OidcConstants.TokenErrors.InvalidScope);
        }

        _logger.LogDebug("{clientId} credentials token request validation success", _validatedRequest.Client.ClientId);
        return Valid();
    }

    private async Task<TokenRequestValidationResult> ValidateResourceOwnerCredentialRequestAsync(NameValueCollection parameters)
    {
        _logger.LogDebug("Start resource owner password token request validation");

        // check if client is authorized for grant type
        if (!_validatedRequest.Client.AllowedGrantTypes.Contains(GrantType.ResourceOwnerPassword))
        {
            LogError("Client not authorized for resource owner flow, check the AllowedGrantTypes setting", new { client_id = _validatedRequest.Client.ClientId });
            return Invalid(OidcConstants.TokenErrors.UnauthorizedClient);
        }

        // check if client is allowed to request scopes
        var scopeError = await ValidateRequestedScopesAndResourcesAsync(parameters);
        if (scopeError != null)
        {
            return Invalid(scopeError);
        }

        // check resource owner credentials
        var userName = parameters.Get(OidcConstants.TokenRequest.UserName);
        var password = parameters.Get(OidcConstants.TokenRequest.Password);

        if (userName.IsMissing())
        {
            LogError("Username is missing");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        if (password.IsMissing())
        {
            password = "";
        }

        if (userName.Length > _options.InputLengthRestrictions.UserName ||
            password.Length > _options.InputLengthRestrictions.Password)
        {
            LogError("Username or password too long");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        _validatedRequest.UserName = userName;


        // authenticate user
        var resourceOwnerContext = new ResourceOwnerPasswordValidationContext
        {
            UserName = userName,
            Password = password,
            Request = _validatedRequest
        };
        await _resourceOwnerValidator.ValidateAsync(resourceOwnerContext);

        if (resourceOwnerContext.Result.IsError)
        {
            // protect against bad validator implementations
            resourceOwnerContext.Result.Error ??= OidcConstants.TokenErrors.InvalidGrant;

            if (resourceOwnerContext.Result.Error == OidcConstants.TokenErrors.UnsupportedGrantType)
            {
                LogError("Resource owner password credential grant type not supported");
                await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, "password grant type not supported", resourceOwnerContext.Request.Client.ClientId);

                return Invalid(OidcConstants.TokenErrors.UnsupportedGrantType, customResponse: resourceOwnerContext.Result.CustomResponse);
            }

            var errorDescription = "invalid_username_or_password";

            if (resourceOwnerContext.Result.ErrorDescription.IsPresent())
            {
                errorDescription = resourceOwnerContext.Result.ErrorDescription;
            }

            LogInformation("User authentication failed: ", errorDescription ?? resourceOwnerContext.Result.Error);
            await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, errorDescription, resourceOwnerContext.Request.Client.ClientId);

            return Invalid(resourceOwnerContext.Result.Error, errorDescription, resourceOwnerContext.Result.CustomResponse);
        }

        if (resourceOwnerContext.Result.Subject == null)
        {
            var error = "User authentication failed: no principal returned";
            LogError(error);
            await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, error, resourceOwnerContext.Request.Client.ClientId);

            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        // make sure user is enabled
        var isActiveCtx = new IsActiveContext(resourceOwnerContext.Result.Subject, _validatedRequest.Client, IdentityServerConstants.ProfileIsActiveCallers.ResourceOwnerValidation);
        await _profile.IsActiveAsync(isActiveCtx);

        if (isActiveCtx.IsActive == false)
        {
            LogError("User has been disabled", new { subjectId = resourceOwnerContext.Result.Subject.GetSubjectId() });
            await RaiseFailedResourceOwnerAuthenticationEventAsync(userName, "user is inactive", resourceOwnerContext.Request.Client.ClientId);

            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        _validatedRequest.UserName = userName;
        _validatedRequest.Subject = resourceOwnerContext.Result.Subject;

        await RaiseSuccessfulResourceOwnerAuthenticationEventAsync(userName, resourceOwnerContext.Result.Subject.GetSubjectId(), resourceOwnerContext.Request.Client.ClientId);
        _logger.LogDebug("Resource owner password token request validation success.");
        return Valid(resourceOwnerContext.Result.CustomResponse);
    }

    private async Task<TokenRequestValidationResult> ValidateRefreshTokenRequestAsync(NameValueCollection parameters)
    {
        _logger.LogDebug("Start validation of refresh token request");

        var refreshTokenHandle = parameters.Get(OidcConstants.TokenRequest.RefreshToken);
        if (refreshTokenHandle.IsMissing())
        {
            LogError("Refresh token is missing");
            return Invalid(OidcConstants.TokenErrors.InvalidRequest);
        }

        if (refreshTokenHandle.Length > _options.InputLengthRestrictions.RefreshToken)
        {
            LogError("Refresh token too long");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        var result = await _refreshTokenService.ValidateRefreshTokenAsync(refreshTokenHandle, _validatedRequest.Client);

        if (result.IsError)
        {
            LogWarning("Refresh token validation failed. aborting");
            return Invalid(OidcConstants.TokenErrors.InvalidGrant);
        }

        _validatedRequest.RefreshToken = result.RefreshToken;
        _validatedRequest.RefreshTokenHandle = refreshTokenHandle;
        _validatedRequest.Subject = result.RefreshToken.Subject;
        _validatedRequest.SessionId = result.RefreshToken.SessionId;

        // ...
        
        // resource and scope validation 
        var validatedResources = await _resourceValidator.ValidateRequestedResourcesAsync(new ResourceValidationRequest
        {
            Client = _validatedRequest.Client,
            Scopes = _validatedRequest.RefreshToken.AuthorizedScopes,
            ResourceIndicators = resourceIndicators,
        });

        if (!validatedResources.Succeeded)
        {
            if (validatedResources.InvalidResourceIndicators.Any())
            {
                return Invalid(OidcConstants.AuthorizeErrors.InvalidTarget, "Invalid resource indicator.");
            }
            if (validatedResources.InvalidScopes.Any())
            {
                return Invalid(OidcConstants.AuthorizeErrors.InvalidScope, "Invalid scope.");
            }
        }

        IdentityServerLicenseValidator.Instance.ValidateResourceIndicators(_validatedRequest.RequestedResourceIndicator);
        _validatedRequest.ValidatedResources = validatedResources.FilterByResourceIndicator(_validatedRequest.RequestedResourceIndicator);

        _logger.LogDebug("Validation of refresh token request success");
        // todo: more logging - similar to TokenValidator before

        return Valid();
    }

    private async Task<string> ValidateRequestedScopesAndResourcesAsync(NameValueCollection parameters, bool ignoreImplicitIdentityScopes = false, bool ignoreImplicitOfflineAccess = false)
    {
        var scopes = parameters.Get(OidcConstants.TokenRequest.Scope);
        if (scopes.IsMissing())
        {
            _logger.LogTrace("Client provided no scopes - checking allowed scopes list");

            if (!IEnumerableExtensions.IsNullOrEmpty(_validatedRequest.Client.AllowedScopes))
            {
                // this finds all the scopes the client is allowed to access
                var clientAllowedScopes = new List<string>();
                if (!ignoreImplicitIdentityScopes)
                {
                    var resources = await _resourceStore.FindResourcesByScopeAsync(_validatedRequest.Client.AllowedScopes);
                    clientAllowedScopes.AddRange(resources.ToScopeNames().Where(x => _validatedRequest.Client.AllowedScopes.Contains(x)));
                }
                else
                {
                    var apiScopes = await _resourceStore.FindApiScopesByNameAsync(_validatedRequest.Client.AllowedScopes);
                    clientAllowedScopes.AddRange(apiScopes.Select(x => x.Name));
                }

                if (!ignoreImplicitOfflineAccess)
                {
                    if (_validatedRequest.Client.AllowOfflineAccess)
                    {
                        clientAllowedScopes.Add(IdentityServerConstants.StandardScopes.OfflineAccess);
                    }
                }

                scopes = clientAllowedScopes.Distinct().ToSpaceSeparatedString();
                _logger.LogTrace("Defaulting to: {scopes}", scopes);
            }
            else
            {
                LogError("No allowed scopes configured for client", new { clientId = _validatedRequest.Client.ClientId });
                return OidcConstants.TokenErrors.InvalidScope;
            }
        }

        if (scopes.Length > _options.InputLengthRestrictions.Scope)
        {
            LogError("Scope parameter exceeds max allowed length");
            return OidcConstants.TokenErrors.InvalidScope;
        }

        var requestedScopes = scopes.ParseScopesString();

        if (requestedScopes == null)
        {
            LogError("No scopes found in request");
            return OidcConstants.TokenErrors.InvalidScope;
        }


        var resourceIndicators = _validatedRequest.RequestedResourceIndicator == null ?
            Enumerable.Empty<string>() :
            new[] { _validatedRequest.RequestedResourceIndicator };

        var resourceValidationResult = await _resourceValidator.ValidateRequestedResourcesAsync(new ResourceValidationRequest
        {
            Client = _validatedRequest.Client,
            Scopes = requestedScopes,
            ResourceIndicators = resourceIndicators,
        });

        if (!resourceValidationResult.Succeeded)
        {
            if (resourceValidationResult.InvalidResourceIndicators.Any())
            {
                LogError("Invalid resource indicator");
                return OidcConstants.TokenErrors.InvalidTarget;
            }

            if (resourceValidationResult.InvalidScopes.Any())
            {
                LogError("Invalid scopes requested");
            }
            else
            {
                LogError("Invalid scopes for client requested");
            }

            return OidcConstants.TokenErrors.InvalidScope;
        }

        _validatedRequest.RequestedScopes = requestedScopes;

        IdentityServerLicenseValidator.Instance.ValidateResourceIndicators(_validatedRequest.RequestedResourceIndicator);
        _validatedRequest.ValidatedResources = resourceValidationResult.FilterByResourceIndicator(_validatedRequest.RequestedResourceIndicator);

        return null;
    }

    private TokenRequestValidationResult Valid(Dictionary<string, object> customResponse = null)
    {
        return new TokenRequestValidationResult(_validatedRequest, customResponse);
    }

    private TokenRequestValidationResult Invalid(string error, string errorDescription = null, Dictionary<string, object> customResponse = null)
    {
        return new TokenRequestValidationResult(_validatedRequest, error, errorDescription, customResponse);
    }
  
    private async Task<TokenRequestValidationResult> ValidateDeviceCodeRequestAsync(NameValueCollection parameters);
    private async Task<TokenRequestValidationResult> ValidateCibaRequestRequestAsync(NameValueCollection parameters);
    private async Task<TokenRequestValidationResult> ValidateExtensionGrantRequestAsync(NameValueCollection parameters); 
    private TokenRequestValidationResult ValidateAuthorizationCodeWithProofKeyParameters(string codeVerifier, AuthorizationCode authZcode);
    private bool ValidateCodeVerifierAgainstCodeChallenge(string codeVerifier, string codeChallenge, string codeChallengeMethod); 
    // ...
}
//----------------------------------Ʌ
```

```C#
//-------------------------------------V
public class DefaultRefreshTokenService : IRefreshTokenService
{
    protected readonly ILogger Logger;
    protected IRefreshTokenStore RefreshTokenStore { get; }
    protected IProfileService Profile { get; }
    protected IClock Clock { get; }
    protected PersistentGrantOptions Options { get; }

    public DefaultRefreshTokenService(
        IRefreshTokenStore refreshTokenStore, 
        IProfileService profile,
        IClock clock,
        PersistentGrantOptions options,
        ILogger<DefaultRefreshTokenService> logger)
    {
        // ...
    }

    public virtual async Task<TokenValidationResult> ValidateRefreshTokenAsync(string tokenHandle, Client client)
    {
        using var activity = Tracing.ServiceActivitySource.StartActivity("DefaultRefreshTokenService.ValidateRefreshToken");
        
        var invalidGrant = new TokenValidationResult
        {
            IsError = true, Error = OidcConstants.TokenErrors.InvalidGrant
        };

        Logger.LogTrace("Start refresh token validation");

        // check if refresh token is valid
        var refreshToken = await RefreshTokenStore.GetRefreshTokenAsync(tokenHandle);
        if (refreshToken == null)
        {
            Logger.LogWarning("Invalid refresh token");
            return invalidGrant;
        }

        // check if refresh token has expired
        if (refreshToken.CreationTime.HasExceeded(refreshToken.Lifetime, Clock.UtcNow.UtcDateTime))
        {
            Logger.LogWarning("Refresh token has expired.");
            return invalidGrant;
        }
            
        // check if client belongs to requested refresh token
        if (client.ClientId != refreshToken.ClientId)
        {
            Logger.LogError("{0} tries to refresh token belonging to {1}", client.ClientId, refreshToken.ClientId);
            return invalidGrant;
        }

        // check if client still has offline_access scope
        if (!client.AllowOfflineAccess)
        {
            Logger.LogError("{clientId} does not have access to offline_access scope anymore", client.ClientId);
            return invalidGrant;
        }
            
        // check if refresh token has been consumed
        if (refreshToken.ConsumedTime.HasValue)
        {
            if ((await AcceptConsumedTokenAsync(refreshToken)) == false)
            {
                Logger.LogWarning("Rejecting refresh token because it has been consumed already.");
                return invalidGrant;
            }
        }
            
        // make sure user is enabled
        var isActiveCtx = new IsActiveContext(
            refreshToken.Subject,
            client,
            IdentityServerConstants.ProfileIsActiveCallers.RefreshTokenValidation);

        await Profile.IsActiveAsync(isActiveCtx);

        if (isActiveCtx.IsActive == false)
        {
            Logger.LogError("{subjectId} has been disabled", refreshToken.Subject.GetSubjectId());
            return invalidGrant;
        }
            
        return new TokenValidationResult
        {
            IsError = false, 
            RefreshToken = refreshToken, 
            Client = client
        };
    }

    protected virtual Task<bool> AcceptConsumedTokenAsync(RefreshToken refreshToken)
    {
        // by default we will not accept consumed tokens change the behavior here to implement a time window you can also implement additional revocation logic here
        return Task.FromResult(false);
    }

    public virtual async Task<string> CreateRefreshTokenAsync(RefreshTokenCreationRequest request)
    {
        using var activity = Tracing.ServiceActivitySource.StartActivity("DefaultRefreshTokenService.CreateRefreshToken");
        
        Logger.LogDebug("Creating refresh token");

        int lifetime;
        if (request.Client.RefreshTokenExpiration == TokenExpiration.Absolute)
        {
            Logger.LogDebug("Setting an absolute lifetime: {absoluteLifetime}",
                request.Client.AbsoluteRefreshTokenLifetime);
            lifetime = request.Client.AbsoluteRefreshTokenLifetime;
        }
        else
        {
            lifetime = request.Client.SlidingRefreshTokenLifetime;
            if (request.Client.AbsoluteRefreshTokenLifetime > 0 && lifetime > request.Client.AbsoluteRefreshTokenLifetime)
            {
                Logger.LogWarning(
                    "Client {clientId}'s configured " + nameof(request.Client.SlidingRefreshTokenLifetime) +
                    " of {slidingLifetime} exceeds its " + nameof(request.Client.AbsoluteRefreshTokenLifetime) +
                    " of {absoluteLifetime}. The refresh_token's sliding lifetime will be capped to the absolute lifetime",
                    request.Client.ClientId, lifetime, request.Client.AbsoluteRefreshTokenLifetime);
                lifetime = request.Client.AbsoluteRefreshTokenLifetime;
            }

            Logger.LogDebug("Setting a sliding lifetime: {slidingLifetime}", lifetime);
        }

        var refreshToken = new RefreshToken
        {
            Subject = request.Subject,
            SessionId = request.AccessToken.SessionId,
            ClientId = request.Client.ClientId,
            Description = request.Description,
            AuthorizedScopes = request.AuthorizedScopes,
            AuthorizedResourceIndicators = request.AuthorizedResourceIndicators,
            ProofType = request.ProofType,

            CreationTime = Clock.UtcNow.UtcDateTime,
            Lifetime = lifetime,
        };
        refreshToken.SetAccessToken(request.AccessToken, request.RequestedResourceIndicator);

        var handle = await RefreshTokenStore.StoreRefreshTokenAsync(refreshToken);
        return handle;
    }

    public virtual async Task<string> UpdateRefreshTokenAsync(RefreshTokenUpdateRequest request)
    {
        using var activity = Tracing.ServiceActivitySource.StartActivity("DefaultTokenCreationService.UpdateRefreshToken");
        
        Logger.LogDebug("Updating refresh token");

        var handle = request.Handle;
        bool needsCreate = false;
        bool needsUpdate = request.MustUpdate;

        if (request.Client.RefreshTokenUsage == TokenUsage.OneTimeOnly)
        {

            if(Options.DeleteOneTimeOnlyRefreshTokensOnUse)
            {
                Logger.LogDebug("Token usage is one-time only and refresh behavior is delete. Deleting current handle, and generating new handle");

                await RefreshTokenStore.RemoveRefreshTokenAsync(handle);
            } 
            else
            {
                Logger.LogDebug("Token usage is one-time only and refresh behavior is mark as consumed. Setting current handle as consumed, and generating new handle");
                
                // flag as consumed
                if (request.RefreshToken.ConsumedTime == null)
                {
                    request.RefreshToken.ConsumedTime = Clock.UtcNow.UtcDateTime;
                    await RefreshTokenStore.UpdateRefreshTokenAsync(handle, request.RefreshToken);
                }
            }

            // create new one
            needsCreate = true;
        }

        if (request.Client.RefreshTokenExpiration == TokenExpiration.Sliding)
        {
            Logger.LogDebug("Refresh token expiration is sliding - extending lifetime");

            // if absolute exp > 0, make sure we don't exceed absolute exp
            // if absolute exp = 0, allow indefinite slide
            var currentLifetime = request.RefreshToken.CreationTime.GetLifetimeInSeconds(Clock.UtcNow.UtcDateTime);
            Logger.LogDebug("Current lifetime: {currentLifetime}", currentLifetime.ToString());

            var newLifetime = currentLifetime + request.Client.SlidingRefreshTokenLifetime;
            Logger.LogDebug("New lifetime: {slidingLifetime}", newLifetime.ToString());

            // zero absolute refresh token lifetime represents unbounded absolute lifetime
            // if absolute lifetime > 0, cap at absolute lifetime
            if (request.Client.AbsoluteRefreshTokenLifetime > 0 && newLifetime > request.Client.AbsoluteRefreshTokenLifetime)
            {
                newLifetime = request.Client.AbsoluteRefreshTokenLifetime;
                Logger.LogDebug("New lifetime exceeds absolute lifetime, capping it to {newLifetime}",
                    newLifetime.ToString());
            }

            request.RefreshToken.Lifetime = newLifetime;
            needsUpdate = true;
        }

        if (needsCreate)
        {
            // set it to null so that we save non-consumed token
            request.RefreshToken.ConsumedTime = null;
            handle = await RefreshTokenStore.StoreRefreshTokenAsync(request.RefreshToken);
            Logger.LogDebug("Created refresh token in store");
        }
        else if (needsUpdate)
        {
            await RefreshTokenStore.UpdateRefreshTokenAsync(handle, request.RefreshToken);
            Logger.LogDebug("Updated refresh token in store");
        }
        else
        {
            Logger.LogDebug("No updates to refresh token done");
        }

        return handle;
    }
}
//-------------------------------------Ʌ
```

```C#
//----------------------------------->>
public interface IPersistedGrantStore
{
    Task StoreAsync(PersistedGrant grant);
    Task<PersistedGrant?> GetAsync(string key);
    Task<IEnumerable<PersistedGrant>> GetAllAsync(PersistedGrantFilter filter);
    Task RemoveAsync(string key);
    Task RemoveAllAsync(PersistedGrantFilter filter);
}
//-----------------------------------<<

//------------------------------V
public class PersistedGrantStore : Duende.IdentityServer.Stores.IPersistedGrantStore  // from Duende.IdentityServer.EntityFramework.Stores
{
    protected readonly IPersistedGrantDbContext Context;

    public PersistedGrantStore(IPersistedGrantDbContext context, ILogger<PersistedGrantStore> logger, ICancellationTokenProvider cancellationTokenProvider)
    {
        Context = context;
        // ...
    }

    // ...
}
//------------------------------Ʌ

//---------------------------V
public class ValidatedRequest
{
    public NameValueCollection Raw { get; set; } = default!;
    public Client Client { get; set; } = default!;
    public string IssuerName { get; set; } = default!;
    public ParsedSecret? Secret { get; set; }
    public int AccessTokenLifetime { get; set; }
    public ICollection<Claim> ClientClaims { get; set; } = new HashSet<Claim>(new ClaimComparer());
    public AccessTokenType AccessTokenType { get; set; }
    public ClaimsPrincipal? Subject { get; set; }
    public string? SessionId { get; set; }
    public IdentityServerOptions Options { get; set; } = default!;
    public ResourceValidationResult ValidatedResources { get; set; } = new ResourceValidationResult();
    public string? Confirmation { get; set; }
    public ProofType ProofType { get; set; }

    public string ClientId { get; set; } = default!;

    public void SetClient(Client client, ParsedSecret? secret = null, string confirmation = "")
    {
        Client = client ?? throw new ArgumentNullException(nameof(client));
        Secret = secret;
        Confirmation = confirmation;
        ClientId = client.ClientId;

        AccessTokenLifetime = client.AccessTokenLifetime;
        AccessTokenType = client.AccessTokenType;
        ClientClaims = client.Claims.Select(c => new Claim(c.Type, c.Value, c.ValueType)).ToList();
    }
}
//---------------------------Ʌ

//------------------------------------V
public class ValidatedAuthorizeRequest : ValidatedRequest
{
    public string ResponseType { get; set; } = default!;
    public string ResponseMode { get; set; } = default!;
    public string GrantType { get; set; } = default!;
    public string RedirectUri { get; set; } = default!;
    public List<string> RequestedScopes { get; set; } = default!;
    public IEnumerable<string>? RequestedResourceIndicators { get; set; }
    public bool WasConsentShown { get; set; }
    public string? Description { get; set; }
    public string? State { get; set; }
    public string? UiLocales { get; set; }
    public bool IsOpenIdRequest { get; set; }
    public bool IsApiResourceRequest { get; set; }
    public string? Nonce { get; set; }
    public List<string>? AuthenticationContextReferenceClasses { get; set; }
    public string? DisplayMode { get; set; }
    public IEnumerable<string> PromptModes { get; set; } = Enumerable.Empty<string>();
    public IEnumerable<string> OriginalPromptModes { get; set; } = Enumerable.Empty<string>();
    public IEnumerable<string> ProcessedPromptModes { get; set; } = Enumerable.Empty<string>();
    public int? MaxAge { get; set; }
    public string? LoginHint { get; set; }
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public IEnumerable<Claim> RequestObjectValues { get; set; } = new List<Claim>();
    public string? RequestObject { get; set; }
    public string? DPoPKeyThumbprint { get; set; }
    public string? PushedAuthorizationReferenceValue { get; set; }
    public AuthorizeRequestType AuthorizeRequestType { get; set; }
   
    public bool AccessTokenRequested => ResponseType == OidcConstants.ResponseTypes.IdTokenToken ||
                                        ResponseType == OidcConstants.ResponseTypes.Code ||
                                        ResponseType == OidcConstants.ResponseTypes.CodeIdToken ||
                                        ResponseType == OidcConstants.ResponseTypes.CodeToken ||
                                        ResponseType == OidcConstants.ResponseTypes.CodeIdTokenToken;

    public ValidatedAuthorizeRequest()
    {
        RequestedScopes = new List<string>();
        AuthenticationContextReferenceClasses = new List<string>();
    }
}

public enum AuthorizeRequestType
{
    Authorize,
    PushedAuthorization,
    AuthorizeWithPushedParameters
}
//------------------------------------Ʌ

//---------------------------V
internal class TokenValidator : ITokenValidator
{
    private readonly ILogger _logger;
    private readonly IdentityServerOptions _options;
    private readonly IIssuerNameService _issuerNameService;
    private readonly IReferenceTokenStore _referenceTokenStore;
    private readonly ICustomTokenValidator _customValidator;
    private readonly IClientStore _clients;
    private readonly IProfileService _profile;
    private readonly IKeyMaterialService _keys;
    private readonly ISessionCoordinationService _sessionCoordinationService;
    private readonly IClock _clock;
    private readonly TokenValidationLog _log;

    public TokenValidator(
        IdentityServerOptions options,
        IIssuerNameService issuerNameService,
        IClientStore clients,
        IProfileService profile,
        IReferenceTokenStore referenceTokenStore,
        ICustomTokenValidator customValidator,
        IKeyMaterialService keys,
        ISessionCoordinationService sessionCoordinationService,
        IClock clock,
        ILogger<TokenValidator> logger)
    {
        _options = options;
        _issuerNameService = issuerNameService;
        _clients = clients;
        _profile = profile;
        _referenceTokenStore = referenceTokenStore;
        _customValidator = customValidator;
        _keys = keys;
        _sessionCoordinationService = sessionCoordinationService;
        _clock = clock;
        _logger = logger;

        _log = new TokenValidationLog();
    }

    public async Task<TokenValidationResult> ValidateIdentityTokenAsync(string token, string clientId = null,
        bool validateLifetime = true)
    {
        using var activity = Tracing.BasicActivitySource.StartActivity("TokenValidator.ValidateIdentityToken");
        
        _logger.LogDebug("Start identity token validation");

        if (token.Length > _options.InputLengthRestrictions.Jwt)
        {
            _logger.LogError("JWT too long");
            return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
        }

        if (clientId.IsMissing())
        {
            clientId = GetClientIdFromJwt(token);

            if (clientId.IsMissing())
            {
                _logger.LogError("No clientId supplied, can't find id in identity token.");
                return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
            }
        }

        _log.ClientId = clientId;
        _log.ValidateLifetime = validateLifetime;

        var client = await _clients.FindEnabledClientByIdAsync(clientId);
        if (client == null)
        {
            _logger.LogError("Unknown or disabled client: {clientId}.", clientId);
            return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
        }

        _log.ClientName = client.ClientName;
        _logger.LogDebug("Client found: {clientId} / {clientName}", client.ClientId, client.ClientName);

        var keys = await _keys.GetValidationKeysAsync();
        var result = await ValidateJwtAsync(token, keys, audience: clientId, validateLifetime: validateLifetime);

        result.Client = client;

        if (result.IsError)
        {
            LogError("Error validating JWT");
            return result;
        }

        _logger.LogDebug("Calling into custom token validator: {type}", _customValidator.GetType().FullName);
        var customResult = await _customValidator.ValidateIdentityTokenAsync(result);

        if (customResult.IsError)
        {
            LogError("Custom validator failed: " + (customResult.Error ?? "unknown"));
            return customResult;
        }

        _log.Claims = customResult.Claims.ToClaimsDictionary();

        LogSuccess();
        return customResult;
    }

    public async Task<TokenValidationResult> ValidateAccessTokenAsync(string token, string expectedScope = null)
    {
        using var activity = Tracing.BasicActivitySource.StartActivity("TokenValidator.ValidateAccessToken");
        
        _logger.LogTrace("Start access token validation");

        _log.ExpectedScope = expectedScope;
        _log.ValidateLifetime = true;

        TokenValidationResult result;

        if (token.Contains("."))
        {
            if (token.Length > _options.InputLengthRestrictions.Jwt)
            {
                _logger.LogError("JWT too long");

                return new TokenValidationResult
                {
                    IsError = true,
                    Error = OidcConstants.ProtectedResourceErrors.InvalidToken,
                    ErrorDescription = "Token too long"
                };
            }

            _log.AccessTokenType = AccessTokenType.Jwt.ToString();
            result = await ValidateJwtAsync(
                token,
                await _keys.GetValidationKeysAsync());
        }
        else
        {
            if (token.Length > _options.InputLengthRestrictions.TokenHandle)
            {
                _logger.LogError("token handle too long");

                return new TokenValidationResult
                {
                    IsError = true,
                    Error = OidcConstants.ProtectedResourceErrors.InvalidToken,
                    ErrorDescription = "Token too long"
                };
            }

            _log.AccessTokenType = AccessTokenType.Reference.ToString();
            result = await ValidateReferenceAccessTokenAsync(token);
        }

        _log.Claims = result.Claims.ToClaimsDictionary();

        if (result.IsError)
        {
            return result;
        }

        // make sure client is still active (if client_id claim is present)
        var clientClaim = result.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.ClientId);
        if (clientClaim != null)
        {
            var client = await _clients.FindEnabledClientByIdAsync(clientClaim.Value);
            if (client == null)
            {
                _logger.LogError("Client deleted or disabled: {clientId}", clientClaim.Value);

                result.IsError = true;
                result.Error = OidcConstants.ProtectedResourceErrors.InvalidToken;
                result.Claims = null;

                return result;
            }
        }

        // make sure user is still active (if sub claim is present)
        var subClaim = result.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject);
        if (subClaim != null)
        {
            var principal = Principal.Create("tokenvalidator", result.Claims.ToArray());

            if (result.ReferenceTokenId.IsPresent())
            {
                principal.Identities.First()
                    .AddClaim(new Claim(JwtClaimTypes.ReferenceTokenId, result.ReferenceTokenId));
            }

            var isActiveCtx = new IsActiveContext(principal, result.Client,
                IdentityServerConstants.ProfileIsActiveCallers.AccessTokenValidation);
            await _profile.IsActiveAsync(isActiveCtx);

            if (isActiveCtx.IsActive == false)
            {
                _logger.LogError("User marked as not active: {subject}", subClaim.Value);

                result.IsError = true;
                result.Error = OidcConstants.ProtectedResourceErrors.InvalidToken;
                result.Claims = null;

                return result;
            }

            var sub = subClaim.Value;
            var sid = principal.FindFirstValue("sid");
            if (sid != null)
            {
                var sessionResult = await _sessionCoordinationService.ValidateSessionAsync(new SessionValidationRequest
                {
                    SubjectId = sub,
                    SessionId = sid,
                    Client = result.Client,
                    Type = SessionValidationType.AccessToken
                });

                if (!sessionResult)
                {
                    _logger.LogError("Server-side session invalid for subject Id {subjectId} and session Id {sessionId}.", sub, sid);
                    return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
                }
            }
        }

        // check expected scope(s)
        if (expectedScope.IsPresent())
        {
            var scope = result.Claims.FirstOrDefault(c =>
                c.Type == JwtClaimTypes.Scope && c.Value == expectedScope);
            if (scope == null)
            {
                LogError($"Checking for expected scope {expectedScope} failed");
                return Invalid(OidcConstants.ProtectedResourceErrors.InsufficientScope);
            }
        }

        _logger.LogDebug("Calling into custom token validator: {type}", _customValidator.GetType().FullName);
        var customResult = await _customValidator.ValidateAccessTokenAsync(result);

        if (customResult.IsError)
        {
            LogError("Custom validator failed: " + (customResult.Error ?? "unknown"));
            return customResult;
        }

        // add claims again after custom validation
        _log.Claims = customResult.Claims.ToClaimsDictionary();

        LogSuccess();
        return customResult;
    }

    private async Task<TokenValidationResult> ValidateJwtAsync(string jwtString,
        IEnumerable<SecurityKeyInfo> validationKeys, bool validateLifetime = true, string audience = null)
    {
        using var activity = Tracing.BasicActivitySource.StartActivity("TokenValidator.ValidateJwt");
        
        var handler = new JsonWebTokenHandler();

        var parameters = new TokenValidationParameters
        {
            ValidIssuer = await _issuerNameService.GetCurrentAsync(),
            IssuerSigningKeys = validationKeys.Select(k => k.Key),
            ValidateLifetime = validateLifetime
        };

        if (audience.IsPresent())
        {
            parameters.ValidAudience = audience;
        }
        else
        {
            parameters.ValidateAudience = false;

            // if no audience is specified, we make at least sure that it is an access token
            if (_options.AccessTokenJwtType.IsPresent())
            {
                parameters.ValidTypes = new[] { _options.AccessTokenJwtType };
            }
        }
            
        var result = await handler.ValidateTokenAsync(jwtString, parameters);
        if (!result.IsValid)
        {
            if (result.Exception is SecurityTokenExpiredException expiredException)
            {
                _logger.LogInformation(expiredException, "JWT token validation error: {exception}",
                    expiredException.Message);
                return Invalid(OidcConstants.ProtectedResourceErrors.ExpiredToken);
            }
            else
            {
                _logger.LogError(result.Exception, "JWT token validation error: {exception}",
                    result.Exception.Message);
                return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
            }
        }

        var id = result.ClaimsIdentity;

        // if access token contains an ID, log it
        var jwtId = id.FindFirst(JwtClaimTypes.JwtId);
        if (jwtId != null)
        {
            _log.JwtId = jwtId.Value;
        }

        // load the client that belongs to the client_id claim
        Client client = null;
        var clientId = id.FindFirst(JwtClaimTypes.ClientId);
        if (clientId != null)
        {
            client = await _clients.FindEnabledClientByIdAsync(clientId.Value);
            if (client == null)
            {
                LogError($"Client deleted or disabled: {clientId}");
                return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
            }
        }

        var claims = id.Claims.ToList();

        // check the scope format (array vs space delimited string)
        var scopes = claims.Where(c => c.Type == JwtClaimTypes.Scope).ToArray();
        if (scopes.Any())
        {
            foreach (var scope in scopes)
            {
                if (scope.Value.Contains(" "))
                {
                    claims.Remove(scope);

                    var values = scope.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    foreach (var value in values)
                    {
                        claims.Add(new Claim(JwtClaimTypes.Scope, value));
                    }
                }
            }
        }

        return new TokenValidationResult
        {
            IsError = false,

            Claims = claims,
            Client = client,
            Jwt = jwtString
        };
    }

    private async Task<TokenValidationResult> ValidateReferenceAccessTokenAsync(string tokenHandle)   // <---------------------itp, tokenHandle is same as reference-type access key
    {
        using var activity = Tracing.BasicActivitySource.StartActivity("TokenValidator.ValidateReferenceAccessToken");
        
        _log.TokenHandle = tokenHandle;
        var token = await _referenceTokenStore.GetReferenceTokenAsync(tokenHandle);  // <---------------------itp
        //  token contains the claims such as { "role" : "payinguser" }

        if (token == null)
        {
            LogError("Invalid reference token.");
            return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
        }

        if (token.CreationTime.HasExceeded(token.Lifetime, _clock.UtcNow.UtcDateTime))
        {
            LogError("Token expired.");

            await _referenceTokenStore.RemoveReferenceTokenAsync(tokenHandle);
            return Invalid(OidcConstants.ProtectedResourceErrors.ExpiredToken);
        }

        // load the client that is defined in the token
        Client client = null;
        if (token.ClientId != null)
        {
            client = await _clients.FindEnabledClientByIdAsync(token.ClientId);
        }

        if (client == null)
        {
            LogError($"Client deleted or disabled: {token.ClientId}");
            return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
        }

        return new TokenValidationResult
        {
            IsError = false,

            Client = client,
            Claims = ReferenceTokenToClaims(token),
            ReferenceToken = token,
            ReferenceTokenId = tokenHandle
        };
    }

    private IEnumerable<Claim> ReferenceTokenToClaims(Token token)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtClaimTypes.Issuer, token.Issuer),
            new Claim(JwtClaimTypes.NotBefore,
                new DateTimeOffset(token.CreationTime).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new Claim(JwtClaimTypes.IssuedAt, new DateTimeOffset(token.CreationTime).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64),
            new Claim(JwtClaimTypes.Expiration,
                new DateTimeOffset(token.CreationTime).AddSeconds(token.Lifetime).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64)
        };

        if (!String.IsNullOrEmpty(token.Confirmation))
        {
            claims.Add(new Claim(JwtClaimTypes.Confirmation, token.Confirmation, IdentityServerConstants.ClaimValueTypes.Json));
        }

        foreach (var aud in token.Audiences)
        {
            claims.Add(new Claim(JwtClaimTypes.Audience, aud));
        }

        claims.AddRange(token.Claims);
        return claims;
    }

    private string GetClientIdFromJwt(string token)
    {
        try
        {
            var jwt = new JwtSecurityToken(token);
            var clientId = jwt.Audiences.FirstOrDefault();

            return clientId;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Malformed JWT token: {exception}", ex.Message);
            return null;
        }
    }
}
//---------------------------Ʌ

//-------------------------------V
public class DefaultGrantStore<T>
{
    protected string GrantType { get; }
    protected ILogger Logger { get; }
    protected IPersistedGrantStore Store { get; }
    protected IPersistentGrantSerializer Serializer { get; }
    protected IHandleGenerationService HandleGenerationService { get; }

    protected DefaultGrantStore(string grantType,
        IPersistedGrantStore store,
        IPersistentGrantSerializer serializer,
        IHandleGenerationService handleGenerationService,
        ILogger logger)
    {
        // ...
    }

    private const string KeySeparator = ":";

    protected const string HexEncodingFormatSuffix = "-1";

    protected async Task<string> CreateHandleAsync()
    {
        return await HandleGenerationService.GenerateAsync() + HexEncodingFormatSuffix;
    }

    protected virtual string GetHashedKey(string value)
    {
        var key = (value + KeySeparator + GrantType);

        if (value.EndsWith(HexEncodingFormatSuffix))
        {
            // newer format >= v6; uses hex encoding to avoid collation issues
            using (var sha = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(key);
                var hash = sha.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }

        // old format <= v5
        return key.Sha256();
    }

    protected virtual async Task<T> GetItemAsync(string key)
    {
        var hashedKey = GetHashedKey(key);
        var item = await GetItemByHashedKeyAsync(hashedKey);
        if (item == null)
        {
            Logger.LogDebug("{grantType} grant with value: {key} not found in store.", GrantType, key);
        }
        return item;
    }

    protected virtual async Task<T> GetItemByHashedKeyAsync(string hashedKey)
    {
        var grant = await Store.GetAsync(hashedKey);
        if (grant != null && grant.Type == GrantType)
        {
            try
            {
                return Serializer.Deserialize<T>(grant.Data);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Failed to deserialize JSON from grant store.");
            }
        }

        return default;
    }

    protected virtual async Task<IEnumerable<T>> GetAllAsync(PersistedGrantFilter filter)
    {
        filter.Type = GrantType;
        var items = await Store.GetAllAsync(filter);
        var result = items.Select(x => Serializer.Deserialize<T>(x.Data)).ToArray();
        return result;
    }

    protected virtual async Task<string> CreateItemAsync(T item, string clientId, string subjectId, string sessionId, string description, DateTime created, int lifetime)
    {
        var handle = await CreateHandleAsync();
        await StoreItemAsync(handle, item, clientId, subjectId, sessionId, description, created, created.AddSeconds(lifetime));
        return handle;
    }

    protected virtual Task StoreItemAsync(string key, T item, string clientId, string subjectId, string sessionId, string description, DateTime created, DateTime? expiration, DateTime? consumedTime = null)
    {
        key = GetHashedKey(key);
        return StoreItemByHashedKeyAsync(key, item, clientId, subjectId, sessionId, description, created, expiration, consumedTime);
    }

    protected virtual async Task StoreItemByHashedKeyAsync(string hashedKey, T item, string clientId, string subjectId, string sessionId, string description, DateTime created, DateTime? expiration, DateTime? consumedTime = null)
    {
        var json = Serializer.Serialize(item);

        var grant = new PersistedGrant
        {
            Key = hashedKey,
            Type = GrantType,
            ClientId = clientId,
            SubjectId = subjectId,
            SessionId = sessionId,
            Description = description,
            CreationTime = created,
            Expiration = expiration,
            ConsumedTime = consumedTime,
            Data = json
        };

        await Store.StoreAsync(grant);
    }

    protected virtual Task RemoveItemAsync(string key)
    {
        key = GetHashedKey(key);
        return RemoveItemByHashedKeyAsync(key);
    }

    protected virtual async Task RemoveItemByHashedKeyAsync(string key)
    {
        await Store.RemoveAsync(key);
    }

    protected virtual async Task RemoveAllAsync(string subjectId, string clientId, string sessionId = null)
    {
        await Store.RemoveAllAsync(new PersistedGrantFilter
        {
            SubjectId = subjectId,
            ClientId = clientId,
            SessionId = sessionId,
            Type = GrantType
        });
    }
}
//-------------------------------Ʌ

//-----------------------------------V
public class DefaultRefreshTokenStore : DefaultGrantStore<RefreshToken>, IRefreshTokenStore
{
    public DefaultRefreshTokenStore(
        IPersistedGrantStore store, 
        IPersistentGrantSerializer serializer, 
        IHandleGenerationService handleGenerationService,
        ILogger<DefaultRefreshTokenStore> logger) 
        : base(IdentityServerConstants.PersistedGrantTypes.RefreshToken, store, serializer, handleGenerationService, logger) { }

    public async Task<string> StoreRefreshTokenAsync(RefreshToken refreshToken)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("DefaultRefreshTokenStore.StoreRefreshTokenAsync");
        
        return await CreateItemAsync(refreshToken, refreshToken.ClientId, refreshToken.SubjectId, refreshToken.SessionId, refreshToken.Description, refreshToken.CreationTime, refreshToken.Lifetime);
    }

    public Task UpdateRefreshTokenAsync(string handle, RefreshToken refreshToken)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("DefaultRefreshTokenStore.UpdateRefreshToken");
        
        return StoreItemAsync(handle, refreshToken, refreshToken.ClientId, refreshToken.SubjectId, refreshToken.SessionId, refreshToken.Description, refreshToken.CreationTime, refreshToken.CreationTime.AddSeconds(refreshToken.Lifetime), refreshToken.ConsumedTime);
    }

    public Task<RefreshToken> GetRefreshTokenAsync(string refreshTokenHandle)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("DefaultRefreshTokenStore.GetRefreshToken");
        
        return GetItemAsync(refreshTokenHandle);
    }

    public Task RemoveRefreshTokenAsync(string refreshTokenHandle)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("DefaultRefreshTokenStore.RemoveRefreshToken");
        
        return RemoveItemAsync(refreshTokenHandle);
    }

    public Task RemoveRefreshTokensAsync(string subjectId, string clientId)
    {
        using var activity = Tracing.StoreActivitySource.StartActivity("DefaultRefreshTokenStore.RemoveRefreshTokens");
        
        return RemoveAllAsync(subjectId, clientId);
    }
}
//-----------------------------------Ʌ
```

```C#
//------------------------------>>
public interface IProfileService  // the purpose of IProfileService is to allow "UserStore" such as TestUserStore or LocalUserService to return more user data from UserInfo endpoint
{                                 // as we normally don't want the cookie to become too big and only includes essential claims in the cookie, and let user decide whether to call UserInfo
    Task GetProfileDataAsync(ProfileDataRequestContext context);
    Task IsActiveAsync(IsActiveContext context);
}
//------------------------------<<

//------------------------------------V
public class ProfileDataRequestContext
{
    public ProfileDataRequestContext() { }

    public ProfileDataRequestContext(ClaimsPrincipal subject, Client client, string caller, IEnumerable<string> requestedClaimTypes)
    {
        // ...
    }

    public ValidatedRequest ValidatedRequest { get; set; } = default!;
    public ClaimsPrincipal Subject { get; set; } = default!;
    public IEnumerable<string> RequestedClaimTypes { get; set; } = Enumerable.Empty<string>();
    public Client Client { get; set; } = default!;
    public string Caller { get; set; } = default!;
    public ResourceValidationResult RequestedResources { get; set; } = default!;
    public List<Claim> IssuedClaims { get; set; } = new List<Claim>();
}
//------------------------------------Ʌ

//--------------------------------V
public class DefaultProfileService : IProfileService
{
    protected readonly ILogger Logger;
    public DefaultProfileService(ILogger<DefaultProfileService> logger) { Logger = logger; }

    public virtual Task GetProfileDataAsync(ProfileDataRequestContext context)
    {        
        context.LogProfileRequest(Logger);
        context.AddRequestedClaims(context.Subject.Claims);
        context.LogIssuedClaims(Logger);

        return Task.CompletedTask;
    }

    public virtual Task IsActiveAsync(IsActiveContext context)
    {        
        context.IsActive = true;
        return Task.CompletedTask;
    }
}
//--------------------------------Ʌ

//---------------------------------V
public class TestUserProfileService : IProfileService
{
    protected readonly ILogger Logger;
        
    protected readonly TestUserStore Users;

    public TestUserProfileService(TestUserStore users, ILogger<TestUserProfileService> logger)
    {
        Users = users;
        Logger = logger;
    }

    public virtual Task GetProfileDataAsync(ProfileDataRequestContext context)  // <-----------------------u1.6
    {
        context.LogProfileRequest(Logger);

        if (context.RequestedClaimTypes.Any())
        {
            var user = Users.FindBySubjectId(context.Subject.GetSubjectId());   // <-----------------------u1.6.1.
            if (user != null)
            {
                context.AddRequestedClaims(user.Claims);
            }
        }

        context.LogIssuedClaims(Logger);

        return Task.CompletedTask;
    }

    public virtual Task IsActiveAsync(IsActiveContext context)
    {
        var user = Users.FindBySubjectId(context.Subject.GetSubjectId());
        context.IsActive = user?.IsActive == true;

        return Task.CompletedTask;
    }
}
//---------------------------------Ʌ

//-----------------------------------------------------V
public static class ProfileDataRequestContextExtensions
{
    public static List<Claim> FilterClaims(this ProfileDataRequestContext context, IEnumerable<Claim> claims)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));
        if (claims == null) throw new ArgumentNullException(nameof(claims));

        return claims.Where(x => context.RequestedClaimTypes.Contains(x.Type)).ToList();
    }

    public static void AddRequestedClaims(this ProfileDataRequestContext context, IEnumerable<Claim> claims)
    {
        if (context.RequestedClaimTypes.Any())
        {
            context.IssuedClaims.AddRange(context.FilterClaims(claims));
        }
    }
    
    // ...
}
//-----------------------------------------------------Ʌ

//-----------------------------V
public class IdentityServerUser
{
    public string SubjectId { get; }
    public string? DisplayName { get; set; }
    public string? IdentityProvider { get; set; }
    public string? Tenant { get; set; }
    public ICollection<string> AuthenticationMethods { get; set; } = new HashSet<string>();
    public DateTime? AuthenticationTime { get; set; }
    public ICollection<Claim> AdditionalClaims { get; set; } = new HashSet<Claim>(new ClaimComparer());

    public IdentityServerUser(string subjectId)
    {
        if (subjectId.IsMissing()) throw new ArgumentException("SubjectId is mandatory", nameof(subjectId));

        SubjectId = subjectId;
    }

    public ClaimsPrincipal CreatePrincipal()   // <---------------------------------i5
    {
        if (SubjectId.IsMissing()) throw new ArgumentException("SubjectId is mandatory", nameof(SubjectId));
        var claims = new List<Claim> { new Claim(JwtClaimTypes.Subject, SubjectId) };

        if (DisplayName.IsPresent())
            claims.Add(new Claim(JwtClaimTypes.Name, DisplayName!));

        if (IdentityProvider.IsPresent())
            claims.Add(new Claim(JwtClaimTypes.IdentityProvider, IdentityProvider!));
            
        if (Tenant.IsPresent())
            claims.Add(new Claim(IdentityServerConstants.ClaimTypes.Tenant, Tenant!));

        if (AuthenticationTime.HasValue)
            claims.Add(new Claim(JwtClaimTypes.AuthenticationTime, new DateTimeOffset(AuthenticationTime.Value).ToUnixTimeSeconds().ToString()));

        if (AuthenticationMethods.Any())
        {
            foreach (var amr in AuthenticationMethods)
            {
                claims.Add(new Claim(JwtClaimTypes.AuthenticationMethod, amr));
            }
        }

        claims.AddRange(AdditionalClaims);

        var id = new ClaimsIdentity(claims.Distinct(new ClaimComparer()), Constants.IdentityServerAuthenticationType, JwtClaimTypes.Name, JwtClaimTypes.Role);
        return new ClaimsPrincipal(id);
    }
}
//-----------------------------Ʌ

//--------------------------V  // namespace Duende.IdentityServer.Endpoints.Results
public class LoginPageResult : AuthorizeInteractionPageResult
{
    public LoginPageResult(ValidatedAuthorizeRequest request, IdentityServerOptions options) 
        : base(request, options.UserInteraction.LoginUrl, options.UserInteraction.LoginReturnUrlParameter)
    {
    }
}
//--------------------------Ʌ

//--------------------------------------------------V
public abstract class AuthorizeInteractionPageResult : EndpointResult<AuthorizeInteractionPageResult>
{
    public AuthorizeInteractionPageResult(ValidatedAuthorizeRequest request, string redirectUrl, string returnUrlParameterName)
    {
        Request = request ?? throw new ArgumentNullException(nameof(request));
        RedirectUrl = redirectUrl ?? throw new ArgumentNullException(nameof(redirectUrl));
        ReturnUrlParameterName = returnUrlParameterName ?? throw new ArgumentNullException(nameof(returnUrlParameterName));
    }

    public ValidatedAuthorizeRequest Request { get; }
    public string RedirectUrl { get; }
    public string ReturnUrlParameterName { get; }
}

class AuthorizeInteractionPageHttpWriter : IHttpResponseWriter<AuthorizeInteractionPageResult>
{
    private readonly IServerUrls _urls;
    private readonly IAuthorizationParametersMessageStore _authorizationParametersMessageStore;

    public AuthorizeInteractionPageHttpWriter(
        IServerUrls urls,
        IAuthorizationParametersMessageStore authorizationParametersMessageStore = null)
    {
        _urls = urls;
        _authorizationParametersMessageStore = authorizationParametersMessageStore;
    }

    public async Task WriteHttpResponse(AuthorizeInteractionPageResult result, HttpContext context)
    {
        var returnUrl = _urls.BasePath.EnsureTrailingSlash() + ProtocolRoutePaths.AuthorizeCallback;

        if (_authorizationParametersMessageStore != null)
        {
            returnUrl = returnUrl.AddQueryString(Constants.AuthorizationParamsStore.MessageStoreIdParameterName, id);
        }
        else
        {
            if (result.Request.PushedAuthorizationReferenceValue != null)
            {
                var requestUri = $"{PushedAuthorizationRequestUri}:{result.Request.PushedAuthorizationReferenceValue}";
                returnUrl = returnUrl
                    .AddQueryString(OidcConstants.AuthorizeRequest.RequestUri, requestUri)
                    .AddQueryString(OidcConstants.AuthorizeRequest.ClientId, result.Request.ClientId);
            } 
            else
            {
                returnUrl = returnUrl.AddQueryString(result.Request.ToOptimizedQueryString());
            }
        }

        var url = result.RedirectUrl;
        if (!url.IsLocalUrl())
        {
            // this converts the relative redirect path to an absolute one if we're 
            // redirecting to a different server
            returnUrl = _urls.Origin + returnUrl;
        }

        url = url.AddQueryString(result.ReturnUrlParameterName, returnUrl);   // url is "/Account/Login",  returnUrl is "/connect/authorize/callbackxxxxxx
        context.Response.Redirect(_urls.GetAbsoluteUrl(url));  // <--------------------------------------q2
    }
}
//--------------------------------------------------Ʌ

//------------------------------------------------------------V
public class AuthorizeResult : EndpointResult<AuthorizeResult>
{
    public AuthorizeResponse Response { get; }

    public AuthorizeResult(AuthorizeResponse response)
    {
        Response = response ?? throw new ArgumentNullException(nameof(response));
    }
}

public class AuthorizeHttpWriter : IHttpResponseWriter<AuthorizeResult>
{
    public AuthorizeHttpWriter(
        IdentityServerOptions options,
        IUserSession userSession,
        IPushedAuthorizationService pushedAuthorizationService,
        IMessageStore<ErrorMessage> errorMessageStore,
        IServerUrls urls,
        IClock clock)
    {
       // ...
    }

    private readonly IdentityServerOptions _options;
    private readonly IUserSession _userSession;
    private readonly IPushedAuthorizationService _pushedAuthorizationService;
    private readonly IMessageStore<ErrorMessage> _errorMessageStore;
    private readonly IServerUrls _urls;
    private readonly IClock _clock;

    public async Task WriteHttpResponse(AuthorizeResult result, HttpContext context)
    {
        await ConsumePushedAuthorizationRequest(result);

        if (result.Response.IsError)
        {
            await ProcessErrorAsync(result.Response, context);
        }
        else
        {
            await ProcessResponseAsync(result.Response, context);  // <----------------------------c3.3
        }
    }

    private async Task ConsumePushedAuthorizationRequest(AuthorizeResult result)
    {
        var referenceValue = result.Response?.Request?.PushedAuthorizationReferenceValue;
        if(referenceValue.IsPresent())
        {
            await _pushedAuthorizationService.ConsumeAsync(referenceValue);
        }
    }

    private async Task ProcessErrorAsync(AuthorizeResponse response, HttpContext context)
    {
        // these are the conditions where we can send a response back directly to the client, otherwise we're only showing the error UI
        var isSafeError =
            response.Error == OidcConstants.AuthorizeErrors.AccessDenied ||
            response.Error == OidcConstants.AuthorizeErrors.AccountSelectionRequired ||
            response.Error == OidcConstants.AuthorizeErrors.LoginRequired ||
            response.Error == OidcConstants.AuthorizeErrors.ConsentRequired ||
            response.Error == OidcConstants.AuthorizeErrors.InteractionRequired ||
            response.Error == OidcConstants.AuthorizeErrors.TemporarilyUnavailable ||
            response.Error == OidcConstants.AuthorizeErrors.UnmetAuthenticationRequirements;
        if (isSafeError)
        {
            // this scenario we can return back to the client
            await ProcessResponseAsync(response, context);
        }
        else
        {
            // we now know we must show error page
            await RedirectToErrorPageAsync(response, context);
        }
    }

    private async Task ProcessResponseAsync(AuthorizeResponse response, HttpContext context)
    {
        if (!response.IsError)
        {
            // success response -- track client authorization for sign-out
            await _userSession.AddClientIdAsync(response.Request.ClientId);  // <----------------------------c3.4
        }

        await RenderAuthorizeResponseAsync(response, context);
    }

    private async Task RenderAuthorizeResponseAsync(AuthorizeResponse response, HttpContext context)
    {
        if (response.Request.ResponseMode == OidcConstants.ResponseModes.Query ||
            response.Request.ResponseMode == OidcConstants.ResponseModes.Fragment)
        {
            context.Response.SetNoCache();
            context.Response.Redirect(BuildRedirectUri(response));
        }
        else if (response.Request.ResponseMode == OidcConstants.ResponseModes.FormPost)
        {
            context.Response.SetNoCache();
            AddSecurityHeaders(context);
            await context.Response.WriteHtmlAsync(GetFormPostHtml(response));  // <----------------------------c3.5 redirect users with https://localhost:7184/signin-oidc POST
        }
        else
        {
            throw new InvalidOperationException("Unsupported response mode");
        }
    }

    private void AddSecurityHeaders(HttpContext context)
    {
        context.Response.AddScriptCspHeaders(_options.Csp, IdentityServerConstants.ContentSecurityPolicyHashes.AuthorizeScript);

        var referrer_policy = "no-referrer";
        if (!context.Response.Headers.ContainsKey("Referrer-Policy"))
        {
            context.Response.Headers.Append("Referrer-Policy", referrer_policy);
        }
    }

    private string BuildRedirectUri(AuthorizeResponse response)
    {
        var uri = response.RedirectUri;
        var query = response.ToNameValueCollection(_options).ToQueryString();

        if (response.Request.ResponseMode == OidcConstants.ResponseModes.Query)
        {
            uri = uri.AddQueryString(query);
        }
        else
        {
            uri = uri.AddHashFragment(query);
        }

        if (response.IsError && !uri.Contains("#"))
        {
            // https://tools.ietf.org/html/draft-bradley-oauth-open-redirector-00
            uri += "#_=_";
        }

        return uri;
    }

    private const string DefaultFormPostHeadTags = "<head><meta http-equiv='X-UA-Compatible' content='IE=edge' /><base target='_self'/></head>";
    private const string DefaultFormPostBodyTags = "<body><form method='post' action='{uri}'>{body}<noscript><button>Click to continue</button></noscript></form><script>window.addEventListener('load', function(){document.forms[0].submit();});</script></body>";

    protected virtual string FormPostHeader => DefaultFormPostHeadTags;
    protected virtual string FormPostBody => DefaultFormPostBodyTags;

    protected virtual string GetFormPostHtml(AuthorizeResponse response)
    {
        var html = $"<html>{FormPostHeader}{FormPostBody}</html>";

        var url = response.Request.RedirectUri;
        url = HtmlEncoder.Default.Encode(url);
        html = html.Replace("{uri}", url);
        html = html.Replace("{body}", response.ToNameValueCollection(_options).ToFormPost());

        return html;
    }

    private async Task RedirectToErrorPageAsync(AuthorizeResponse response, HttpContext context)
    {
        var errorModel = new ErrorMessage
        {
            ActivityId = System.Diagnostics.Activity.Current?.Id,
            RequestId = context.TraceIdentifier,
            Error = response.Error,
            ErrorDescription = response.ErrorDescription,
            UiLocales = response.Request?.UiLocales,
            DisplayMode = response.Request?.DisplayMode,
            ClientId = response.Request?.ClientId
        };

        if (response.RedirectUri != null && response.Request?.ResponseMode != null)
        {
            // if we have a valid redirect uri, then include it to the error page
            errorModel.RedirectUri = BuildRedirectUri(response);
            errorModel.ResponseMode = response.Request.ResponseMode;
        }

        var message = new Message<ErrorMessage>(errorModel, _clock.UtcNow.UtcDateTime);
        var id = await _errorMessageStore.WriteAsync(message);

        var errorUrl = _options.UserInteraction.ErrorUrl;

        var url = errorUrl.AddQueryString(_options.UserInteraction.ErrorIdParameter, id);
        context.Response.Redirect(_urls.GetAbsoluteUrl(url));
    }
}
//------------------------------------------------------------Ʌ

//-------------------------------------V
public abstract class EndpointResult<T> : IEndpointResult where T : class, IEndpointResult
{
    /// <inheritdoc/>
    public async Task ExecuteAsync(HttpContext context)
    {
        var writer = context.RequestServices.GetService<IHttpResponseWriter<T>>();
        if (writer != null)
        {
            T target = this as T;
            if (target == null)
            {
                throw new Exception($"Type parameter {typeof(T)} must be the class derived from 'EndpointResult<T>'.");
            }

            await writer.WriteHttpResponse(target, context);
        }
        else
        {
            throw new Exception($"No IEndpointResultGenerator<T> registered for IEndpointResult type '{typeof(T)}'.");
        }
    }
}
//-------------------------------------Ʌ
```

```C#
//--------------------------------V
public class DefaultConsentService : IConsentService
{
    protected readonly IUserConsentStore UserConsentStore;
    protected readonly IClock Clock;
    protected readonly ILogger<DefaultConsentService> Logger;

    public DefaultConsentService(IClock clock, IUserConsentStore userConsentStore, ILogger<DefaultConsentService> logger)
    {
        // ...
    }

    public virtual async Task<bool> RequiresConsentAsync(ClaimsPrincipal subject, Client client, IEnumerable<ParsedScopeValue> parsedScopes)
    {
        using var activity = Tracing.ServiceActivitySource.StartActivity("DefaultConsentService.RequiresConsent");
        
        if (client == null) throw new ArgumentNullException(nameof(client));
        if (subject == null) throw new ArgumentNullException(nameof(subject));

        if (!client.RequireConsent)
        {
            Logger.LogDebug("Client is configured to not require consent, no consent is required");
            return false;
        }

        if (parsedScopes == null || !parsedScopes.Any())
        {
            Logger.LogDebug("No scopes being requested, no consent is required");
            return false;
        }

        if (!client.AllowRememberConsent)
        {
            Logger.LogDebug("Client is configured to not allow remembering consent, consent is required");
            return true;
        }
            
        if (parsedScopes.Any(x => x.ParsedName != x.RawValue))
        {
            Logger.LogDebug("Scopes contains parameterized values, consent is required");
            return true;
        }

        var scopes = parsedScopes.Select(x => x.RawValue).ToArray();

        // we always require consent for offline access if
        // the client has not disabled RequireConsent 
        if (scopes.Contains(IdentityServerConstants.StandardScopes.OfflineAccess))
        {
            Logger.LogDebug("Scopes contains offline_access, consent is required");
            return true;
        }

        var consent = await UserConsentStore.GetUserConsentAsync(subject.GetSubjectId(), client.ClientId);

        if (consent == null)
        {
            Logger.LogDebug("Found no prior consent from consent store, consent is required");
            return true;
        }

        if (consent.Expiration.HasExpired(Clock.UtcNow.UtcDateTime))
        {
            Logger.LogDebug("Consent found in consent store is expired, consent is required");
            await UserConsentStore.RemoveUserConsentAsync(consent.SubjectId, consent.ClientId);
            return true;
        }

        if (consent.Scopes != null)
        {
            var intersect = scopes.Intersect(consent.Scopes);
            var different = scopes.Count() != intersect.Count();

            if (different)
            {
                Logger.LogDebug("Consent found in consent store is different than current request, consent is required");
            }
            else
            {
                Logger.LogDebug("Consent found in consent store is same as current request, consent is not required");
            }

            return different;
        }

        Logger.LogDebug("Consent found in consent store has no scopes, consent is required");

        return true;
    }

    public virtual async Task UpdateConsentAsync(ClaimsPrincipal subject, Client client, IEnumerable<ParsedScopeValue> parsedScopes)
    {       
        if (client.AllowRememberConsent)
        {
            var subjectId = subject.GetSubjectId();
            var clientId = client.ClientId;

            var scopes = parsedScopes?.Select(x => x.RawValue).ToArray();
            if (scopes != null && scopes.Any())
            {
                Logger.LogDebug("Client allows remembering consent, and consent given. Updating consent store for subject: {subject}", subject.GetSubjectId());

                var consent = new Consent
                {
                    CreationTime = Clock.UtcNow.UtcDateTime,
                    SubjectId = subjectId,
                    ClientId = clientId,
                    Scopes = scopes
                };

                if (client.ConsentLifetime.HasValue)
                {
                    consent.Expiration = consent.CreationTime.AddSeconds(client.ConsentLifetime.Value);
                }

                await UserConsentStore.StoreUserConsentAsync(consent);
            }
            else
            {
                Logger.LogDebug("Client allows remembering consent, and no scopes provided. Removing consent from consent store for subject: {subject}", subject.GetSubjectId());

                await UserConsentStore.RemoveUserConsentAsync(subjectId, clientId);
            }
        }
    }
}
//--------------------------------Ʌ
```

```C#
//------------------------------------------------V
public interface IIdentityServerInteractionService
{
    Task<AuthorizationRequest?> GetAuthorizationContextAsync(string? returnUrl);
    bool IsValidReturnUrl(string? returnUrl);
    Task<ErrorMessage?> GetErrorContextAsync(string? errorId);
    Task<LogoutRequest> GetLogoutContextAsync(string? logoutId);
    Task<string?> CreateLogoutContextAsync();
    Task GrantConsentAsync(AuthorizationRequest request, ConsentResponse consent, string? subject = null);
    Task DenyAuthorizationAsync(AuthorizationRequest request, AuthorizationError error, string? errorDescription = null);
    Task<IEnumerable<Grant>> GetAllUserGrantsAsync();
    Task RevokeUserConsentAsync(string? clientId);
    Task RevokeTokensForCurrentSessionAsync();
}
//------------------------------------------------Ʌ

//----------------------------------------------------V
internal class DefaultIdentityServerInteractionService : IIdentityServerInteractionService
{
    private readonly IClock _clock;
    private readonly IHttpContextAccessor _context;
    private readonly IMessageStore<LogoutMessage> _logoutMessageStore;
    private readonly IMessageStore<ErrorMessage> _errorMessageStore;
    private readonly IConsentMessageStore _consentMessageStore;
    private readonly IPersistedGrantService _grants;
    private readonly IUserSession _userSession;
    private readonly ILogger _logger;
    private readonly ReturnUrlParser _returnUrlParser;

    public DefaultIdentityServerInteractionService(
        IClock clock,
        IHttpContextAccessor context,
        IMessageStore<LogoutMessage> logoutMessageStore,
        IMessageStore<ErrorMessage> errorMessageStore,
        IConsentMessageStore consentMessageStore,
        IPersistedGrantService grants,
        IUserSession userSession,
        ReturnUrlParser returnUrlParser,
        ILogger<DefaultIdentityServerInteractionService> logger)
    {
        // ...
    }

    public async Task<AuthorizationRequest> GetAuthorizationContextAsync(string returnUrl)
    {        
        var result = await _returnUrlParser.ParseAsync(returnUrl);

        if (result != null)
        {
            _logger.LogTrace("AuthorizationRequest being returned");
        }
        else
        {
            _logger.LogTrace("No AuthorizationRequest being returned");
        }

        return result;
    }

    public async Task<LogoutRequest> GetLogoutContextAsync(string logoutId)
    {        
        var msg = await _logoutMessageStore.ReadAsync(logoutId);
        var iframeUrl = await _context.HttpContext.GetIdentityServerSignoutFrameCallbackUrlAsync(msg?.Data);
        return new LogoutRequest(iframeUrl, msg?.Data);
    }

    public async Task<string> CreateLogoutContextAsync()
    {        
        var user = await _userSession.GetUserAsync();
        if (user != null)
        {
            var clientIds = await _userSession.GetClientListAsync();
            if (clientIds.Any())
            {
                var sid = await _userSession.GetSessionIdAsync();
                var msg = new Message<LogoutMessage>(new LogoutMessage
                {
                    SubjectId = user?.GetSubjectId(),
                    SessionId = sid,
                    ClientIds = clientIds
                }, _clock.UtcNow.UtcDateTime);
                var id = await _logoutMessageStore.WriteAsync(msg);
                return id;
            }
        }

        return null;
    }

    public async Task<ErrorMessage> GetErrorContextAsync(string errorId)
    {        
        if (errorId != null)
        { 
            var result = await _errorMessageStore.ReadAsync(errorId);
            var data = result?.Data;
           
            return data;
        }

        return null;
    }

    public async Task GrantConsentAsync(AuthorizationRequest request, ConsentResponse consent, string subject = null) // <-------------conscope
    {       
        if (subject == null)
        {
            var user = await _userSession.GetUserAsync();
            subject = user?.GetSubjectId();
        }

        if (subject == null && consent.Granted)
        {
            throw new ArgumentNullException(nameof(subject), "User is not currently authenticated, and no subject id passed");  // <-------------conscope
        }

        var consentRequest = new ConsentRequest(request, subject);
        await _consentMessageStore.WriteAsync(consentRequest.Id, new Message<ConsentResponse>(consent, _clock.UtcNow.UtcDateTime));
    }

    public Task DenyAuthorizationAsync(AuthorizationRequest request, AuthorizationError error, string errorDescription = null)
    {
        using var activity = Tracing.ServiceActivitySource.StartActivity("DefaultIdentityServerInteractionService.DenyAuthorization");
        
        var response = new ConsentResponse 
        {
            Error = error,
            ErrorDescription = errorDescription
        };
        return GrantConsentAsync(request, response);
    }

    public bool IsValidReturnUrl(string returnUrl)
    {        
        var result = _returnUrlParser.IsValidReturnUrl(returnUrl);

        return result;
    }

    public async Task<IEnumerable<Grant>> GetAllUserGrantsAsync()
    {        
        var user = await _userSession.GetUserAsync();
        if (user != null)
        {
            var subject = user.GetSubjectId();
            return await _grants.GetAllGrantsAsync(subject);
        }

        return Enumerable.Empty<Grant>();
    }

    public async Task RevokeUserConsentAsync(string clientId)
    {    
        var user = await _userSession.GetUserAsync();
        if (user != null)
        {
            var subject = user.GetSubjectId();
            await _grants.RemoveAllGrantsAsync(subject, clientId);
        }
    }

    public async Task RevokeTokensForCurrentSessionAsync()
    {        
        var user = await _userSession.GetUserAsync();
        if (user != null)
        {
            var subject = user.GetSubjectId();
            var sessionId = await _userSession.GetSessionIdAsync();
            await _grants.RemoveAllGrantsAsync(subject, sessionId: sessionId);
        }
    }
}
//----------------------------------------------------Ʌ
```


## Razor Page (created by template)

```C#
//----------------------------V  Account/Login/Index.cshtml
[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    private readonly TestUserStore _users;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IIdentityProviderStore _identityProviderStore;

    public ViewModel View { get; set; } = default!;

    [BindProperty]
    public InputModel Input { get; set; } = default!;

    public Index(
        IIdentityServerInteractionService interaction,
        IAuthenticationSchemeProvider schemeProvider,
        IIdentityProviderStore identityProviderStore,
        IEventService events,
        TestUserStore? users = null)
    {
        // ...
    }

    public async Task<IActionResult> OnGet(string? returnUrl)  // <----------------------------- ReturnUrl is already "/connect/authorize/callback?client_id=xxxx"
    {
        await BuildModelAsync(returnUrl);
            
        if (View.IsExternalLoginOnly)
        {
            // we only have one option for logging in and it's an external provider
            return RedirectToPage("/ExternalLogin/Challenge", new { scheme = View.ExternalLoginScheme, returnUrl });
        }

        return Page();
    }
        
    public async Task<IActionResult> OnPost()  // <---------------------------------i5
    {
        var context = await _interaction.GetAuthorizationContextAsync(Input.ReturnUrl);  // ReturnUrl is "/connect/authorize/callback?client_id=xxxx"

        // the user clicked the "cancel" button
        if (Input.Button != "login")
        {
            if (context != null)
            {             
                await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                if (context.IsNativeClient())
                {
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                    return this.LoadingPage(Input.ReturnUrl);
                }

                return Redirect(Input.ReturnUrl ?? "~/");
            }
            else
            {
                // since we don't have a valid context, then we just go back to the home page
                return Redirect("~/");
            }
        }

        if (ModelState.IsValid)
        {
            // validate username/password against in-memory store
            if (_users.ValidateCredentials(Input.Username, Input.Password))
            {
                var user = _users.FindByUsername(Input.Username);
                await _events.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.SubjectId, user.Username, clientId: context?.Client.ClientId));
                Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

                // only set explicit expiration here if user chooses "remember me". 
                // otherwise we rely upon expiration configured in cookie middleware.
                var props = new AuthenticationProperties();
                if (LoginOptions.AllowRememberLogin && Input.RememberLogin)
                {
                    props.IsPersistent = true;
                    props.ExpiresUtc = DateTimeOffset.UtcNow.Add(LoginOptions.RememberMeLoginDuration);
                };

                // issue authentication cookie with subject ID and username
                var isuser = new IdentityServerUser(user.SubjectId)
                {
                    DisplayName = user.Username
                };

                await HttpContext.SignInAsync(isuser, props);   // <-----------------------------i5

                if (context != null)
                {
                    // This "can't happen", because if the ReturnUrl was null, then the context would be null
                    ArgumentNullException.ThrowIfNull(Input.ReturnUrl, nameof(Input.ReturnUrl));

                    if (context.IsNativeClient())
                    {
                        // The client is native, so this change in how to
                        // return the response is for better UX for the end user.
                        return this.LoadingPage(Input.ReturnUrl);
                    }

                    /* Input.ReturnUrl is
                    /connect/authorize/callback?client_id=imagegalleryclient&redirect_uri=https%3A%2F%2Flocalhost%3A7184%2Fsignin-oidc&response_type=code&scope=openid%20profile&code_challenge=0RPBpTHdTI26Nq-ylPLyeMnOQpVRvM914JxZhVaXFEw&code_challenge_method=S256&response_mode=form_post&nonce=638575024813670890.ZDdjNWYyZTMtZjgyNC00YjU3LWJiNjQtNGEyZDYxNm3N2U4OTdmNmY0NDItZWQ1Zi00YzBlLTk5NmMtM2FiNWUzNGVjZGFj&state=CfDJ8Fr2n1UxboNJlI8uHVA4skr-GSu4CL-ItezMgzmUDV0hJbvWGe-EOcojQhDhDKVg8Yr-8f4bdwQCCvPXVwjof6NzqM0X2Xuna-hOczCNqlW1gvRYZYlgLcLQzvWGJrIevwgI5WSXbhV31ZioZO92BhHh-6F21M2dZ7gp_uFX0HL8vGiaKJmiOmNmFQogOmt4pK2RjhPFRzBQmkuvPe7iMtBwp_qEeVFRTNd6k0r5xzFAinPR-cFefjQqui9YJbolD6mTfNLr-VMHOtrVkl1VF3lzuqg2rm-4f3NtABGjWQMbYw0MqlZE9dglgHBFZU97rW9eBQ50IZXiAT5-q9EA-_-vXNrQPKETDAOpFE5A2x2lPlHvHCm3cmSMN1TUA&x-client-SKU=ID_NET8_0&x-client-ver=7.1.2.0"
                    */
                    return Redirect(Input.ReturnUrl ?? "~/");  // <-----------------------------i5.
                }

                // request for a local page
                if (Url.IsLocalUrl(Input.ReturnUrl))
                {
                    return Redirect(Input.ReturnUrl);
                }
                else if (string.IsNullOrEmpty(Input.ReturnUrl))
                {
                    return Redirect("~/");
                }
                else
                {
                    // user might have clicked on a malicious link - should be logged
                    throw new ArgumentException("invalid return URL");
                }
            }

            const string error = "invalid credentials";
            await _events.RaiseAsync(new UserLoginFailureEvent(Input.Username, error, clientId:context?.Client.ClientId));
            Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, error);
            ModelState.AddModelError(string.Empty, LoginOptions.InvalidCredentialsErrorMessage);
        }

        // something went wrong, show form with error
        await BuildModelAsync(Input.ReturnUrl);
        return Page();
    }

    private async Task BuildModelAsync(string? returnUrl) {}
}
//----------------------------Ʌ

//----------------------------V  Account/Logout/Index.cshtml
[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;

    [BindProperty] 
    public string? LogoutId { get; set; }

    public Index(IIdentityServerInteractionService interaction, IEventService events)
    {
        _interaction = interaction;
        _events = events;
    }

    public async Task<IActionResult> OnGet(string? logoutId) // <-----------------------------------e2.0
    {
        LogoutId = logoutId;

        var showLogoutPrompt = LogoutOptions.ShowLogoutPrompt;

        if (User.Identity?.IsAuthenticated != true)
        {
            // if the user is not authenticated, then just show logged out page
            showLogoutPrompt = false;
        }
        else
        {
            var context = await _interaction.GetLogoutContextAsync(LogoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                showLogoutPrompt = false;
            }
        }
            
        if (showLogoutPrompt == false)
        {
            return await OnPost();  // <-----------------------------------e2.1
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            LogoutId ??= await _interaction.CreateLogoutContextAsync();
                
            // delete local authentication cookie
            await HttpContext.SignOutAsync();  // <--------------------------------------------!impoort e2.2 end the session

            // see if we need to trigger federated logout
            var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;

            // raise the logout event
            await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            Telemetry.Metrics.UserLogout(idp);

            // if it's a local login we can ignore this workflow
            if (idp != null && idp != Duende.IdentityServer.IdentityServerConstants.LocalIdentityProvider)
            {
                // we need to see if the provider supports external logout
                if (await HttpContext.GetSchemeSupportsSignOutAsync(idp))
                {
                    // build a return URL so the upstream provider will redirect back
                    // to us after the user has logged out. this allows us to then
                    // complete our single sign-out processing.
                    var url = Url.Page("/Account/Logout/Loggedout", new { logoutId = LogoutId });

                    // this triggers a redirect to the external provider for sign-out
                    return SignOut(new AuthenticationProperties { RedirectUri = url }, idp);
                }
            }
        }

        return RedirectToPage("/Account/Logout/LoggedOut", new { logoutId = LogoutId });  // <--------------------------------------------e2.3
    }
}

//----------------------------Ʌ

//--------------------------------V /Account/Logout/LoggedOut.cshtml
[SecurityHeaders]
[AllowAnonymous]
public class LoggedOut : PageModel
{
    private readonly IIdentityServerInteractionService _interactionService;

    public LoggedOutViewModel View { get; set; } = default!;

    public LoggedOut(IIdentityServerInteractionService interactionService)
    {
        _interactionService = interactionService;
    }

    public async Task OnGet(string? logoutId)  // <--------------------------------------------e2.4
    {
        // get context information (client name, post logout redirect URI and iframe for federated signout)
        var logout = await _interactionService.GetLogoutContextAsync(logoutId);

        View = new LoggedOutViewModel
        {
            AutomaticRedirectAfterSignOut = LogoutOptions.AutomaticRedirectAfterSignOut,
            PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
            ClientName = String.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
            // SignOutIFrameUrl is https://localhost:5001/connect/endsession/callback?endSessionId=CfDJ8Fr2n1UxboNJxxx
            SignOutIframeUrl = logout?.SignOutIFrameUrl  // <-------------------------------------------------------------------e2.5
            // see why connect/session/callback is needed refer to https://github.com/IdentityServer/IdentityServer3/issues/1581 look like it is just a placeholder
        };
    }
}
/*
@page
@model Marvin.IDP.Pages.Logout.LoggedOut

<div class="logged-out-page">
    <h1>
        Logout
        <small>You are now logged out</small>
    </h1>

    @if (Model.View.PostLogoutRedirectUri != null)
    {
        <div>
            Click <a class="PostLogoutRedirectUri" href="@Model.View.PostLogoutRedirectUri">here</a> to return to the
            <span>@Model.View.ClientName</span> application.
        </div>
    }

    @if (Model.View.SignOutIframeUrl != null)
    {
        <iframe width="0" height="0" class="signout" src="@Model.View.SignOutIframeUrl"></iframe>  // <---------------------------------e.2.6
    }
</div>

@section scripts
{
    @if (Model.View.AutomaticRedirectAfterSignOut)
    {
        <script src="~/js/signout-redirect.js"></script>
    }
}
*/
//--------------------------------Ʌ
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