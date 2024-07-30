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
        builder.Services.AddTransientDecorator<IAuthenticationService, IdentityServerAuthenticationService>();  // <---------this decorate original asp.net's AuthenticationService
        builder.Services.AddTransientDecorator<IAuthenticationHandlerProvider, FederatedSignoutAuthenticationHandlerProvider>();
 
        return builder;
    }

    public static IIdentityServerBuilder AddDefaultEndpoints(this IIdentityServerBuilder builder)
    {
        builder.Services.AddTransient<IEndpointRouter, EndpointRouter>();  // <---------------------------------q1, it is IdentityServer's own Router like UseRouting()
 
        builder.AddEndpoint<AuthorizeCallbackEndpoint>(EndpointNames.Authorize, ProtocolRoutePaths.AuthorizeCallback.EnsureLeadingSlash());   // <---------------------c1.0
        builder.AddEndpoint<AuthorizeEndpoint>(EndpointNames.Authorize, ProtocolRoutePaths.Authorize.EnsureLeadingSlash());   // <-----------------------q1,q2 handles /connect/authorize
        builder.AddEndpoint<CheckSessionEndpoint>(EndpointNames.CheckSession, ProtocolRoutePaths.CheckSession.EnsureLeadingSlash());
        builder.AddEndpoint<DeviceAuthorizationEndpoint>(EndpointNames.DeviceAuthorization, ProtocolRoutePaths.DeviceAuthorization.EnsureLeadingSlash());
        builder.AddEndpoint<DiscoveryKeyEndpoint>(EndpointNames.Discovery, ProtocolRoutePaths.DiscoveryWebKeys.EnsureLeadingSlash());
        builder.AddEndpoint<DiscoveryEndpoint>(EndpointNames.Discovery, ProtocolRoutePaths.DiscoveryConfiguration.EnsureLeadingSlash());  // <---------------q1
        builder.AddEndpoint<EndSessionCallbackEndpoint>(EndpointNames.EndSession, ProtocolRoutePaths.EndSessionCallback.EnsureLeadingSlash());  //<----------so
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

//--------------------------------------V handle /connect/authorize/callback
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
        var user = await UserSession.GetUserAsync();

        var result = await ProcessAuthorizeRequestAsync(parameters, user, true);  // <--------------------------------c1.1.
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
              SessionState = "0A1p6zn4hcizfpMeipQE3EgmOavZyi6IKFOR1D_UY.90CD968BDBEBFFD7839BD0AEA5E74CE"
              State = "CfDJ8Fr2n1UxboNJlI8uHVA4skobbheKboVu0uc-Sw82YrXv0FSfGKT7h0rLyCJv18oA_-76qioJpUgqSBOy64XArrHcs_bRqkg1q7ZSkFLeT..."
           }
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

    public virtual async Task<AuthorizeResponse> CreateResponseAsync(ValidatedAuthorizeRequest request)   // <----------------------c2.2
    {
        using var activity = Tracing.BasicActivitySource.StartActivity("AuthorizeResponseGenerator.CreateResponse");

        if (request.GrantType == GrantType.AuthorizationCode)
        {
            return await CreateCodeFlowResponseAsync(request);   // <----------------------c2.3
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

    protected virtual async Task<AuthorizeResponse> CreateCodeFlowResponseAsync(ValidatedAuthorizeRequest request)  // <----------------------c2.4
    {
        Logger.LogDebug("Creating Authorization Code Flow response.");

        var code = await CreateCodeAsync(request);  // <----------------------c2.5.
        var id = await AuthorizationCodeStore.StoreAuthorizationCodeAsync(code);

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

        var code = new AuthorizationCode   // <----------------------c3.4.
        {
            CreationTime = Clock.UtcNow.UtcDateTime,
            ClientId = request.Client.ClientId,
            Lifetime = request.Client.AuthorizationCodeLifetime,
            Subject = request.Subject,
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
        using var activity = Tracing.BasicActivitySource.StartActivity(IdentityServerConstants.EndpointNames.EndSession + "Endpoint");

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
        using var activity = Tracing.BasicActivitySource.StartActivity(IdentityServerConstants.EndpointNames.EndSession + "Endpoint");

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

    internal static async Task<string> GetCookieAuthenticationSchemeAsync(this HttpContext context)
    {
        var options = context.RequestServices.GetRequiredService<IdentityServerOptions>();
        if (options.Authentication.CookieAuthenticationScheme != null)
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

    internal async Task<IEndpointResult> ProcessAuthorizeRequestAsync(NameValueCollection parameters, ClaimsPrincipal user, ConsentResponse consent)  // <------------------c2.0
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
 
        var response = await _authorizeResponseGenerator.CreateResponseAsync(request);   // <----------------------------------c2.1
 
        await RaiseResponseEventAsync(response);
 
 
        return new AuthorizeResult(response);  // <----------------------------------c3.0
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

```C#
//------------------------------>>
public interface IProfileService
{
    Task GetProfileDataAsync(ProfileDataRequestContext context);
    Task IsActiveAsync(IsActiveContext context);
}
//------------------------------<<

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

    public virtual Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        context.LogProfileRequest(Logger);

        if (context.RequestedClaimTypes.Any())
        {
            var user = Users.FindBySubjectId(context.Subject.GetSubjectId());
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
            await HttpContext.SignOutAsync();  // <--------------------------------------------e2.2 end the session

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