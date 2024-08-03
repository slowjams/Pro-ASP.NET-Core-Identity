## OpenIdConnect

```C#
//------------------V
public class Program 
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddRazorPages();

        builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = "Cookies";
            options.DefaultChallengeScheme = "oidc";
        })
        .AddCookie("Cookies")
        .AddOpenIdConnect("oidc", options =>
        {
            options.Authority = "https://localhost:5001";

            options.ClientId = "web";
            options.ClientSecret = "secret";
            options.ResponseType = "code";

            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");

            options.MapInboundClaims = false;  // jcm
            options.SaveTokens = true;
        });

        var app = builder.Build();

        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapRazorPages().RequireAuthorization();

        app.Run();
    }
}
//------------------Ʌ

//-------------------------------V
public class OpenIdConnectOptions : RemoteAuthenticationOptions
{
    private CookieBuilder _nonceCookieBuilder;
    private readonly JwtSecurityTokenHandler _defaultHandler = new JwtSecurityTokenHandler();
    private readonly JsonWebTokenHandler _defaultTokenHandler = new JsonWebTokenHandler
    {
        MapInboundClaims = JwtSecurityTokenHandler.DefaultMapInboundClaims
    };
    private bool _mapInboundClaims = JwtSecurityTokenHandler.DefaultMapInboundClaims;

    public string? Authority { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }

    public OpenIdConnectConfiguration? Configuration { get; set; }
    public IConfigurationManager<OpenIdConnectConfiguration>? ConfigurationManager { get; set; }

    public bool GetClaimsFromUserInfoEndpoint { get; set; }  // <------------------------------
    public ClaimActionCollection ClaimActions { get; } = new ClaimActionCollection();

    public bool RequireHttpsMetadata { get; set; } = true;
    public string? MetadataAddress { get; set; }

    public new OpenIdConnectEvents Events { get; set; }  // on base.Events

    public TimeSpan? MaxAge { get; set; }

    public OpenIdConnectProtocolValidator ProtocolValidator { get; set; } = new OpenIdConnectProtocolValidator
    {
        RequireStateValidation = false,
        NonceLifetime = TimeSpan.FromMinutes(15.0)
    };

    public PathString SignedOutCallbackPath { get; set; }
    public string SignedOutRedirectUri { get; set; } = "/";
    public bool RefreshOnIssuerKeyNotFound { get; set; } = true;
    public OpenIdConnectRedirectBehavior AuthenticationMethod { get; set; }

    public string? Resource { get; set; }
    public string ResponseMode { get; set; } = "form_post";
    public string ResponseType { get; set; } = "id_token";

    public string? Prompt { get; set; }
    public ICollection<string> Scope { get; } = new HashSet<string>();
    public PathString RemoteSignOutPath { get; set; }
    public string? SignOutScheme { get; set; }
    public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
    public ISecureDataFormat<string> StringDataFormat { get; set; }
    
    public ISecurityTokenValidator SecurityTokenValidator { get; set; }
    public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();

    public bool UseTokenLifetime { get; set; }
    public bool SkipUnrecognizedRequests { get; set; }
    public bool DisableTelemetry { get; set; }

    public CookieBuilder NonceCookie { get; set; }  // on _nonceCookieBuilder
    public bool UsePkce { get; set; } = true;

    public TimeSpan AutomaticRefreshInterval { get; set; } = ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval;
    public TimeSpan RefreshInterval { get; set; } = ConfigurationManager<OpenIdConnectConfiguration>.DefaultRefreshInterval;

    public bool MapInboundClaims   // jcm, on _defaultHandler.MapInboundClaims
    {
        get => _mapInboundClaims;
        set
        {
            _mapInboundClaims = value;
            _defaultHandler.MapInboundClaims = value;
            _defaultTokenHandler.MapInboundClaims = value;
        }
    }

    public OpenIdConnectOptions()  // <--------------------------------------------------
    {
        base.CallbackPath = new PathString("/signin-oidc");
        SignedOutCallbackPath = new PathString("/signout-callback-oidc");
        RemoteSignOutPath = new PathString("/signout-oidc");
        SecurityTokenValidator = _defaultHandler;
        Events = new OpenIdConnectEvents();
        Scope.Add("openid"); Scope.Add("profile");
        ClaimActions.DeleteClaim("nonce"); 
        ClaimActions.DeleteClaim("aud"); // <------------------------------------------------oica
        ClaimActions.DeleteClaim("azp"); 
        ClaimActions.DeleteClaim("acr");
        ClaimActions.DeleteClaim("iss"); 
        ClaimActions.DeleteClaim("iat"); 
        ClaimActions.DeleteClaim("nbf");
        ClaimActions.DeleteClaim("exp");
        ClaimActions.DeleteClaim("at_hash");
        ClaimActions.DeleteClaim("c_hash");
        ClaimActions.DeleteClaim("ipaddr");
        ClaimActions.DeleteClaim("platf");
        ClaimActions.DeleteClaim("ver");
        ClaimActions.MapUniqueJsonKey("sub", "sub"); 
        ClaimActions.MapUniqueJsonKey("name", "name");
        ClaimActions.MapUniqueJsonKey("given_name", "given_name"); 
        ClaimActions.MapUniqueJsonKey("family_name", "family_name");
        ClaimActions.MapUniqueJsonKey("profile", "profile"); 
        ClaimActions.MapUniqueJsonKey("email", "email");  // <----------------------------oica

        _nonceCookieBuilder = new OpenIdConnectNonceCookieBuilder(this)
        {
            Name = OpenIdConnectDefaults.CookieNoncePrefix,
            HttpOnly = true,
            SameSite = SameSiteMode.None,
            SecurePolicy = CookieSecurePolicy.SameAsRequest,
            IsEssential = true
        };
    }

    public override void Validate()
    {     
        base.Validate();
        // ... validate  MaxAge.HasValue && MaxAge.Value < TimeSpan.Zero, IsNullOrEmpty on ClientId, CallbackPath.HasValue, ConfigurationManager     
    }

    private class OpenIdConnectNonceCookieBuilder : RequestPathBaseCookieBuilder
    {
        private readonly OpenIdConnectOptions _options;

        protected override string AdditionalPath => _options.CallbackPath;

        public OpenIdConnectNonceCookieBuilder(OpenIdConnectOptions oidcOptions)
        {
            _options = oidcOptions;
        }

        public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
        {
            CookieOptions cookieOptions = base.Build(context, expiresFrom);
            if (!Expiration.HasValue || !cookieOptions.Expires.HasValue)
            {
                cookieOptions.Expires = expiresFrom.Add(_options.ProtocolValidator.NonceLifetime);
            }

            return cookieOptions;
        }
    }
}
//-------------------------------Ʌ

//--------------------------------------V
public class RemoteAuthenticationOptions : AuthenticationSchemeOptions
{
    private const string CorrelationPrefix = ".AspNetCore.Correlation.";

    private CookieBuilder _correlationCookieBuilder;

    public RemoteAuthenticationOptions()
    {
        _correlationCookieBuilder = new CorrelationCookieBuilder(this)
        {
            Name = CorrelationPrefix,
            HttpOnly = true,
            SameSite = SameSiteMode.None,
            SecurePolicy = CookieSecurePolicy.SameAsRequest,
            IsEssential = true,
        };
    }

    public override void Validate(string scheme)
    {
        base.Validate(scheme);
        if (string.Equals(scheme, SignInScheme, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(Resources.Exception_RemoteSignInSchemeCannotBeSelf);
        }
    }

    public override void Validate()
    {
        base.Validate();
        if (CallbackPath == null || !CallbackPath.HasValue)
        {
            throw new ArgumentException(Resources.FormatException_OptionMustBeProvided(nameof(CallbackPath)), nameof(CallbackPath));
        }
    }

    public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromSeconds(60);

    public HttpMessageHandler? BackchannelHttpHandler { get; set; }

    public HttpClient Backchannel { get; set; } = default!;

    public IDataProtectionProvider? DataProtectionProvider { get; set; }

    public PathString CallbackPath { get; set; }

    public PathString AccessDeniedPath { get; set; }

    public string ReturnUrlParameter { get; set; } = "ReturnUrl";

    public string? SignInScheme { get; set; }

    public TimeSpan RemoteAuthenticationTimeout { get; set; } = TimeSpan.FromMinutes(15);

    public new RemoteAuthenticationEvents Events
    {
        get => (RemoteAuthenticationEvents)base.Events!;
        set => base.Events = value;
    }

    public bool SaveTokens { get; set; }

    public CookieBuilder CorrelationCookie { get; set; }  // on _correlationCookieBuilder
    
    private class CorrelationCookieBuilder : RequestPathBaseCookieBuilder
    {
        private readonly RemoteAuthenticationOptions _options;

        public CorrelationCookieBuilder(RemoteAuthenticationOptions remoteAuthenticationOptions)
        {
            _options = remoteAuthenticationOptions;
        }

        protected override string AdditionalPath => _options.CallbackPath;

        public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
        {
            var cookieOptions = base.Build(context, expiresFrom);

            if (!Expiration.HasValue || !cookieOptions.Expires.HasValue)
            {
                cookieOptions.Expires = expiresFrom.Add(_options.RemoteAuthenticationTimeout);
            }

            return cookieOptions;
        }
    }
}
//--------------------------------------Ʌ
```

```C#
//----------------------------------------->>
public static class OpenIdConnectExtensions
{
    public static AuthenticationBuilder AddOpenIdConnect(this AuthenticationBuilder builder, Action<OpenIdConnectOptions> configureOptions)
    {
        return builder.AddOpenIdConnect("OpenIdConnect", configureOptions);
    }

    public static AuthenticationBuilder AddOpenIdConnect(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<OpenIdConnectOptions> configureOptions)
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, OpenIdConnectPostConfigureOptions>());
        return builder.AddRemoteScheme<OpenIdConnectOptions, OpenIdConnectHandler>(authenticationScheme, displayName, configureOptions);
    }
}
//-----------------------------------------<<
```

```C#
//-------------------------------V OpenIdConnectHandler is like ExternalAuthHandler
public class OpenIdConnectHandler : RemoteAuthenticationHandler<OpenIdConnectOptions>, IAuthenticationSignOutHandler, IAuthenticationHandler
{
    private const string NonceProperty = "N";

    private const string HeaderValueEpocDate = "Thu, 01 Jan 1970 00:00:00 GMT";

    private OpenIdConnectConfiguration _configuration;

    protected HttpClient Backchannel => base.Options.Backchannel;

    protected HtmlEncoder HtmlEncoder { get; }

    protected new OpenIdConnectEvents Events
    {
        get
        {
            return (OpenIdConnectEvents)base.Events;
        }
        set
        {
            base.Events = value;
        }
    }

    public OpenIdConnectHandler(IOptionsMonitor<OpenIdConnectOptions> options, ILoggerFactory logger, HtmlEncoder htmlEncoder, UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
        HtmlEncoder = htmlEncoder;
    }

    protected override Task<object> CreateEventsAsync()
    {
        return Task.FromResult((object)new OpenIdConnectEvents());
    }
  
    public override Task<bool> HandleRequestAsync()   // <----------------------o1.0 handles /signin-oidc request which contains auth code from idp
    {
        if (base.Options.RemoteSignOutPath.HasValue && base.Options.RemoteSignOutPath == base.Request.Path)
        {
            return HandleRemoteSignOutAsync();
        }

        if (base.Options.SignedOutCallbackPath.HasValue && base.Options.SignedOutCallbackPath == base.Request.Path)  // handles https://localhost:7184/signout-callback-oidc
        {                                                                                                            // which calls by IDP via its Client config PostLogoutRedirectUris
            return HandleSignOutCallbackAsync();  // redirect user to https://localhost:7184 which later trigger the HandleChallengeAsync again to show user Accout/Login page
        }

        return base.HandleRequestAsync();  // <----------------------o1.1.
    }

    protected virtual async Task<bool> HandleRemoteSignOutAsync()
    {
        OpenIdConnectMessage message = null;
        if (HttpMethods.IsGet(base.Request.Method))
        {
            message = new OpenIdConnectMessage(base.Request.Query.Select<KeyValuePair<string, StringValues>, KeyValuePair<string, string[]>>((KeyValuePair<string, StringValues> pair) => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
        }
        else if (HttpMethods.IsPost(base.Request.Method) && !string.IsNullOrEmpty(base.Request.ContentType) && base.Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) && base.Request.Body.CanRead)
        {
            message = new OpenIdConnectMessage((await base.Request.ReadFormAsync(base.Context.RequestAborted)).Select<KeyValuePair<string, StringValues>, KeyValuePair<string, string[]>>((KeyValuePair<string, StringValues> pair) => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
        }

        RemoteSignOutContext remoteSignOutContext = new RemoteSignOutContext(base.Context, base.Scheme, base.Options, message);
        await Events.RemoteSignOut(remoteSignOutContext);
        if (remoteSignOutContext.Result != null)
        {
            if (remoteSignOutContext.Result.Handled)
            {
                base.Logger.RemoteSignOutHandledResponse();
                return true;
            }

            if (remoteSignOutContext.Result.Skipped)
            {
                base.Logger.RemoteSignOutSkipped();
                return false;
            }

            if (remoteSignOutContext.Result.Failure != null)
            {
                throw new InvalidOperationException("An error was returned from the RemoteSignOut event.", remoteSignOutContext.Result.Failure);
            }
        }

        if (message == null)
        {
            return false;
        }

        ClaimsPrincipal claimsPrincipal = (await base.Context.AuthenticateAsync(base.Options.SignOutScheme))?.Principal;
        string text = claimsPrincipal?.FindFirst("sid")?.Value;
        if (!string.IsNullOrEmpty(text))
        {
            if (string.IsNullOrEmpty(message.Sid))
            {
                base.Logger.RemoteSignOutSessionIdMissing();
                return true;
            }

            if (!string.Equals(text, message.Sid, StringComparison.Ordinal))
            {
                base.Logger.RemoteSignOutSessionIdInvalid();
                return true;
            }
        }

        string text = claimsPrincipal?.FindFirst("iss")?.Value;
        if (!string.IsNullOrEmpty(text))
        {
            if (string.IsNullOrEmpty(message.Iss))
            {
                base.Logger.RemoteSignOutIssuerMissing();
                return true;
            }

            if (!string.Equals(text, message.Iss, StringComparison.Ordinal))
            {
                base.Logger.RemoteSignOutIssuerInvalid();
                return true;
            }
        }

        base.Logger.RemoteSignOut();
        await base.Context.SignOutAsync(base.Options.SignOutScheme);
        return true;
    }

    public virtual async Task SignOutAsync(AuthenticationProperties? properties)  // <------------------------------sot0
    {
        string text = ResolveTarget(base.Options.ForwardSignOut);
        if (text != null)
        {
            await base.Context.SignOutAsync(text, properties);
            return;
        }

        if (properties == null)
        {
            properties = new AuthenticationProperties();
        }

        base.Logger.EnteringOpenIdAuthenticationHandlerHandleSignOutAsync(GetType().FullName);
        if (_configuration == null && base.Options.ConfigurationManager != null)
        {
            _configuration = await base.Options.ConfigurationManager.GetConfigurationAsync(base.Context.RequestAborted);
        }

        OpenIdConnectMessage message = new OpenIdConnectMessage
        {
            EnableTelemetryParameters = !base.Options.DisableTelemetry,
            IssuerAddress = (_configuration?.EndSessionEndpoint ?? string.Empty),
            PostLogoutRedirectUri = BuildRedirectUriIfRelative(base.Options.SignedOutCallbackPath)
        };
        if (string.IsNullOrEmpty(properties.RedirectUri))
        {
            properties.RedirectUri = BuildRedirectUriIfRelative(base.Options.SignedOutRedirectUri);
            if (string.IsNullOrWhiteSpace(properties.RedirectUri))
            {
                properties.RedirectUri = base.OriginalPathBase + base.OriginalPath + base.Request.QueryString;
            }
        }

        base.Logger.PostSignOutRedirect(properties.RedirectUri);
        OpenIdConnectMessage openIdConnectMessage = message;
        openIdConnectMessage.IdTokenHint = await base.Context.GetTokenAsync(base.Options.SignOutScheme, "id_token");
        RedirectContext redirectContext = new RedirectContext(base.Context, base.Scheme, base.Options, properties)
        {
            ProtocolMessage = message
        };
        await Events.RedirectToIdentityProviderForSignOut(redirectContext);
        if (redirectContext.Handled)
        {
            base.Logger.RedirectToIdentityProviderForSignOutHandledResponse();
            return;
        }

        message = redirectContext.ProtocolMessage;
        if (!string.IsNullOrEmpty(message.State))
        {
            properties.Items[OpenIdConnectDefaults.UserstatePropertiesKey] = message.State;
        }

        message.State = base.Options.StateDataFormat.Protect(properties);
        if (string.IsNullOrEmpty(message.IssuerAddress))
        {
            throw new InvalidOperationException("Cannot redirect to the end session endpoint, the configuration may be missing or invalid.");
        }

        if (base.Options.AuthenticationMethod == OpenIdConnectRedirectBehavior.RedirectGet)
        {
            string redirectUri = message.CreateLogoutRequestUrl();
            // redirectUri is below
            // https://localhost:5001/connect/endsession?post_logout_redirect_uri=https%3A%2F%2Flocalhost%3A7184%2Fsignout-callback-oidc&id_token_hint=eyJhbGciOiJSUzxxxx
            if (!Uri.IsWellFormedUriString(text2, UriKind.Absolute))
            {
                base.Logger.InvalidLogoutQueryStringRedirectUrl(redirectUri);
            }

            base.Response.Redirect(redirectUri);  // <---------------------------------------sot1.
        }
        else
        {
            if (base.Options.AuthenticationMethod != OpenIdConnectRedirectBehavior.FormPost)
            {
                throw new NotImplementedException($"An unsupported authentication method has been configured: {base.Options.AuthenticationMethod}");
            }

            string s = message.BuildFormPost();
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            base.Response.ContentLength = bytes.Length;
            base.Response.ContentType = "text/html;charset=UTF-8";
            base.Response.Headers.CacheControl = "no-cache, no-store";
            base.Response.Headers.Pragma = "no-cache";
            base.Response.Headers.Expires = "Thu, 01 Jan 1970 00:00:00 GMT";
            await base.Response.Body.WriteAsync(bytes);
        }

        base.Logger.AuthenticationSchemeSignedOut(base.Scheme.Name);
    }

    protected virtual async Task<bool> HandleSignOutCallbackAsync()
    {
        OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage(base.Request.Query.Select<KeyValuePair<string, StringValues>, KeyValuePair<string, string[]>>((KeyValuePair<string, StringValues> pair) => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
        AuthenticationProperties properties = null;
        if (!string.IsNullOrEmpty(openIdConnectMessage.State))
        {
            properties = base.Options.StateDataFormat.Unprotect(openIdConnectMessage.State);
        }

        RemoteSignOutContext signOut = new RemoteSignOutContext(base.Context, base.Scheme, base.Options, openIdConnectMessage)
        {
            Properties = properties
        };
        await Events.SignedOutCallbackRedirect(signOut);
        if (signOut.Result != null)
        {
            if (signOut.Result.Handled)
            {
                base.Logger.SignOutCallbackRedirectHandledResponse();
                return true;
            }

            if (signOut.Result.Skipped)
            {
                base.Logger.SignOutCallbackRedirectSkipped();
                return false;
            }

            if (signOut.Result.Failure != null)
            {
                throw new InvalidOperationException("An error was returned from the SignedOutCallbackRedirect event.", signOut.Result.Failure);
            }
        }

        properties = signOut.Properties;
        if (!string.IsNullOrEmpty(properties?.RedirectUri))
        {
            base.Response.Redirect(properties.RedirectUri);  // <----------------RedirectUri is https://localhost:7184
        }

        return true;
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        await HandleChallengeAsyncInternal(properties);
        StringValues stringValues = base.Context.Response.Headers.Location;
        if (stringValues == StringValues.Empty)
        {
            stringValues = "(not set)";
        }

        StringValues stringValues = base.Context.Response.Headers.SetCookie;
        if (stringValues == StringValues.Empty)
        {
            stringValues = "(not set)";
        }

        base.Logger.HandleChallenge(stringValues, stringValues);
    }

    private async Task HandleChallengeAsyncInternal(AuthenticationProperties properties)   // <-------------------------------a0
    {
        base.Logger.EnteringOpenIdAuthenticationHandlerHandleUnauthorizedAsync(GetType().FullName);
        if (string.IsNullOrEmpty(properties.RedirectUri))
        {
            properties.RedirectUri = base.OriginalPathBase + base.OriginalPath + base.Request.QueryString;
        }

        base.Logger.PostAuthenticationLocalRedirect(properties.RedirectUri);
        if (_configuration == null && base.Options.ConfigurationManager != null)
        {
            _configuration = await base.Options.ConfigurationManager.GetConfigurationAsync(base.Context.RequestAborted);   // <-------------------------------a1
        }

        OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage
        {
            ClientId = base.Options.ClientId,
            EnableTelemetryParameters = !base.Options.DisableTelemetry,
            IssuerAddress = (_configuration?.AuthorizationEndpoint ?? string.Empty),
            RedirectUri = BuildRedirectUri(base.Options.CallbackPath),
            Resource = base.Options.Resource,
            ResponseType = base.Options.ResponseType,
            Prompt = (properties.GetParameter<string>("prompt") ?? base.Options.Prompt),
            Scope = string.Join(" ", properties.GetParameter<ICollection<string>>("scope") ?? base.Options.Scope)
        };
        if (base.Options.UsePkce && base.Options.ResponseType == "code")
        {
            byte[] array = new byte[32];
            RandomNumberGenerator.Fill(array);
            string text = Base64UrlTextEncoder.Encode(array);
            properties.Items.Add(OAuthConstants.CodeVerifierKey, text);
            string value = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
            openIdConnectMessage.Parameters.Add(OAuthConstants.CodeChallengeKey, value);
            openIdConnectMessage.Parameters.Add(OAuthConstants.CodeChallengeMethodKey, OAuthConstants.CodeChallengeMethodS+256);
        }

        TimeSpan? timeSpan = properties.GetParameter<TimeSpan?>("max_age") ?? base.Options.MaxAge;
        if (timeSpan.HasValue)
        {
            openIdConnectMessage.MaxAge = Convert.ToInt64(Math.Floor(timeSpan.Value.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        }

        if (!string.Equals(base.Options.ResponseType, "code", StringComparison.Ordinal) || !string.Equals(base.Options.ResponseMode, "query", StringComparison.Ordinal))
        {
            openIdConnectMessage.ResponseMode = base.Options.ResponseMode;
        }

        if (base.Options.ProtocolValidator.RequireNonce)
        {
            openIdConnectMessage.Nonce = base.Options.ProtocolValidator.GenerateNonce();
            WriteNonceCookie(openIdConnectMessage.Nonce);
        }

        GenerateCorrelationId(properties);
        RedirectContext redirectContext = new RedirectContext(base.Context, base.Scheme, base.Options, properties)
        {
            ProtocolMessage = openIdConnectMessage
        };
        await Events.RedirectToIdentityProvider(redirectContext);
        if (redirectContext.Handled)
        {
            base.Logger.RedirectToIdentityProviderHandledResponse();
            return;
        }

        openIdConnectMessage = redirectContext.ProtocolMessage;
        if (!string.IsNullOrEmpty(openIdConnectMessage.State))
        {
            properties.Items[OpenIdConnectDefaults.UserstatePropertiesKey] = openIdConnectMessage.State;
        }

        properties.Items.Add(OpenIdConnectDefaults.RedirectUriForCodePropertiesKey, openIdConnectMessage.RedirectUri);
        openIdConnectMessage.State = base.Options.StateDataFormat.Protect(properties);
        if (string.IsNullOrEmpty(openIdConnectMessage.IssuerAddress))
        {
            throw new InvalidOperationException("Cannot redirect to the authorization endpoint, the configuration may be missing or invalid.");
        }

        if (base.Options.AuthenticationMethod == OpenIdConnectRedirectBehavior.RedirectGet)
        {
            string redirectUri = openIdConnectMessage.CreateAuthenticationRequestUrl();   // <------------------------------------------a2
            /* redirectUri is e.g

              https://localhost:5001/connect/authorize?client_id=imagegalleryclient&redirect_uri=https%3A%2F%2Flocalhost%3A7184%2Fsignin-oidc&response_type=code&scope=openid%20profile&code_challenge=gxNP3gQQtCv6ybY-1SzRhuJ2lAJcw4xfY63-N0VMp_M&code_challenge_method=S.256&response_mode=form_post&nonce=638574178447973386.ZjQ1NjXXXXXXX&state=XXXXoA&x-client-SKU=ID_NET8_0&x-client-ver=7.1.2.0

            */
            
            if (!Uri.IsWellFormedUriString(text2, UriKind.Absolute))
            {
                base.Logger.InvalidAuthenticationRequestUrl(redirectUri);
            }

            base.Response.Redirect(redirectUri);   // <------------------------------------------a2
            return;
        }

        if (base.Options.AuthenticationMethod == OpenIdConnectRedirectBehavior.FormPost)
        {
            string s = openIdConnectMessage.BuildFormPost();
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            base.Response.ContentLength = bytes.Length;
            base.Response.ContentType = "text/html;charset=UTF-8";
            base.Response.Headers.CacheControl = "no-cache, no-store";
            base.Response.Headers.Pragma = "no-cache";
            base.Response.Headers.Expires = "Thu, 01 Jan 1970 00:00:00 GMT";
            await base.Response.Body.WriteAsync(bytes);
            return;
        }

        throw new NotImplementedException($"An unsupported authentication method has been configured: {base.Options.AuthenticationMethod}");
    }

    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()   // <----------------------------------------o3.0
    {
        base.Logger.EnteringOpenIdAuthenticationHandlerHandleRemoteAuthenticateAsync(GetType().FullName);
        OpenIdConnectMessage authorizationResponse = null;
        if (HttpMethods.IsGet(base.Request.Method))
        {
            authorizationResponse = new OpenIdConnectMessage(base.Request.Query.Select<KeyValuePair<string, StringValues>, KeyValuePair<string, string[]>>((KeyValuePair<string, StringValues> pair) => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
            if (!string.IsNullOrEmpty(authorizationResponse.IdToken) || !string.IsNullOrEmpty(authorizationResponse.AccessToken))
            {
                if (base.Options.SkipUnrecognizedRequests)
                {
                    return HandleRequestResult.SkipHandler();
                }

                return HandleRequestResult.Fail("An OpenID Connect response cannot contain an identity token or an access token when using response_mode=query");
            }
        }
        else if (HttpMethods.IsPost(base.Request.Method) && !string.IsNullOrEmpty(base.Request.ContentType) && base.Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) && base.Request.Body.CanRead)
        {
            authorizationResponse = new OpenIdConnectMessage((await base.Request.ReadFormAsync(base.Context.RequestAborted)).Select<KeyValuePair<string, StringValues>, KeyValuePair<string, string[]>>((KeyValuePair<string, StringValues> pair) => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
        }

        if (authorizationResponse == null)
        {
            if (base.Options.SkipUnrecognizedRequests)
            {
                return HandleRequestResult.SkipHandler();
            }

            return HandleRequestResult.Fail("No message.");
        }

        AuthenticationProperties properties = null;
        try
        {
            properties = ReadPropertiesAndClearState(authorizationResponse);
            MessageReceivedContext messageReceivedContext = await RunMessageReceivedEventAsync(authorizationResponse, properties);
            if (messageReceivedContext.Result != null)
            {
                return messageReceivedContext.Result;
            }

            authorizationResponse = messageReceivedContext.ProtocolMessage;
            properties = messageReceivedContext.Properties;
            if (properties == null || properties.Items.Count == 0)
            {
                if (string.IsNullOrEmpty(authorizationResponse.State))
                {
                    base.Logger.NullOrEmptyAuthorizationResponseState();
                    if (base.Options.SkipUnrecognizedRequests)
                    {
                        return HandleRequestResult.SkipHandler();
                    }

                    return HandleRequestResult.Fail(Resources.MessageStateIsNullOrEmpty);
                }

                properties = ReadPropertiesAndClearState(authorizationResponse);
            }

            if (properties == null)
            {
                base.Logger.UnableToReadAuthorizationResponseState();
                if (base.Options.SkipUnrecognizedRequests)
                {
                    return HandleRequestResult.SkipHandler();
                }

                return HandleRequestResult.Fail(Resources.MessageStateIsInvalid);
            }

            if (!ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("Correlation failed.", properties);
            }

            if (!string.IsNullOrEmpty(authorizationResponse.Error))
            {
                if (string.Equals(authorizationResponse.Error, "access_denied", StringComparison.Ordinal))
                {
                    HandleRequestResult handleRequestResult = await HandleAccessDeniedErrorAsync(properties);
                    if (!handleRequestResult.None)
                    {
                        return handleRequestResult;
                    }
                }

                return HandleRequestResult.Fail(CreateOpenIdConnectProtocolException(authorizationResponse, null), properties);
            }

            if (_configuration == null && base.Options.ConfigurationManager != null)
            {
                base.Logger.UpdatingConfiguration();
                _configuration = await base.Options.ConfigurationManager.GetConfigurationAsync(base.Context.RequestAborted);
            }

            PopulateSessionProperties(authorizationResponse, properties);
            ClaimsPrincipal user = null;
            JwtSecurityToken jwt = null;
            string nonce2 = null;
            TokenValidationParameters validationParameters = base.Options.TokenValidationParameters.Clone();
            if (!string.IsNullOrEmpty(authorizationResponse.IdToken))
            {
                base.Logger.ReceivedIdToken();
                user = ValidateToken(authorizationResponse.IdToken, properties, validationParameters, out jwt);
                nonce2 = jwt.Payload.Nonce;
                if (!string.IsNullOrEmpty(nonce2))
                {
                    nonce2 = ReadNonceCookie(nonce2);
                }

                TokenValidatedContext tokenValidatedContext = await RunTokenValidatedEventAsync(authorizationResponse, null, user, properties, jwt, nonce2);
                if (tokenValidatedContext.Result != null)
                {
                    return tokenValidatedContext.Result;
                }

                authorizationResponse = tokenValidatedContext.ProtocolMessage;
                user = tokenValidatedContext.Principal;
                properties = tokenValidatedContext.Properties;
                jwt = tokenValidatedContext.SecurityToken;
                nonce2 = tokenValidatedContext.Nonce;
            }

            base.Options.ProtocolValidator.ValidateAuthenticationResponse(new OpenIdConnectProtocolValidationContext
            {
                ClientId = base.Options.ClientId,
                ProtocolMessage = authorizationResponse,
                ValidatedIdToken = jwt,
                Nonce = nonce2
            });
            OpenIdConnectMessage openIdConnectMessage = null;
             // Authorization Code or Hybrid flow
            if (!string.IsNullOrEmpty(authorizationResponse.Code))
            {
                var authorizationCodeReceivedContext = 
                    await RunAuthorizationCodeReceivedEventAsync(authorizationResponse, user, properties!, jwt);  // <----------------------o3.1

                if (authorizationCodeReceivedContext.Result != null)
                {
                    return authorizationCodeReceivedContext.Result;
                }
                authorizationResponse = authorizationCodeReceivedContext.ProtocolMessage;
                user = authorizationCodeReceivedContext.Principal!;
                properties = authorizationCodeReceivedContext.Properties!;
                var tokenEndpointRequest = authorizationCodeReceivedContext.TokenEndpointRequest;
                // If the developer redeemed the code themselves...
                tokenEndpointResponse = authorizationCodeReceivedContext.TokenEndpointResponse;
                jwt = authorizationCodeReceivedContext.JwtSecurityToken!;

                if (!authorizationCodeReceivedContext.HandledCodeRedemption)
                {
                    tokenEndpointResponse = await RedeemAuthorizationCodeAsync(tokenEndpointRequest!);  // <-------------------------o3.2
                }

                var tokenResponseReceivedContext = await RunTokenResponseReceivedEventAsync(authorizationResponse, tokenEndpointResponse!, user, properties);
                if (tokenResponseReceivedContext.Result != null)
                {
                    return tokenResponseReceivedContext.Result;
                }

                authorizationResponse = tokenResponseReceivedContext.ProtocolMessage;
                tokenEndpointResponse = tokenResponseReceivedContext.TokenEndpointResponse;
                user = tokenResponseReceivedContext.Principal;   // <----------------------user is null here
                properties = tokenResponseReceivedContext.Properties!;

                // no need to validate signature when token is received using "code flow" as per spec
                // [http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation].
                validationParameters.RequireSignedTokens = false;

                // At least a cursory validation is required on the new IdToken, even if we've already validated the one from the authorization response.
                // And we'll want to validate the new JWT in ValidateTokenResponse.
                ClaimsPrincipal tokenEndpointUser;
                JwtSecurityToken tokenEndpointJwt;

                if (!Options.UseSecurityTokenValidator)
                {
                    var tokenValidationResult = 
                        await ValidateTokenUsingHandlerAsync(tokenEndpointResponse.IdToken, properties, validationParameters);   // <---------!!!!!!use IdToken to create ClaimIdentity
                    
                    tokenEndpointUser = new ClaimsPrincipal(tokenValidationResult.ClaimsIdentity);   // <----------------------------------------o4.0
                    
                    tokenEndpointJwt = JwtSecurityTokenConverter.Convert(tokenValidationResult.SecurityToken as JsonWebToken);
                }
                else
                {
                    tokenEndpointUser = ValidateToken(tokenEndpointResponse.IdToken, properties, validationParameters, out tokenEndpointJwt);
                }

                // Avoid reading & deleting the nonce cookie, running the event, etc, if it was already done as part of the authorization response validation.
                if (user == null)
                {
                    nonce = tokenEndpointJwt.Payload.Nonce;
                    if (!string.IsNullOrEmpty(nonce))
                    {
                        nonce = ReadNonceCookie(nonce);
                    }

                    var tokenValidatedContext = await RunTokenValidatedEventAsync(authorizationResponse, tokenEndpointResponse, tokenEndpointUser, properties, tokenEndpointJwt, nonce);
                    if (tokenValidatedContext.Result != null)
                    {
                        return tokenValidatedContext.Result;
                    }
                    authorizationResponse = tokenValidatedContext.ProtocolMessage;
                    tokenEndpointResponse = tokenValidatedContext.TokenEndpointResponse;
                    user = tokenValidatedContext.Principal!;   // <-----------------o4.1 user is set now, but lose "user = Emma" claim, since idToken normally doesn't contains user name
                    properties = tokenValidatedContext.Properties;
                    jwt = tokenValidatedContext.SecurityToken;
                    nonce = tokenValidatedContext.Nonce;
                }
                else
                {
                    if (!string.Equals(jwt.Subject, tokenEndpointJwt.Subject, StringComparison.Ordinal))
                    {
                        throw new SecurityTokenException("The sub claim does not match in the id_token's from the authorization and token endpoints.");
                    }

                    jwt = tokenEndpointJwt;
                }

                // Validate the token response if it wasn't provided manually
                if (!authorizationCodeReceivedContext.HandledCodeRedemption)
                {
                    Options.ProtocolValidator.ValidateTokenResponse(new OpenIdConnectProtocolValidationContext()
                    {
                        ClientId = Options.ClientId,
                        ProtocolMessage = tokenEndpointResponse,
                        ValidatedIdToken = jwt,
                        Nonce = nonce
                    });
                }
            }

            if (Options.SaveTokens)
            {
                SaveTokens(properties!, tokenEndpointResponse ?? authorizationResponse);  // <----------------------------------------o4.2
            }

            if (Options.GetClaimsFromUserInfoEndpoint)  // when `options.GetClaimsFromUserInfoEndpoint = true`
            {
                return await GetUserInformationAsync(tokenEndpointResponse ?? authorizationResponse, jwt!, user!, properties!);  // <----------------------o4.4
                // note that we return here immediately compared to o4.8, the AuthenticationTicket in o4.8 is created from id token
                // while here we get full user claims into AuthenticationTicket then into cookie
            }
            else
            {
                using (var payload = JsonDocument.Parse("{}"))
                {
                    var identity = (ClaimsIdentity)user!.Identity!;
                    foreach (var action in Options.ClaimActions)  // <-----------------------mjk
                    {
                        action.Run(payload.RootElement, identity, ClaimsIssuer);
                    }
                }
            }

            return HandleRequestResult.Success(new AuthenticationTicket(user, properties, Scheme.Name));   // <----------------------------------------o4.8. user is authenticated now
        }
        catch (Exception exception)
        {
            base.Logger.ExceptionProcessingMessage(exception);
            if (base.Options.RefreshOnIssuerKeyNotFound && exception is SecurityTokenSignatureKeyNotFoundException && base.Options.ConfigurationManager != null)
            {
                base.Logger.ConfigurationManagerRequestRefreshCalled();
                base.Options.ConfigurationManager.RequestRefresh();
            }

            AuthenticationFailedContext authenticationFailedContext = await RunAuthenticationFailedEventAsync(authorizationResponse, exception);
            if (authenticationFailedContext.Result != null)
            {
                return authenticationFailedContext.Result;
            }

            return HandleRequestResult.Fail(exception, properties);
        }
    }

    private AuthenticationProperties ReadPropertiesAndClearState(OpenIdConnectMessage message)
    {
        AuthenticationProperties authenticationProperties = null;
        if (!string.IsNullOrEmpty(message.State))
        {
            authenticationProperties = base.Options.StateDataFormat.Unprotect(message.State);
            if (authenticationProperties != null)
            {
                authenticationProperties.Items.TryGetValue(OpenIdConnectDefaults.UserstatePropertiesKey, out string value);
                message.State = value;
            }
        }

        return authenticationProperties;
    }

    private void PopulateSessionProperties(OpenIdConnectMessage message, AuthenticationProperties properties)
    {
        if (!string.IsNullOrEmpty(message.SessionState))
        {
            properties.Items[".sessionState"] = message.SessionState;
        }

        if (!string.IsNullOrEmpty(_configuration?.CheckSessionIframe))
        {
            properties.Items[".checkSessionIFrame"] = _configuration.CheckSessionIframe;
        }
    }

    protected virtual async Task<OpenIdConnectMessage> RedeemAuthorizationCodeAsync(OpenIdConnectMessage tokenEndpointRequest)   // <------------------------o3.2.0
    {
        base.Logger.RedeemingCodeForTokens();
                                                                     // TokenEndpoint is https://localhost:5001/connect/token
        HttpRequestMessage httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, tokenEndpointRequest.TokenEndpoint ?? _configuration?.TokenEndpoint);
        httpRequestMessage.Content = new FormUrlEncodedContent(tokenEndpointRequest.Parameters);
        httpRequestMessage.Version = Backchannel.DefaultRequestVersion;

        HttpResponseMessage responseMessage = await Backchannel.SendAsync(httpRequestMessage, base.Context.RequestAborted);  // <------------------------o3.2.1.
                                                                                                                             // exchange auth code for access code
        string text = responseMessage.Content.Headers.ContentType?.MediaType;
        if (string.IsNullOrEmpty(text))
        {
            base.Logger.LogDebug($"Unexpected token response format. Status Code: {responseMessage.StatusCode}. Content-Type header is missing.");
        }
        else if (!string.Equals(text, "application/json", StringComparison.OrdinalIgnoreCase))
        {
            base.Logger.LogDebug($"Unexpected token response format. Status Code: {responseMessage.StatusCode}. Content-Type {responseMessage.Content.Headers.ContentType}.");
        }

        OpenIdConnectMessage openIdConnectMessage;
        try
        {
            openIdConnectMessage = new OpenIdConnectMessage(await responseMessage.Content.ReadAsStringAsync(base.Context.RequestAborted));
        }
        catch (Exception innerException)
        {
            throw new OpenIdConnectProtocolException($"Failed to parse token response body as JSON. Status Code: {responseMessage.StatusCode}. Content-Type: {responseMessage.Content.Headers.ContentType}", innerException);
        }

        if (!responseMessage.IsSuccessStatusCode)
        {
            throw CreateOpenIdConnectProtocolException(openIdConnectMessage, responseMessage);
        }

        return openIdConnectMessage;

        /* openIdConnectMessage contains both access token and id token

        access token:
        {
           "iss": "https://localhost:5001",
           "nbf": 1721992836,
           "iat": 1721992836,
           "exp": 1721996436,
           "aud": "https://localhost:5001/resources",
           "scope": [
               "openid",
               "profile"
           ],
           "amr": [
               "pwd"
           ],
           "client_id": "imagegalleryclient",
           "sub": "b7539694-97e7-4dfe-84da-b4256e1ff5c7",  <---------------Emma's SubjectId
           "auth_time": 1721992825,
           "idp": "local",
           "sid": "9FDA47CA6FF69E743E1298E10D3D6424",
           "jti": "7329E425E9973BEAE2B88DCB72A27FEC"
         }

        id token:      
        {
           "iss": "https://localhost:5001",
           "nbf": 1721992836,
           "iat": 1721992836,
           "exp": 1721993136,
           "aud": "imagegalleryclient",
           "amr": [
               "pwd"
           ],
           "nonce": "638575896217007596.ZmVlZWNiNzEtZDJkNSN2VlLWJmMmItZmM3YjIzM2VkNDExYjVmM2RiYTMtNzYxMi00OTc2LWEzZDEtZTBmNmZjZjNlYjg3",
           "at_hash": "OW66WFmR8RXkZMOx-jGDSg",
           "sid": "9FDA47CA6FF69E743E1298E10D3D6424",
           "sub": "b7539694-97e7-4dfe-84da-b4256e1ff5c7",   <---------------Emma's SubjectId
           "auth_time": 1721992825,
           "idp": "local"
        }

        */
    }

    protected virtual async Task<HandleRequestResult> GetUserInformationAsync(   // <----------------------------------------o4.4
        OpenIdConnectMessage message, 
        JwtSecurityToken jwt, 
        ClaimsPrincipal principal,
         AuthenticationProperties properties)
    {
        string text = _configuration?.UserInfoEndpoint;   // <-------------------o4.5 https://localhost:5001/connect/userinfo
        if (string.IsNullOrEmpty(text))
        {
            base.Logger.UserInfoEndpointNotSet();
            return HandleRequestResult.Success(new AuthenticationTicket(principal, properties, base.Scheme.Name));
        }

        if (string.IsNullOrEmpty(message.AccessToken))
        {
            base.Logger.AccessTokenNotAvailable();
            return HandleRequestResult.Success(new AuthenticationTicket(principal, properties, base.Scheme.Name));
        }

        base.Logger.RetrievingClaims();
        HttpRequestMessage httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, text);
        httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", message.AccessToken);
        httpRequestMessage.Version = Backchannel.DefaultRequestVersion;

        HttpResponseMessage responseMessage =  
            await Backchannel.SendAsync(httpRequestMessage, base.Context.RequestAborted);  // <-------------------o4.6 call IDP on https://localhost:5001/connect/userinfo
                                                                                           // note that we need AccessToken for the UserInfoEndpoint in IDP
        responseMessage.EnsureSuccessStatusCode();

        string userInfoResponse = await responseMessage.Content.ReadAsStringAsync(base.Context.RequestAborted);
        MediaTypeHeaderValue contentType = responseMessage.Content.Headers.ContentType;
        JsonDocument jsonDocument;
        if ((contentType?.MediaType?.Equals("application/json", StringComparison.OrdinalIgnoreCase)).GetValueOrDefault())
        {
            jsonDocument = JsonDocument.Parse(userInfoResponse);
        }
        else
        {
            if (!(contentType?.MediaType?.Equals("application/jwt", StringComparison.OrdinalIgnoreCase)).GetValueOrDefault())
            {
                return HandleRequestResult.Fail("Unknown response type: " + contentType?.MediaType, properties);
            }

            jsonDocument = JsonDocument.Parse(new JwtSecurityToken(userInfoResponse).Payload.SerializeToJson());
        }

        using (jsonDocument)
        {
            UserInformationReceivedContext userInformationReceivedContext = await RunUserInformationReceivedEventAsync(principal, properties, message, jsonDocument);
            if (userInformationReceivedContext.Result != null)
            {
                return userInformationReceivedContext.Result;
            }

            principal = userInformationReceivedContext.Principal;
            properties = userInformationReceivedContext.Properties;
            using JsonDocument jsonDocument2 = userInformationReceivedContext.User;
            base.Options.ProtocolValidator.ValidateUserInfoResponse(new OpenIdConnectProtocolValidationContext
            {
                UserInfoEndpointResponse = userInfoResponse,
                ValidatedIdToken = jwt
            });
            ClaimsIdentity identity = (ClaimsIdentity)principal.Identity;
            foreach (ClaimAction claimAction in base.Options.ClaimActions)
            {
                claimAction.Run(jsonDocument2.RootElement, identity, ClaimsIssuer);
            }
        }

        return HandleRequestResult.Success(
            new AuthenticationTicket(principal, properties, base.Scheme.Name)  // <-----------------o4.7 now you see why user-client cookie contains name = Emma claim, while id token 
        );                                                                     // still doesn't have name = Emma, because we call UserInfoEndpoint to get more claims  and it is not
    }                                                                          // a good practice to contains user info, the url will be lengthy, some old browser might not support it

    private void SaveTokens(AuthenticationProperties properties, OpenIdConnectMessage message)  
    {
        List<AuthenticationToken> list = new List<AuthenticationToken>();
        if (!string.IsNullOrEmpty(message.AccessToken))
        {
            list.Add(new AuthenticationToken
            {
                Name = "access_token",
                Value = message.AccessToken
            });
        }

        if (!string.IsNullOrEmpty(message.IdToken))
        {
            list.Add(new AuthenticationToken
            {
                Name = "id_token",
                Value = message.IdToken
            });
        }

        if (!string.IsNullOrEmpty(message.RefreshToken))
        {
            list.Add(new AuthenticationToken
            {
                Name = "refresh_token",
                Value = message.RefreshToken
            });
        }

        if (!string.IsNullOrEmpty(message.TokenType))
        {
            list.Add(new AuthenticationToken
            {
                Name = "token_type",
                Value = message.TokenType
            });
        }

        if (!string.IsNullOrEmpty(message.ExpiresIn) && int.TryParse(message.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result))
        {
            DateTimeOffset dateTimeOffset = base.Clock.UtcNow + TimeSpan.FromSeconds(result);
            list.Add(new AuthenticationToken
            {
                Name = "expires_at",
                Value = dateTimeOffset.ToString("o", CultureInfo.InvariantCulture)
            });
        }

        properties.StoreTokens(list);  // <------------------o4.3 save token into AuthenticationProperties.Items which will be part of AuthenticationTicket then serilzed into cookies
    }

    private void WriteNonceCookie(string nonce)
    {
        if (string.IsNullOrEmpty(nonce))
        {
            throw new ArgumentNullException("nonce");
        }

        CookieOptions options = base.Options.NonceCookie.Build(base.Context, base.Clock.UtcNow);
        base.Response.Cookies.Append(base.Options.NonceCookie.Name + base.Options.StringDataFormat.Protect(nonce), "N", options);
    }

    private string ReadNonceCookie(string nonce)
    {
        if (nonce == null)
        {
            return null;
        }

        foreach (string key in base.Request.Cookies.Keys)
        {
            string name = base.Options.NonceCookie.Name;
            if (name == null || !key.StartsWith(name, StringComparison.Ordinal))
            {
                continue;
            }

            try
            {
                if (base.Options.StringDataFormat.Unprotect(key.Substring(base.Options.NonceCookie.Name.Length, key.Length - base.Options.NonceCookie.Name.Length)) == nonce)
                {
                    CookieOptions options = base.Options.NonceCookie.Build(base.Context, base.Clock.UtcNow);
                    base.Response.Cookies.Delete(key, options);
                    return nonce;
                }
            }
            catch (Exception ex)
            {
                base.Logger.UnableToProtectNonceCookie(ex);
            }
        }

        return null;
    }

    private async Task<MessageReceivedContext> RunMessageReceivedEventAsync(OpenIdConnectMessage message, AuthenticationProperties properties)
    {
        base.Logger.MessageReceived(message.BuildRedirectUrl());
        MessageReceivedContext context = new MessageReceivedContext(base.Context, base.Scheme, base.Options, properties)
        {
            ProtocolMessage = message
        };
        await Events.MessageReceived(context);
        if (context.Result != null)
        {
            if (context.Result.Handled)
            {
                base.Logger.MessageReceivedContextHandledResponse();
            }
            else if (context.Result.Skipped)
            {
                base.Logger.MessageReceivedContextSkipped();
            }
        }

        return context;
    }

    private async Task<TokenValidatedContext> RunTokenValidatedEventAsync(OpenIdConnectMessage authorizationResponse, OpenIdConnectMessage tokenEndpointResponse, ClaimsPrincipal user, AuthenticationProperties properties, JwtSecurityToken jwt, string nonce)
    {
        TokenValidatedContext context = new TokenValidatedContext(base.Context, base.Scheme, base.Options, user, properties)
        {
            ProtocolMessage = authorizationResponse,
            TokenEndpointResponse = tokenEndpointResponse,
            SecurityToken = jwt,
            Nonce = nonce
        };
        await Events.TokenValidated(context);
        if (context.Result != null)
        {
            if (context.Result.Handled)
            {
                base.Logger.TokenValidatedHandledResponse();
            }
            else if (context.Result.Skipped)
            {
                base.Logger.TokenValidatedSkipped();
            }
        }

        return context;
    }

    private async Task<AuthorizationCodeReceivedContext> RunAuthorizationCodeReceivedEventAsync(OpenIdConnectMessage authorizationResponse, ClaimsPrincipal user, AuthenticationProperties properties, JwtSecurityToken jwt)
    {
        base.Logger.AuthorizationCodeReceived();
        OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage
        {
            ClientId = base.Options.ClientId,
            ClientSecret = base.Options.ClientSecret,
            Code = authorizationResponse.Code,
            GrantType = "authorization_code",
            EnableTelemetryParameters = !base.Options.DisableTelemetry,
            RedirectUri = properties.Items[OpenIdConnectDefaults.RedirectUriForCodePropertiesKey]
        };
        if (properties.Items.TryGetValue(OAuthConstants.CodeVerifierKey, out string value))
        {
            openIdConnectMessage.Parameters.Add(OAuthConstants.CodeVerifierKey, value);
            properties.Items.Remove(OAuthConstants.CodeVerifierKey);
        }

        AuthorizationCodeReceivedContext context = new AuthorizationCodeReceivedContext(base.Context, base.Scheme, base.Options, properties)
        {
            ProtocolMessage = authorizationResponse,
            TokenEndpointRequest = openIdConnectMessage,
            Principal = user,
            JwtSecurityToken = jwt,
            Backchannel = Backchannel
        };
        await Events.AuthorizationCodeReceived(context);   // <---------------------------------o3.1, for users to override 
        if (context.Result != null)
        {
            if (context.Result.Handled)
            {
                base.Logger.AuthorizationCodeReceivedContextHandledResponse();
            }
            else if (context.Result.Skipped)
            {
                base.Logger.AuthorizationCodeReceivedContextSkipped();
            }
        }

        return context;
    }

    private async Task<TokenResponseReceivedContext> RunTokenResponseReceivedEventAsync(OpenIdConnectMessage message, OpenIdConnectMessage tokenEndpointResponse, ClaimsPrincipal user, AuthenticationProperties properties)
    {
        base.Logger.TokenResponseReceived();
        TokenResponseReceivedContext context = new TokenResponseReceivedContext(base.Context, base.Scheme, base.Options, user, properties)
        {
            ProtocolMessage = message,
            TokenEndpointResponse = tokenEndpointResponse
        };
        await Events.TokenResponseReceived(context);
        if (context.Result != null)
        {
            if (context.Result.Handled)
            {
                base.Logger.TokenResponseReceivedHandledResponse();
            }
            else if (context.Result.Skipped)
            {
                base.Logger.TokenResponseReceivedSkipped();
            }
        }

        return context;
    }

    private async Task<UserInformationReceivedContext> RunUserInformationReceivedEventAsync(ClaimsPrincipal principal, AuthenticationProperties properties, OpenIdConnectMessage message, JsonDocument user)
    {
        base.Logger.UserInformationReceived(user.ToString());
        UserInformationReceivedContext context = new UserInformationReceivedContext(base.Context, base.Scheme, base.Options, principal, properties)
        {
            ProtocolMessage = message,
            User = user
        };
        await Events.UserInformationReceived(context);
        if (context.Result != null)
        {
            if (context.Result.Handled)
            {
                base.Logger.UserInformationReceivedHandledResponse();
            }
            else if (context.Result.Skipped)
            {
                base.Logger.UserInformationReceivedSkipped();
            }
        }

        return context;
    }

    private async Task<AuthenticationFailedContext> RunAuthenticationFailedEventAsync(OpenIdConnectMessage message, Exception exception)
    {
        AuthenticationFailedContext context = new AuthenticationFailedContext(base.Context, base.Scheme, base.Options)
        {
            ProtocolMessage = message,
            Exception = exception
        };
        await Events.AuthenticationFailed(context);
        if (context.Result != null)
        {
            if (context.Result.Handled)
            {
                base.Logger.AuthenticationFailedContextHandledResponse();
            }
            else if (context.Result.Skipped)
            {
                base.Logger.AuthenticationFailedContextSkipped();
            }
        }

        return context;
    }

    private ClaimsPrincipal ValidateToken(string idToken, AuthenticationProperties properties, TokenValidationParameters validationParameters, out JwtSecurityToken jwt)
    {
        if (!base.Options.SecurityTokenValidator.CanReadToken(idToken))
        {
            base.Logger.UnableToReadIdToken(idToken);
            throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, Resources.UnableToValidateToken, idToken));
        }

        if (_configuration != null)
        {
            string[] array = new string[1] { _configuration.Issuer };
            validationParameters.ValidIssuers = validationParameters.ValidIssuers?.Concat(array) ?? array;
            validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(_configuration.SigningKeys) ?? _configuration.SigningKeys;
        }

        SecurityToken validatedToken;
        ClaimsPrincipal result = base.Options.SecurityTokenValidator.ValidateToken(idToken, validationParameters, out validatedToken);
        if (validatedToken is JwtSecurityToken jwtSecurityToken)
        {
            jwt = jwtSecurityToken;
            if (validatedToken == null)
            {
                base.Logger.UnableToValidateIdToken(idToken);
                throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, Resources.UnableToValidateToken, idToken));
            }

            if (base.Options.UseTokenLifetime)
            {
                DateTime validFrom = validatedToken.ValidFrom;
                if (validFrom != DateTime.MinValue)
                {
                    properties.IssuedUtc = validFrom;
                }

                DateTime validTo = validatedToken.ValidTo;
                if (validTo != DateTime.MinValue)
                {
                    properties.ExpiresUtc = validTo;
                }
            }

            return result;
        }

        base.Logger.InvalidSecurityTokenType(validatedToken?.GetType().ToString());
        throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, Resources.ValidatedSecurityTokenNotJwt, validatedToken?.GetType()));
    }

    private string BuildRedirectUriIfRelative(string uri);
}
//-------------------------------Ʌ

//---------------------------------------------------------V
public abstract class RemoteAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions>, IAuthenticationRequestHandler where TOptions : RemoteAuthenticationOptions, new()
{
    private const string CorrelationProperty = ".xsrf";
    private const string CorrelationMarker = "N";
    private const string AuthSchemeKey = ".AuthScheme";

    protected string? SignInScheme => Options.SignInScheme;

    protected new RemoteAuthenticationEvents Events { get; set; }  // on base.Events

    protected RemoteAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock) { }

    protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new RemoteAuthenticationEvents());

    public virtual Task<bool> ShouldHandleRequestAsync()  => Task.FromResult(Options.CallbackPath == Request.Path);  // <-------o2.1 CallbackPath and Path matches which is "signin-oidc"
                                                                                                                     // so it can intercept the callback like ExternalAuthHandler
    public virtual async Task<bool> HandleRequestAsync()  // <----------------------------o2.0
    {
        if (!await ShouldHandleRequestAsync())   // <------------------------o2.1
        {
            return false;
        }

        AuthenticationTicket? ticket = null;
        Exception? exception = null;
        AuthenticationProperties? properties = null;
        try
        {
            var authResult = await HandleRemoteAuthenticateAsync();  // <----------------------------o2.2.
            if (authResult == null)
            {
                exception = new InvalidOperationException("Invalid return state, unable to redirect.");
            }
            else if (authResult.Handled)
            {
                return true;
            }
            else if (authResult.Skipped || authResult.None)
            {
                return false;
            }
            else if (!authResult.Succeeded)
            {
                exception = authResult.Failure ?? new InvalidOperationException("Invalid return state, unable to redirect.");
                properties = authResult.Properties;
            }

            ticket = authResult?.Ticket;
        }
        catch (Exception ex)
        {
            exception = ex;
        }

        if (exception != null)
        {
           // ...
        }

        // We have a ticket if we get here
        Debug.Assert(ticket != null);
        var ticketContext = new TicketReceivedContext(Context, Scheme, Options, ticket)
        {
            ReturnUri = ticket.Properties.RedirectUri
        };

        ticket.Properties.RedirectUri = null;

        // Mark which provider produced this identity so we can cross-check later in HandleAuthenticateAsync
        ticketContext.Properties!.Items[AuthSchemeKey] = Scheme.Name;

        await Events.TicketReceived(ticketContext);

        if (ticketContext.Result != null)
        {
            if (ticketContext.Result.Handled)
            {
                Logger.SignInHandled();
                return true;
            }
            else if (ticketContext.Result.Skipped)
            {
                Logger.SignInSkipped();
                return false;
            }
        }

        await Context.SignInAsync(SignInScheme, ticketContext.Principal!, ticketContext.Properties);  // <-----------o5.0 CookieAuthenticationHandler serialize ClaimsIdentity into cookie

        // Default redirect path is the base path
        if (string.IsNullOrEmpty(ticketContext.ReturnUri))
        {
            ticketContext.ReturnUri = "/";
        }

        Response.Redirect(ticketContext.ReturnUri);  // <----------------------------o5.1.   ReturnUri is the original user request path such as controller/index
                                                     // Response redirect also sends the cookie created above so that users' next request can come with cookoie
        return true;
    }

    protected abstract Task<HandleRequestResult> HandleRemoteAuthenticateAsync();

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await Context.AuthenticateAsync(SignInScheme);
        if (result != null)
        {
            if (result.Failure != null)
            {
                return result;
            }

            // The SignInScheme may be shared with multiple providers, make sure this provider issued the identity.
            var ticket = result.Ticket;
            if (ticket != null && ticket.Principal != null && ticket.Properties != null
                && ticket.Properties.Items.TryGetValue(AuthSchemeKey, out var authenticatedScheme)
                && string.Equals(Scheme.Name, authenticatedScheme, StringComparison.Ordinal))
            {
                return AuthenticateResult.Success(new AuthenticationTicket(ticket.Principal,
                    ticket.Properties, Scheme.Name));
            }

            return AuthenticateResult.Fail("Not authenticated");
        }

        return AuthenticateResult.Fail("Remote authentication does not directly support AuthenticateAsync");
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties) => Context.ForbidAsync(SignInScheme);

    protected virtual void GenerateCorrelationId(AuthenticationProperties properties)
    {
        if (properties == null)
        {
            throw new ArgumentNullException(nameof(properties));
        }

        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var correlationId = Base64UrlTextEncoder.Encode(bytes);

        var cookieOptions = Options.CorrelationCookie.Build(Context, Clock.UtcNow);

        properties.Items[CorrelationProperty] = correlationId;

        var cookieName = Options.CorrelationCookie.Name + correlationId;

        Response.Cookies.Append(cookieName, CorrelationMarker, cookieOptions);
    }

    protected virtual bool ValidateCorrelationId(AuthenticationProperties properties)
    {
        if (properties == null)
        {
            throw new ArgumentNullException(nameof(properties));
        }

        if (!properties.Items.TryGetValue(CorrelationProperty, out var correlationId))
        {
            Logger.CorrelationPropertyNotFound(Options.CorrelationCookie.Name!);
            return false;
        }

        properties.Items.Remove(CorrelationProperty);

        var cookieName = Options.CorrelationCookie.Name + correlationId;

        var correlationCookie = Request.Cookies[cookieName];
        if (string.IsNullOrEmpty(correlationCookie))
        {
            Logger.CorrelationCookieNotFound(cookieName);
            return false;
        }

        var cookieOptions = Options.CorrelationCookie.Build(Context, Clock.UtcNow);

        Response.Cookies.Delete(cookieName, cookieOptions);

        if (!string.Equals(correlationCookie, CorrelationMarker, StringComparison.Ordinal))
        {
            Logger.UnexpectedCorrelationCookieValue(cookieName, correlationCookie);
            return false;
        }

        return true;
    }

    protected virtual async Task<HandleRequestResult> HandleAccessDeniedErrorAsync(AuthenticationProperties properties)
    {
        Logger.AccessDeniedError();
        var context = new AccessDeniedContext(Context, Scheme, Options)
        {
            AccessDeniedPath = Options.AccessDeniedPath,
            Properties = properties,
            ReturnUrl = properties?.RedirectUri,
            ReturnUrlParameter = Options.ReturnUrlParameter
        };
        await Events.AccessDenied(context);

        if (context.Result != null)
        {
            if (context.Result.Handled)
            {
                Logger.AccessDeniedContextHandled();
            }
            else if (context.Result.Skipped)
            {
                Logger.AccessDeniedContextSkipped();
            }

            return context.Result;
        }

        // If an access denied endpoint was specified, redirect the user agent. Otherwise, invoke the RemoteFailure event for further processing.
        if (context.AccessDeniedPath.HasValue)
        {
            string uri = context.AccessDeniedPath;
            if (!string.IsNullOrEmpty(context.ReturnUrlParameter) && !string.IsNullOrEmpty(context.ReturnUrl))
            {
                uri = QueryHelpers.AddQueryString(uri, context.ReturnUrlParameter, context.ReturnUrl);
            }
            Response.Redirect(BuildRedirectUri(uri));

            return HandleRequestResult.Handle();
        }

        return HandleRequestResult.NoResult();
    }
}
//---------------------------------------------------------Ʌ
```

```C#
//--------------------------------V
public abstract class TokenHandler
{
    private int _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;
    private int _maximumTokenSizeInBytes = 256000;
    public static readonly int DefaultTokenLifetimeInMinutes = 60;
    public virtual int MaximumTokenSizeInBytes
    {
        get
        {
            return _maximumTokenSizeInBytes;
        }
        set
        {
            if (value < 1)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("value", LogHelper.FormatInvariant("IDX10101: MaximumTokenSizeInBytes must be greater than zero. value: '{0}'", LogHelper.MarkAsNonPII(value))));
            }

            _maximumTokenSizeInBytes = value;
        }
    }

    [DefaultValue(true)]
    public bool SetDefaultTimesOnTokenCreation { get; set; } = true;

    public int TokenLifetimeInMinutes
    {
        get
        {
            return _defaultTokenLifetimeInMinutes;
        }
        set
        {
            if (value < 1)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("value", LogHelper.FormatInvariant("IDX10104: TokenLifetimeInMinutes must be greater than zero. value: '{0}'", LogHelper.MarkAsNonPII(value))));
            }

            _defaultTokenLifetimeInMinutes = value;
        }
    }

    public virtual Task<TokenValidationResult> ValidateTokenAsync(string token, TokenValidationParameters validationParameters) => throw new NotImplementedException();
    public virtual Task<TokenValidationResult> ValidateTokenAsync(SecurityToken token, TokenValidationParameters validationParameters)  => throw new NotImplementedException();
    public virtual SecurityToken ReadToken(string token)  => throw new NotImplementedException();
    internal virtual ClaimsIdentity CreateClaimsIdentityInternal(SecurityToken securityToken, TokenValidationParameters tokenValidationParameters, string issuer) 
        => throw new NotImplementedException();
}
//--------------------------------Ʌ

//------------------------------------V
internal static class ClaimTypeMapping
{
    private static readonly Dictionary<string, string> shortToLongClaimTypeMapping;
    private static readonly Dictionary<string, string> longToShortClaimTypeMapping;
    private static readonly HashSet<string> inboundClaimFilter;
    public static IDictionary<string, string> InboundClaimTypeMap => shortToLongClaimTypeMapping;
    public static IDictionary<string, string> OutboundClaimTypeMap => longToShortClaimTypeMapping;

    public static ISet<string> InboundClaimFilter => inboundClaimFilter;

    static ClaimTypeMapping()
    {
        shortToLongClaimTypeMapping = new Dictionary<string, string>
        {
            { "actort", "http://schemas.xmlsoap.org/ws/2009/09/identity/claims/actor" },
            { "birthdate", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth" },
            { "email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" },
            { "family_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" },
            { "gender", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender" },
            { "given_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" },
            { "nameid", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" },
            { "sub", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" },
            { "website", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/webpage" },
            { "unique_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" },
            { "oid", "http://schemas.microsoft.com/identity/claims/objectidentifier" },
            { "scp", "http://schemas.microsoft.com/identity/claims/scope" },
            { "commonname", "http://schemas.xmlsoap.org/claims/CommonName" },
            { "denyonlyprimarygroupsid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarygroupsid" },
            { "deviceid", "http://schemas.microsoft.com/2012/01/devicecontext/claims/identifier" },
            { "group", "http://schemas.xmlsoap.org/claims/Group" },
            { "groupsid", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid" },
            { "idp", "http://schemas.microsoft.com/identity/claims/identityprovider" },
            { "role", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" },
            { "roles", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" },
            // ...
        };
        longToShortClaimTypeMapping = new Dictionary<string, string>();
        inboundClaimFilter = (inboundClaimFilter = new HashSet<string>());
        foreach (KeyValuePair<string, string> item in shortToLongClaimTypeMapping)
        {
            if (!longToShortClaimTypeMapping.ContainsKey(item.Value))
            {
                longToShortClaimTypeMapping.Add(item.Value, item.Key);
            }
        }
    }
}
//------------------------------------Ʌ

//------------------------------V
public class JsonWebTokenHandler : TokenHandler
{
    private IDictionary<string, string> _inboundClaimTypeMap;
    private const string _namespace = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties";
    private static string _shortClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName";
    private bool _mapInboundClaims = DefaultMapInboundClaims;
    public static IDictionary<string, string> DefaultInboundClaimTypeMap = new Dictionary<string, string>(ClaimTypeMapping.InboundClaimTypeMap);  // <---------
    public static bool DefaultMapInboundClaims = false;
    public const string Base64UrlEncodedUnsignedJWSHeader = "eyJhbGciOiJub25lIn0";
    public Type TokenType => typeof(JsonWebToken);
    public IDictionary<string, string> InboundClaimTypeMap { get; set; }
    public virtual bool CanValidateToken { get; }
    
    public JsonWebTokenHandler()
    {
        if (_mapInboundClaims)
            _inboundClaimTypeMap = new Dictionary<string, string>(DefaultInboundClaimTypeMap);
        else
            _inboundClaimTypeMap = new Dictionary<string, string>();
    }

    public bool MapInboundClaims  // jcm, default value is false
    {
        get {
            return _mapInboundClaims;
        }
            
        set {
            if (!_mapInboundClaims && value && _inboundClaimTypeMap.Count == 0)
                _inboundClaimTypeMap = new Dictionary<string, string>(DefaultInboundClaimTypeMap);

            _mapInboundClaims = value;
        }
    }
    public virtual bool CanReadToken(string token);
    public virtual string CreateToken(SecurityTokenDescriptor tokenDescriptor);
    public virtual string CreateToken(string payload);
    public virtual string CreateToken(string payload, IDictionary<string, object> additionalHeaderClaims);
    public virtual string CreateToken(string payload, SigningCredentials signingCredentials, IDictionary<string, object> additionalHeaderClaims);
    public virtual string CreateToken(string payload, SigningCredentials signingCredentials);
    public string EncryptToken(string innerJwt, EncryptingCredentials encryptingCredentials, string algorithm, IDictionary<string, object> additionalHeaderClaims);
    public virtual JsonWebToken ReadJsonWebToken(string token);
    public override SecurityToken ReadToken(string token);
    public virtual TokenValidationResult ValidateToken(string token, TokenValidationParameters validationParameters);
    protected virtual ClaimsIdentity CreateClaimsIdentity(JsonWebToken jwtToken, TokenValidationParameters validationParameters, string issuer);
    protected virtual SecurityKey ResolveTokenDecryptionKey(string token, JsonWebToken jwtToken, TokenValidationParameters validationParameters);
    // ...
}
//------------------------------Ʌ

//----------------------------------V
public class JwtSecurityTokenHandler : SecurityTokenHandler
{
    private delegate bool CertMatcher(X509Certificate2 cert);

    private ISet<string> _inboundClaimFilter;

    private IDictionary<string, string> _inboundClaimTypeMap;

    private static string _jsonClaimType;

    private const string _namespace = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties";

    private const string _className = "System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler";

    private IDictionary<string, string> _outboundClaimTypeMap;
    private Dictionary<string, string> _outboundAlgorithmMap;
    private static string _shortClaimType;
    private bool _mapInboundClaims = DefaultMapInboundClaims;
    public static IDictionary<string, string> DefaultInboundClaimTypeMap;
    public static bool DefaultMapInboundClaims;
    public static IDictionary<string, string> DefaultOutboundClaimTypeMap;
    public static ISet<string> DefaultInboundClaimFilter;
    public static IDictionary<string, string> DefaultOutboundAlgorithmMap;

    public bool MapInboundClaims
    {
        get {
            return _mapInboundClaims;
        }
        set {
            if (!_mapInboundClaims && value && _inboundClaimTypeMap.Count == 0)
            {
                _inboundClaimTypeMap = new Dictionary<string, string>(DefaultInboundClaimTypeMap);
            }

            _mapInboundClaims = value;
        }
    }

    public IDictionary<string, string> InboundClaimTypeMap  { get; set; }   // _inboundClaimTypeMap
    public IDictionary<string, string> OutboundClaimTypeMap { get; set; }   // on _outboundClaimTypeMap
    public IDictionary<string, string> OutboundAlgorithmMap => _outboundAlgorithmMap;
    public ISet<string> InboundClaimFilter { get; set; }       // on _inboundClaimFilter
    public static string ShortClaimTypeProperty { get; set; }  // on _shortClaimType
    public static string JsonClaimTypeProperty { get; set; }   // on _jsonClaimType

    public override bool CanValidateToken => true;
    public override bool CanWriteToken => true;
    public override Type TokenType => typeof(JwtSecurityToken);

    static JwtSecurityTokenHandler()
    {
        _jsonClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/json_type";
        _shortClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName";
        DefaultInboundClaimTypeMap = new Dictionary<string, string>(ClaimTypeMapping.InboundClaimTypeMap);
        DefaultMapInboundClaims = true;
        DefaultOutboundClaimTypeMap = new Dictionary<string, string>(ClaimTypeMapping.OutboundClaimTypeMap);
        DefaultInboundClaimFilter = ClaimTypeMapping.InboundClaimFilter;
        DefaultOutboundAlgorithmMap = new Dictionary<string, string>
        {
            { "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "ES256" },
            { "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "ES384" },
            { "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", "ES512" },
            { "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HS256" },
            { "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "HS384" },
            { "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "HS512" },
            { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "RS256" },
            { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "RS384" },
            { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "RS512" }
        };
    }

    public JwtSecurityTokenHandler()
    {
        if (_mapInboundClaims)
        {
            _inboundClaimTypeMap = new Dictionary<string, string>(DefaultInboundClaimTypeMap);
        }
        else
        {
            _inboundClaimTypeMap = new Dictionary<string, string>();
        }

        _outboundClaimTypeMap = new Dictionary<string, string>(DefaultOutboundClaimTypeMap);
        _inboundClaimFilter = new HashSet<string>(DefaultInboundClaimFilter);
        _outboundAlgorithmMap = new Dictionary<string, string>(DefaultOutboundAlgorithmMap);
    }

    public override bool CanReadToken(string token);

    public virtual JwtSecurityToken CreateJwtSecurityToken(string issuer = null, string audience = null, ClaimsIdentity subject = null, DateTime? notBefore = null, DateTime? expires = null, DateTime? issuedAt = null, SigningCredentials signingCredentials = null)
    {
        return CreateJwtSecurityTokenPrivate(issuer, audience, subject, notBefore, expires, issuedAt, signingCredentials, null, null, null, null, null);
    }

    public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
    {
        if (tokenDescriptor == null)
        {
            throw LogHelper.LogArgumentNullException("tokenDescriptor");
        }

        return CreateJwtSecurityTokenPrivate(tokenDescriptor.Issuer, tokenDescriptor.Audience, tokenDescriptor.Subject, tokenDescriptor.NotBefore, tokenDescriptor.Expires, tokenDescriptor.IssuedAt, tokenDescriptor.SigningCredentials, tokenDescriptor.EncryptingCredentials, tokenDescriptor.Claims, tokenDescriptor.TokenType, tokenDescriptor.AdditionalHeaderClaims, tokenDescriptor.AdditionalInnerHeaderClaims);
    }

    private JwtSecurityToken CreateJwtSecurityTokenPrivate(string issuer, string audience, ClaimsIdentity subject, DateTime? notBefore, DateTime? expires, DateTime? issuedAt, SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials, IDictionary<string, object> claimCollection, string tokenType, IDictionary<string, object> additionalHeaderClaims, IDictionary<string, object> additionalInnerHeaderClaims)
    {
        if (base.SetDefaultTimesOnTokenCreation && (!expires.HasValue || !issuedAt.HasValue || !notBefore.HasValue))
        {
            DateTime utcNow = DateTime.UtcNow;
            if (!expires.HasValue)
            {
                expires = utcNow + TimeSpan.FromMinutes(base.TokenLifetimeInMinutes);
            }

            if (!issuedAt.HasValue)
            {
                issuedAt = utcNow;
            }

            if (!notBefore.HasValue)
            {
                notBefore = utcNow;
            }
        }

        if (LogHelper.IsEnabled(EventLogLevel.Verbose))
        {
            LogHelper.LogVerbose("IDX12721: Creating JwtSecurityToken: Issuer: '{0}', Audience: '{1}'", LogHelper.MarkAsNonPII(issuer ?? "null"), LogHelper.MarkAsNonPII(audience ?? "null"));
        }

        JwtPayload jwtPayload = new JwtPayload(issuer, audience, (subject == null) ? null : OutboundClaimTypeTransform(subject.Claims), (claimCollection == null) ? null : OutboundClaimTypeTransform(claimCollection), notBefore, expires, issuedAt);
        JwtHeader jwtHeader = new JwtHeader(signingCredentials, OutboundAlgorithmMap, tokenType, additionalInnerHeaderClaims);
        if (subject?.Actor != null)
        {
            jwtPayload.AddClaim(new Claim("actort", CreateActorValue(subject.Actor)));
        }

        string text = jwtHeader.Base64UrlEncode();
        string text2 = jwtPayload.Base64UrlEncode();
        string rawSignature = string.Empty;
        if (signingCredentials != null)
        {
            rawSignature = JwtTokenUtilities.CreateEncodedSignature(text + "." + text2, signingCredentials);
        }

        if (LogHelper.IsEnabled(EventLogLevel.Informational))
        {
            LogHelper.LogInformation("IDX12722: Creating security token from the header: '{0}', payload: '{1}'.", text, text2);
        }

        if (encryptingCredentials != null)
        {
            return EncryptToken(new JwtSecurityToken(jwtHeader, jwtPayload, text, text2, rawSignature), encryptingCredentials, tokenType, additionalHeaderClaims);
        }

        return new JwtSecurityToken(jwtHeader, jwtPayload, text, text2, rawSignature);
    }

    private JwtSecurityToken EncryptToken(JwtSecurityToken innerJwt, EncryptingCredentials encryptingCredentials, string tokenType, IDictionary<string, object> additionalHeaderClaims);

    private IEnumerable<Claim> OutboundClaimTypeTransform(IEnumerable<Claim> claims)
    {
        foreach (Claim claim in claims)
        {
            string value = null;
            if (_outboundClaimTypeMap.TryGetValue(claim.Type, out value))
            {
                yield return new Claim(value, claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer, claim.Subject);
            }
            else
            {
                yield return claim;
            }
        }
    }

    private Dictionary<string, object> OutboundClaimTypeTransform(IDictionary<string, object> claimCollection)
    {
        Dictionary<string, object> dictionary = new Dictionary<string, object>();
        foreach (string key in claimCollection.Keys)
        {
            if (_outboundClaimTypeMap.TryGetValue(key, out var value))
            {
                dictionary[value] = claimCollection[key];
            }
            else
            {
                dictionary[key] = claimCollection[key];
            }
        }

        return dictionary;
    }

    public JwtSecurityToken ReadJwtToken(string token);

    public override SecurityToken ReadToken(string token) => return ReadJwtToken(token);

    public override SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters) => throw new NotImplementedException();

    public override ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken);
  
    // Returns:
    //     A System.Security.Claims.ClaimsPrincipal from the JWT. Does not include claims
    //     found in the JWT header.
    private ClaimsPrincipal ValidateToken(string token, JwtSecurityToken outerToken, TokenValidationParameters validationParameters, out SecurityToken signatureValidatedToken)
    {
        BaseConfiguration baseConfiguration = null;
        if (validationParameters.ConfigurationManager != null)
        {
            try
            {
                baseConfiguration = validationParameters.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).ConfigureAwait(continueOnCapturedContext: false).GetAwaiter()
                    .GetResult();
            }
            catch (Exception ex)
            {
                if (LogHelper.IsEnabled(EventLogLevel.Warning))
                {
                    LogHelper.LogWarning(LogHelper.FormatInvariant("IDX10261: Unable to retrieve configuration from authority: '{0}'. \nProceeding with token validation in case the relevant properties have been set manually on the TokenValidationParameters. Exception caught: \n {1}. See https://aka.ms/validate-using-configuration-manager for additional information.", LogHelper.MarkAsNonPII(validationParameters.ConfigurationManager.MetadataAddress), ex.ToString()));
                }
            }
        }

        ExceptionDispatchInfo exceptionThrown;
        ClaimsPrincipal claimsPrincipal = ((outerToken != null) ? ValidateJWE(token, outerToken, validationParameters, baseConfiguration, out signatureValidatedToken, out exceptionThrown) : ValidateJWS(token, validationParameters, baseConfiguration, out signatureValidatedToken, out exceptionThrown));
        if (validationParameters.ConfigurationManager != null)
        {
            if (claimsPrincipal != null)
            {
                if (baseConfiguration != null)
                {
                    validationParameters.ConfigurationManager.LastKnownGoodConfiguration = baseConfiguration;
                }

                return claimsPrincipal;
            }

            if (TokenUtilities.IsRecoverableException(exceptionThrown.SourceException))
            {
                if (baseConfiguration != null)
                {
                    validationParameters.ConfigurationManager.RequestRefresh();
                    validationParameters.RefreshBeforeValidation = true;
                    BaseConfiguration baseConfiguration2 = baseConfiguration;
                    baseConfiguration = validationParameters.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).GetAwaiter().GetResult();
                    if (baseConfiguration2 != baseConfiguration)
                    {
                        claimsPrincipal = ((outerToken != null) ? ValidateJWE(token, outerToken, validationParameters, baseConfiguration, out signatureValidatedToken, out exceptionThrown) : ValidateJWS(token, validationParameters, baseConfiguration, out signatureValidatedToken, out exceptionThrown));
                        if (claimsPrincipal != null)
                        {
                            validationParameters.ConfigurationManager.LastKnownGoodConfiguration = baseConfiguration;
                            return claimsPrincipal;
                        }
                    }
                }

                if (validationParameters.ConfigurationManager.UseLastKnownGoodConfiguration)
                {
                    validationParameters.RefreshBeforeValidation = false;
                    validationParameters.ValidateWithLKG = true;
                    Exception sourceException = exceptionThrown.SourceException;
                    string kid = ((outerToken != null) ? outerToken.Header.Kid : (ValidateSignatureUsingDelegates(token, validationParameters, null) ?? GetJwtSecurityTokenFromToken(token, validationParameters)).Header.Kid);
                    BaseConfiguration[] validLkgConfigurations = validationParameters.ConfigurationManager.GetValidLkgConfigurations();
                    foreach (BaseConfiguration baseConfiguration3 in validLkgConfigurations)
                    {
                        if (!baseConfiguration3.Equals(baseConfiguration) && TokenUtilities.IsRecoverableConfiguration(kid, baseConfiguration, baseConfiguration3, sourceException))
                        {
                            claimsPrincipal = ((outerToken != null) ? ValidateJWE(token, outerToken, validationParameters, baseConfiguration3, out signatureValidatedToken, out exceptionThrown) : ValidateJWS(token, validationParameters, baseConfiguration3, out signatureValidatedToken, out exceptionThrown));
                            if (claimsPrincipal != null)
                            {
                                return claimsPrincipal;
                            }
                        }
                    }
                }
            }
        }

        if (claimsPrincipal != null)
        {
            return claimsPrincipal;
        }

        exceptionThrown.Throw();
        return null;
    }

    // ...

    private static JwtSecurityToken ValidateSignatureUsingDelegates(string token, TokenValidationParameters validationParameters, BaseConfiguration configuration);

    private JwtSecurityToken ValidateSignatureAndIssuerSecurityKey(string token, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters, BaseConfiguration configuration);

    private JwtSecurityToken GetJwtSecurityTokenFromToken(string token, TokenValidationParameters validationParameters);

    protected ClaimsPrincipal ValidateTokenPayload(JwtSecurityToken jwtToken, TokenValidationParameters validationParameters)
    {
        return ValidateTokenPayload(jwtToken, validationParameters, null);
    }

    private ClaimsPrincipal ValidateTokenPayload(JwtSecurityToken jwtToken, TokenValidationParameters validationParameters, BaseConfiguration configuration)
    {
        DateTime? expires = ((!jwtToken.Payload.Expiration.HasValue) ? null : new DateTime?(jwtToken.ValidTo));
        DateTime? notBefore = ((!jwtToken.Payload.NotBefore.HasValue) ? null : new DateTime?(jwtToken.ValidFrom));
        ValidateLifetime(notBefore, expires, jwtToken, validationParameters);
        ValidateAudience(jwtToken.Audiences, jwtToken, validationParameters);
        string issuer = ((configuration == null) ? ValidateIssuer(jwtToken.Issuer, jwtToken, validationParameters) : Validators.ValidateIssuer(jwtToken.Issuer, jwtToken, validationParameters, configuration));
        ValidateTokenReplay(expires, jwtToken.RawData, validationParameters);
        if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jwtToken.Actor))
        {
            ValidateToken(jwtToken.Actor, validationParameters.ActorValidationParameters ?? validationParameters, out var _);
        }

        Validators.ValidateTokenType(jwtToken.Header.Typ, jwtToken, validationParameters);
        ClaimsIdentity claimsIdentity = CreateClaimsIdentity(jwtToken, issuer, validationParameters);
        if (validationParameters.SaveSigninToken)
        {
            claimsIdentity.BootstrapContext = jwtToken.RawData;
        }

        return new ClaimsPrincipal(claimsIdentity);
    }

    private ClaimsPrincipal CreateClaimsPrincipalFromToken(JwtSecurityToken jwtToken, string issuer, TokenValidationParameters validationParameters)
    {
        ClaimsIdentity claimsIdentity = CreateClaimsIdentity(jwtToken, issuer, validationParameters);
        if (validationParameters.SaveSigninToken)
        {
            claimsIdentity.BootstrapContext = jwtToken.RawData;
        }

        if (LogHelper.IsEnabled(EventLogLevel.Informational))
        {
            LogHelper.LogInformation("IDX10241: Security token validated. token: '{0}'.", jwtToken);
        }

        return new ClaimsPrincipal(claimsIdentity);
    }

    public override string WriteToken(SecurityToken token);

    protected virtual JwtSecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters)
    {
        JwtSecurityToken jwtSecurityToken = ValidateSignatureUsingDelegates(token, validationParameters, null);
        JwtSecurityToken jwtSecurityTokenFromToken = GetJwtSecurityTokenFromToken(token, validationParameters);
        return ValidateSignature(token, jwtSecurityToken ?? jwtSecurityTokenFromToken, validationParameters, null);
    }

    private JwtSecurityToken ValidateSignature(string token, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters, BaseConfiguration configuration);

    private static IEnumerable<SecurityKey> GetAllDecryptionKeys(TokenValidationParameters validationParameters)
    {
        if (validationParameters.TokenDecryptionKey != null)
            yield return validationParameters.TokenDecryptionKey;

        if (validationParameters.TokenDecryptionKeys == null)
            yield break;

        foreach (SecurityKey tokenDecryptionKey in validationParameters.TokenDecryptionKeys)
            yield return tokenDecryptionKey;
    }

    protected virtual ClaimsIdentity CreateClaimsIdentity(JwtSecurityToken jwtToken, string issuer, TokenValidationParameters validationParameters)
    {
        if (jwtToken == null)
        {
            throw LogHelper.LogArgumentNullException("jwtToken");
        }

        if (validationParameters == null)
        {
            throw LogHelper.LogArgumentNullException("validationParameters");
        }

        string actualIssuer = issuer;
        if (string.IsNullOrWhiteSpace(issuer))
        {
            if (LogHelper.IsEnabled(EventLogLevel.Verbose))
            {
                LogHelper.LogVerbose("IDX10244: Issuer is null or empty. Using runtime default for creating claims '{0}'.", LogHelper.MarkAsNonPII("LOCAL AUTHORITY"));
            }

            actualIssuer = "LOCAL AUTHORITY";
        }

        if (!MapInboundClaims)
        {
            return CreateClaimsIdentityWithoutMapping(jwtToken, actualIssuer, validationParameters);
        }

        return CreateClaimsIdentityWithMapping(jwtToken, actualIssuer, validationParameters);
    }

    private ClaimsIdentity CreateClaimsIdentityWithMapping(JwtSecurityToken jwtToken, string actualIssuer, TokenValidationParameters validationParameters)
    {
        ClaimsIdentity claimsIdentity = validationParameters.CreateClaimsIdentity(jwtToken, actualIssuer);
        foreach (Claim claim in jwtToken.Claims)
        {
            if (_inboundClaimFilter.Contains(claim.Type))
            {
                continue;
            }

            bool flag = true;
            if (!_inboundClaimTypeMap.TryGetValue(claim.Type, out var value))
            {
                value = claim.Type;
                flag = false;
            }

            if (value == "http://schemas.xmlsoap.org/ws/2009/09/identity/claims/actor")
            {
                if (claimsIdentity.Actor != null)
                {
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant("IDX12710: Only a single 'Actor' is supported. Found second claim of type: '{0}', value: '{1}'", LogHelper.MarkAsNonPII("actort"), LogHelper.MarkAsSecurityArtifact(claim.Value, JwtTokenUtilities.SafeLogJwtToken))));
                }

                if (CanReadToken(claim.Value))
                {
                    JwtSecurityToken jwtToken2 = ReadToken(claim.Value) as JwtSecurityToken;
                    claimsIdentity.Actor = CreateClaimsIdentity(jwtToken2, actualIssuer, validationParameters);
                }
            }

            Claim claim = new Claim(value, claim.Value, claim.ValueType, actualIssuer, actualIssuer, claimsIdentity);
            if (claim.Properties.Count > 0)
            {
                foreach (KeyValuePair<string, string> property in claim.Properties)
                {
                    claim.Properties[property.Key] = property.Value;
                }
            }

            if (flag)
            {
                claim.Properties[ShortClaimTypeProperty] = claim2.Type;
            }

            claimsIdentity.AddClaim(claim);
        }

        return claimsIdentity;
    }

    private ClaimsIdentity CreateClaimsIdentityWithoutMapping(JwtSecurityToken jwtToken, string actualIssuer, TokenValidationParameters validationParameters)
    {
        ClaimsIdentity claimsIdentity = validationParameters.CreateClaimsIdentity(jwtToken, actualIssuer);
        foreach (Claim claim2 in jwtToken.Claims)
        {
            if (_inboundClaimFilter.Contains(claim2.Type))
            {
                continue;
            }

            string type = claim2.Type;
            if (type == "http://schemas.xmlsoap.org/ws/2009/09/identity/claims/actor")
            {
                if (claimsIdentity.Actor != null)
                {
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant("IDX12710: Only a single 'Actor' is supported. Found second claim of type: '{0}', value: '{1}'", LogHelper.MarkAsNonPII("actort"), LogHelper.MarkAsSecurityArtifact(claim2.Value, JwtTokenUtilities.SafeLogJwtToken))));
                }

                if (CanReadToken(claim2.Value))
                {
                    JwtSecurityToken jwtToken2 = ReadToken(claim2.Value) as JwtSecurityToken;
                    claimsIdentity.Actor = CreateClaimsIdentity(jwtToken2, actualIssuer, validationParameters);
                }
            }

            Claim claim = new Claim(type, claim2.Value, claim2.ValueType, actualIssuer, actualIssuer, claimsIdentity);
            if (claim2.Properties.Count > 0)
            {
                foreach (KeyValuePair<string, string> property in claim2.Properties)
                {
                    claim.Properties[property.Key] = property.Value;
                }
            }

            claimsIdentity.AddClaim(claim);
        }

        return claimsIdentity;
    }

    protected virtual string CreateActorValue(ClaimsIdentity actor);

    protected virtual void ValidateAudience(IEnumerable<string> audiences, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters)
    {
        Validators.ValidateAudience(audiences, jwtToken, validationParameters);
    }

    protected virtual void ValidateLifetime(DateTime? notBefore, DateTime? expires, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters)
    {
        Validators.ValidateLifetime(notBefore, expires, jwtToken, validationParameters);
    }

    protected virtual string ValidateIssuer(string issuer, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters)
    {
        return Validators.ValidateIssuer(issuer, jwtToken, validationParameters);
    }

    protected virtual void ValidateTokenReplay(DateTime? expires, string securityToken, TokenValidationParameters validationParameters)
    {
        Validators.ValidateTokenReplay(expires, securityToken, validationParameters);
    }

    protected virtual SecurityKey ResolveIssuerSigningKey(string token, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters)
    {
        return JwtTokenUtilities.ResolveTokenSigningKey(jwtToken.Header.Kid, jwtToken.Header.X5t, validationParameters, null);
    }

    protected virtual SecurityKey ResolveTokenDecryptionKey(string token, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters);
    protected string DecryptToken(JwtSecurityToken jwtToken, TokenValidationParameters validationParameters);

    internal IEnumerable<SecurityKey> GetContentEncryptionKeys(JwtSecurityToken jwtToken, TokenValidationParameters validationParameters);

    private static byte[] GetSymmetricSecurityKey(SecurityKey key)
    {
        if (key is SymmetricSecurityKey symmetricSecurityKey)
        {
            return symmetricSecurityKey.Key;
        }

        if (key is JsonWebKey jsonWebKey && jsonWebKey.K != null)
        {
            return Base64UrlEncoder.DecodeBytes(jsonWebKey.K);
        }

        return null;
    }

    protected virtual void ValidateIssuerSecurityKey(SecurityKey key, JwtSecurityToken securityToken, TokenValidationParameters validationParameters)
    {
        Validators.ValidateIssuerSecurityKey(key, securityToken, validationParameters);
    }

    public override void WriteToken(XmlWriter writer, SecurityToken token)
    {
        throw new NotImplementedException();
    }

    public override Task<TokenValidationResult> ValidateTokenAsync(string token, TokenValidationParameters validationParameters)
    {
        try
        {
            SecurityToken validatedToken;
            ClaimsPrincipal claimsPrincipal = ValidateToken(token, validationParameters, out validatedToken);
            return Task.FromResult(new TokenValidationResult
            {
                SecurityToken = validatedToken,
                ClaimsIdentity = (claimsPrincipal?.Identity as ClaimsIdentity),
                IsValid = true
            });
        }
        catch (Exception exception)
        {
            return Task.FromResult(new TokenValidationResult
            {
                IsValid = false,
                Exception = exception
            });
        }
    }
}
//----------------------------------Ʌ
```

```C#
//----------------------------------------------------V
public static class ClaimActionCollectionMapExtensions
{ 
    // ...
    public static void MapJsonKey(this ClaimActionCollection collection, string claimType, string jsonKey)
    {
        collection.MapJsonKey(claimType, jsonKey, ClaimValueTypes.String);
    }

    // can be multiple same claim as  { role: "admin" } { role: "vip" }, check oica flag; IsInRole can be used
    public static void MapJsonKey(this ClaimActionCollection collection, string claimType, string jsonKey, string valueType)
    {
        collection.Add(new JsonKeyClaimAction(claimType, valueType, jsonKey));
    }

    // it merge multiple same name claims into ine single claim which is like array e.g { role: ["admin", "vip" ] } compared to MapJsonKey; IsInRole cannot be used
    public static void MapUniqueJsonKey(this ClaimActionCollection collection, string claimType, string jsonKey, string valueType)
    {
        collection.Add(new UniqueJsonKeyClaimAction(claimType, valueType, jsonKey));
    }

    public static void MapAll(this ClaimActionCollection collection)
    {
        ArgumentNullException.ThrowIfNull(collection);

        collection.Clear();
        collection.Add(new MapAllClaimsAction());
    }

    public static void MapAllExcept(this ClaimActionCollection collection, params string[] exclusions)
    {
        ArgumentNullException.ThrowIfNull(collection);

        collection.MapAll();
        collection.DeleteClaims(exclusions);
    }

    public static void DeleteClaim(this ClaimActionCollection collection, string claimType)
    {
        ArgumentNullException.ThrowIfNull(collection);

        collection.Add(new DeleteClaimAction(claimType));
    }

    public static void DeleteClaims(this ClaimActionCollection collection, params string[] claimTypes)
    {
        ArgumentNullException.ThrowIfNull(collection);
        ArgumentNullException.ThrowIfNull(claimTypes);

        foreach (var claimType in claimTypes)
        {
            collection.Add(new DeleteClaimAction(claimType));
        }
    }
}
//----------------------------------------------------Ʌ
//-------------------------------V
public abstract class ClaimAction
{
    public ClaimAction(string claimType, string valueType)
    {
        ClaimType = claimType;
        ValueType = valueType;
    }>
    public string ClaimType { get; }
    public string ValueType { get; }
    public abstract void Run(JsonElement userData, ClaimsIdentity identity, string issuer);
}

public class DeleteClaimAction : ClaimAction
{
    public DeleteClaimAction(string claimType)
        : base(claimType, ClaimValueTypes.String)
    {
    }

    public override void Run(JsonElement userData, ClaimsIdentity identity, string issuer)
    {
        foreach (var claim in identity.FindAll(ClaimType).ToList())
        {
            identity.TryRemoveClaim(claim);
        }
    }
}

public class JsonKeyClaimAction : ClaimAction
{
    public JsonKeyClaimAction(string claimType, string valueType, string jsonKey) : base(claimType, valueType)
    {
        JsonKey = jsonKey;
    }

    public string JsonKey { get; }

    public override void Run(JsonElement userData, ClaimsIdentity identity, string issuer)
    {
        if (!userData.TryGetProperty(JsonKey, out var value))
        {
            return;
        }
        if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var v in value.EnumerateArray())
            {
                AddClaim(v.ToString()!, identity, issuer);
            }
        }
        else if (value.ValueKind == JsonValueKind.Object || value.ValueKind == JsonValueKind.Undefined)
        {
            // Skip, because they were previously skipped
        }
        else
        {
            AddClaim(value.ToString()!, identity, issuer);
        }
    }

    private protected void AddClaim(string value, ClaimsIdentity identity, string issuer)
    {
        if (!string.IsNullOrEmpty(value))
        {
            identity.AddClaim(new Claim(ClaimType, value, ValueType, issuer));  // <------------------mjk
        }
    }
}
//-------------------------------Ʌ

//--------------------------------V
public class ClaimActionCollection : IEnumerable<ClaimAction>
{
    private IList<ClaimAction> Actions { get; } = new List<ClaimAction>();

    public void Clear() => Actions.Clear();


    public void Remove(string claimType)
    {
        var itemsToRemove = Actions.Where(map => string.Equals(claimType, map.ClaimType, StringComparison.OrdinalIgnoreCase)).ToList();
        itemsToRemove.ForEach(map => Actions.Remove(map));
    }

    public void Add(ClaimAction action)
    {
        Actions.Add(action);
    }

    public IEnumerator<ClaimAction> GetEnumerator()
    {
        return Actions.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return Actions.GetEnumerator();
    }
}
//--------------------------------Ʌ
```

```C#
//-------------------------------------------V
public static class OpenIdConnectResponseType
{
    public const string Code = "code";
    public const string CodeIdToken = "code id_token";
    public const string CodeIdTokenToken = "code id_token token";
    public const string CodeToken = "code token";
    public const string IdToken = "id_token";
    public const string IdTokenToken = "id_token token";
    public const string None = "none";
    public const string Token = "token";
}
//-------------------------------------------Ʌ

//---------------------------------------------V
public static class OpenIdConnectParameterNames
{
    public const string AccessToken = "access_token";
    public const string AcrValues = "acr_values";
    public const string ClaimsLocales = "claims_locales";
    public const string ClientAssertion = "client_assertion";
    public const string ClientAssertionType = "client_assertion_type";
    public const string ClientId = "client_id";
    public const string ClientSecret = "client_secret";
    public const string Code = "code";
    public const string Display = "display";
    public const string DomainHint = "domain_hint";
    public const string Error = "error";
    public const string ErrorDescription = "error_description";
    public const string ErrorUri = "error_uri";
    public const string ExpiresIn = "expires_in";
    public const string GrantType = "grant_type";
    public const string Iss = "iss";
    public const string IdToken = "id_token";
    public const string IdTokenHint = "id_token_hint";
    public const string IdentityProvider = "identity_provider";
    public const string LoginHint = "login_hint";
    public const string MaxAge = "max_age";
    public const string Nonce = "nonce";
    public const string Password = "password";
    public const string PostLogoutRedirectUri = "post_logout_redirect_uri";
    public const string Prompt = "prompt";
    public const string RedirectUri = "redirect_uri";
    public const string RefreshToken = "refresh_token";
    public const string RequestUri = "request_uri";
    public const string Resource = "resource";
    public const string ResponseMode = "response_mode";
    public const string ResponseType = "response_type";
    public const string Scope = "scope";
    public const string SkuTelemetry = "x-client-SKU";
    public const string SessionState = "session_state";
    public const string Sid = "sid";
    public const string State = "state";
    public const string TargetLinkUri = "target_link_uri";
    public const string TokenType = "token_type";
    public const string UiLocales = "ui_locales";
    public const string UserId = "user_id";
    public const string Username = "username";
    public const string VersionTelemetry = "x-client-ver";
}
//---------------------------------------------Ʌ
```

