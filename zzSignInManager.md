```C#
//------------------V
public class Startup
{

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddIdentityCore<AppUser>(opts => // opts is IdentityOptions
        {
            opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        })
        .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
        .AddSignInManager();  // <-----------------------------------------s0

        services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>, AppUserClaimsPrincipalFactory>();
    }
    // ...
}
//------------------Ʌ
```

```C#
//----------------------V
public class SignInModel : PageModel
{
    public SignInModel(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
    {
        UserManager = userManager;
        SignInManager = signInManager;
    }

    public UserManager<AppUser> UserManager { get; set; }
    public SignInManager<AppUser> SignInManager { get; set; }

    // ...

    public async Task<ActionResult> OnPost(string username, [FromQuery] string returnUrl)
    {
        AppUser user = await UserManager.FindByEmailAsync(username);

        await SignInManager.SignInAsync(user, false);  // <--------------------------s1

        // ...
    }
}
//----------------------Ʌ
```


## `SignInManager`

```C#
public class SignInManager<TUser>
{
    private const string LoginProviderKey = "LoginProvider";
    private const string XsrfKey = "XsrfId";
 
    private readonly IHttpContextAccessor _contextAccessor;
    private readonly IAuthenticationSchemeProvider _schemes;
    private readonly IUserConfirmation<TUser> _confirmation;
    private HttpContext? _context;
    private TwoFactorAuthenticationInfo? _twoFactorInfo;

    public SignInManager(
        UserManager<TUser> userManager,  // <-------------------------------------------
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<TUser> claimsFactory,  // <--------------------------DI User-registered,  check code of AppUserClaimsPrincipalFactory
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<TUser>> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<TUser> confirmation)
    {
        UserManager = userManager;
        _contextAccessor = contextAccessor;
        ClaimsFactory = claimsFactory;
        Options = optionsAccessor?.Value ?? new IdentityOptions();
        Logger = logger;
        _schemes = schemes;
        _confirmation = confirmation;
    }

    public virtual ILogger Logger { get; set; }

    public UserManager<TUser> UserManager { get; set; }

    public IUserClaimsPrincipalFactory<TUser> ClaimsFactory { get; set; }

    public IdentityOptions Options { get; set; }

    public string AuthenticationScheme { get; set; } = IdentityConstants.ApplicationScheme;  // "Identity.Application"

    public HttpContext Context
    {
        get {
            var context = _context ?? _contextAccessor?.HttpContext;
            if (context == null)
            {
                throw new InvalidOperationException("HttpContext must not be null.");
            }
            return context;
        }
        set {
            _context = value;
        }
    }

    public virtual async Task<ClaimsPrincipal> CreateUserPrincipalAsync(TUser user)  
    {
        return await ClaimsFactory.CreateAsync(user);  // <-------------------------s1.2.1. create a ClaimsPrincipal based on TUser 
    }

    public virtual bool IsSignedIn(ClaimsPrincipal principal)
    {
        return principal.Identities != null && principal.Identities.Any(i => i.AuthenticationType == AuthenticationScheme);
    }

    public virtual async Task<bool> CanSignInAsync(TUser user)
    {
        if (Options.SignIn.RequireConfirmedEmail && !(await UserManager.IsEmailConfirmedAsync(user)))
        {
            Logger.LogDebug(EventIds.UserCannotSignInWithoutConfirmedEmail, "User cannot sign in without a confirmed email.");
            return false;
        }
        if (Options.SignIn.RequireConfirmedPhoneNumber && !(await UserManager.IsPhoneNumberConfirmedAsync(user)))
        {
            Logger.LogDebug(EventIds.UserCannotSignInWithoutConfirmedPhoneNumber, "User cannot sign in without a confirmed phone number.");
            return false;
        }
        if (Options.SignIn.RequireConfirmedAccount && !(await _confirmation.IsConfirmedAsync(UserManager, user)))  // <---------------------c1
        {
            Logger.LogDebug(EventIds.UserCannotSignInWithoutConfirmedAccount, "User cannot sign in without a confirmed account.");
            return false;
        }
        return true;
    }

    public virtual async Task RefreshSignInAsync(TUser user)
    {
        var auth = await Context.AuthenticateAsync(AuthenticationScheme);
        IList<Claim> claims = Array.Empty<Claim>();
 
        var authenticationMethod = auth?.Principal?.FindFirst(ClaimTypes.AuthenticationMethod);
        var amr = auth?.Principal?.FindFirst("amr");
 
        if (authenticationMethod != null || amr != null)
        {
            claims = new List<Claim>();
            if (authenticationMethod != null)
            {
                claims.Add(authenticationMethod);
            }
            if (amr != null)
            {
                claims.Add(amr);
            }
        }
 
        await SignInWithClaimsAsync(user, auth?.Properties, claims);
    }

    public virtual Task SignInAsync(TUser user, bool isPersistent, string? authenticationMethod = null) // <-----------------s1
        => SignInAsync(user, new AuthenticationProperties { IsPersistent = isPersistent }, authenticationMethod);

    public virtual Task SignInAsync(TUser user, AuthenticationProperties authenticationProperties, string? authenticationMethod = null)
    {
        IList<Claim> additionalClaims = Array.Empty<Claim>();
        if (authenticationMethod != null)
        {
            additionalClaims = new List<Claim>();
            additionalClaims.Add(new Claim(ClaimTypes.AuthenticationMethod, authenticationMethod));
        }
        return SignInWithClaimsAsync(user, authenticationProperties, additionalClaims);
    }

    public virtual Task SignInWithClaimsAsync(TUser user, bool isPersistent, IEnumerable<Claim> additionalClaims)
        => SignInWithClaimsAsync(user, new AuthenticationProperties { IsPersistent = isPersistent }, additionalClaims);

    public virtual async Task SignInWithClaimsAsync(TUser user, AuthenticationProperties? authenticationProperties, IEnumerable<Claim> additionalClaims)  // <------------s1.1
    {
        ClaimsPrincipal userPrincipal = 
            await CreateUserPrincipalAsync(user);  // <-----------------! s1.2 it retrieve some properties from TUser and "convert" those properties into calims,
                                                   // so you can store users info in a database and let UI query only user id and find the user from database then
                                                   // make identity related claims based on TUser                                                                
        foreach (var claim in additionalClaims)
        {
            userPrincipal.Identities.First().AddClaim(claim);
        }

        await Context.SignInAsync(
            AuthenticationScheme,    // <--------------------------s1.3.
            userPrincipal,
            authenticationProperties ?? new AuthenticationProperties());
 
        // This is useful for updating claims immediately when hitting MapIdentityApi's /account/info endpoint with cookies.
        Context.User = userPrincipal;
    }

    public virtual async Task SignOutAsync() // <-------clear "all" (except TwoFactorRememberMeScheme) cookie, it might throw an exception for no handler for the external scheme
    {                                        // when not used properly, the safe alternative is HttpContext.SignOutAsync() which clear the default "Identity.Application" cookie
        await Context.SignOutAsync(AuthenticationScheme);
 
        if (await _schemes.GetSchemeAsync(IdentityConstants.ExternalScheme) != null)
        {
            await Context.SignOutAsync(IdentityConstants.ExternalScheme);
        }
        if (await _schemes.GetSchemeAsync(IdentityConstants.TwoFactorUserIdScheme) != null)
        {
            await Context.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);
        }
    }

    public virtual async Task<TUser?> ValidateSecurityStampAsync(ClaimsPrincipal? principal)
    {
        if (principal == null)
        {
            return null;
        }
        var user = await UserManager.GetUserAsync(principal);
        if (await ValidateSecurityStampAsync(user, principal.FindFirstValue(Options.ClaimsIdentity.SecurityStampClaimType)))
        {
            return user;
        }
        Logger.LogDebug(EventIds.SecurityStampValidationFailedId4, "Failed to validate a security stamp.");
        return null;
    }

    public virtual async Task<TUser?> ValidateTwoFactorSecurityStampAsync(ClaimsPrincipal? principal)
    {
        if (principal == null || principal.Identity?.Name == null)
        {
            return null;
        }
        var user = await UserManager.FindByIdAsync(principal.Identity.Name);
        if (await ValidateSecurityStampAsync(user, principal.FindFirstValue(Options.ClaimsIdentity.SecurityStampClaimType)))
        {
            return user;
        }
        Logger.LogDebug(EventIds.TwoFactorSecurityStampValidationFailed, "Failed to validate a security stamp.");
        return null;
    }

    public virtual async Task<bool> ValidateSecurityStampAsync(TUser? user, string? securityStamp)
        => user != null && (!UserManager.SupportsUserSecurityStamp || securityStamp == await UserManager.GetSecurityStampAsync(user));

    
    // isPersistent indicates cookie used to authenticate requests should not persist when the browser is closed
    public virtual async Task<SignInResult> PasswordSignInAsync(TUser user, string password, bool isPersistent, bool lockoutOnFailure) // <-------------p1
    { 
        SignInResult attempt = await CheckPasswordSignInAsync(user, password, lockoutOnFailure);
        return attempt.Succeeded ? await SignInOrTwoFactorAsync(user, isPersistent) : attempt;
    }

    public virtual async Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
    {
        var user = await UserManager.FindByNameAsync(userName);  // <--------------------------------
        if (user == null)
        {
            return SignInResult.Failed;
        }
 
        return await PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
    }

    public virtual async Task<SignInResult> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure)  // <-------------p2
    { 
        var error = await PreSignInCheck(user);  // <--------------------------p2.1 check whether email, phone num is confirmed then check IsLockedOut
        if (error != null)
        {
            return error;
        }
 
        if (await UserManager.CheckPasswordAsync(user, password))  // <--------------------------------p2.2-
        {
            var alwaysLockout = AppContext.TryGetSwitch("Microsoft.AspNetCore.Identity.CheckPasswordSignInAlwaysResetLockoutOnSuccess", out var enabled) && enabled;
            // Only reset the lockout when not in quirks mode if either TFA is not enabled or the client is remembered for TFA.
            if (alwaysLockout || !await IsTwoFactorEnabledAsync(user) || await IsTwoFactorClientRememberedAsync(user))
            {
                var resetLockoutResult = await ResetLockoutWithResult(user);
                if (!resetLockoutResult.Succeeded)
                {
                    // ResetLockout got an unsuccessful result that could be caused by concurrency failures indicating an
                    // attacker could be trying to bypass the MaxFailedAccessAttempts limit. Return the same failure we do
                    // when failing to increment the lockout to avoid giving an attacker extra guesses at the password.
                    return SignInResult.Failed;
                }
            }
 
            return SignInResult.Success;
        }
        Logger.LogDebug(EventIds.InvalidPassword, "User failed to provide the correct password.");
 
        if (UserManager.SupportsUserLockout && lockoutOnFailure)
        {
            // If lockout is requested, increment access failed count which might lock out the user
            var incrementLockoutResult = await UserManager.AccessFailedAsync(user) ?? IdentityResult.Success;
            if (!incrementLockoutResult.Succeeded)
            {
                // Return the same failure we do when resetting the lockout fails after a correct password.
                return SignInResult.Failed;
            }
 
            if (await UserManager.IsLockedOutAsync(user))
            {
                return await LockedOut(user);
            }
        }
        return SignInResult.Failed;
    }

    public virtual async Task<bool> IsTwoFactorClientRememberedAsync(TUser user)
    {
        if (await _schemes.GetSchemeAsync(IdentityConstants.TwoFactorRememberMeScheme) == null)
        {
            return false;
        }
 
        var userId = await UserManager.GetUserIdAsync(user);
        var result = await Context.AuthenticateAsync(IdentityConstants.TwoFactorRememberMeScheme);
        return (result?.Principal != null && result.Principal.FindFirstValue(ClaimTypes.Name) == userId);
    }

    public virtual async Task RememberTwoFactorClientAsync(TUser user)
    {
        ClaimsPrincipal principal = await StoreRememberClient(user);  // <--------------this principal contains a new ClaimsIdentity(IdentityConstants.TwoFactorRememberMeScheme)
                                                                      // which contains 1. new Claim(ClaimTypes.Name, userId) and 
                                                                      // 2. new Claim(Options.ClaimsIdentity.SecurityStampClaimType, stamp)
        await Context.SignInAsync(IdentityConstants.TwoFactorRememberMeScheme,  // <----------------CookieAuthenticationHandler adds another "remember me" cookie sent to client
            principal,
            new AuthenticationProperties { IsPersistent = true });
    }

    public virtual Task ForgetTwoFactorClientAsync()
    {
        return Context.SignOutAsync(IdentityConstants.TwoFactorRememberMeScheme);
    }

    public virtual async Task<SignInResult> TwoFactorRecoveryCodeSignInAsync(string recoveryCode)  // <-----------this should onlyu be called after users enter credentials
    {
        var twoFactorInfo = await RetrieveTwoFactorInfoAsync();
        if (twoFactorInfo == null)
        {
            return SignInResult.Failed;
        }
 
        var result = await UserManager.RedeemTwoFactorRecoveryCodeAsync(twoFactorInfo.User, recoveryCode); 
        if (result.Succeeded)
        {
            return await DoTwoFactorSignInAsync(twoFactorInfo.User, twoFactorInfo, isPersistent: false, rememberClient: false);
        }
 
        // We don't protect against brute force attacks since codes are expected to be random.
        return SignInResult.Failed;
    }

    private async Task<SignInResult> DoTwoFactorSignInAsync(TUser user, TwoFactorAuthenticationInfo twoFactorInfo, bool isPersistent, bool rememberClient)
    {
        var resetLockoutResult = await ResetLockoutWithResult(user);
        if (!resetLockoutResult.Succeeded)
        {
            // ResetLockout got an unsuccessful result that could be caused by concurrency failures indicating an
            // attacker could be trying to bypass the MaxFailedAccessAttempts limit. Return the same failure we do
            // when failing to increment the lockout to avoid giving an attacker extra guesses at the two factor code.
            return SignInResult.Failed;
        }
 
        var claims = new List<Claim>();

        claims.Add(new Claim("amr", "mfa"));  // <----------------user will still have an amr claim even if they have bypassed the second factor or are configured
                                              // for single-factor sign-ins, but the claim value will be pwd, indicating password-based authentication as
                                              // SignInWithClaimsAsync(user, isPersistent, new Claim[] { new Claim("amr", "pwd") })

        if (twoFactorInfo.LoginProvider != null)
        {
            claims.Add(new Claim(ClaimTypes.AuthenticationMethod, twoFactorInfo.LoginProvider));
        }
        // Cleanup external cookie
        if (await _schemes.GetSchemeAsync(IdentityConstants.ExternalScheme) != null)
        {
            await Context.SignOutAsync(IdentityConstants.ExternalScheme);
        }
        // Cleanup two factor user id cookie
        if (await _schemes.GetSchemeAsync(IdentityConstants.TwoFactorUserIdScheme) != null)
        {
            await Context.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);  // <-------------------clear two factor user id cookie
            if (rememberClient)
            {
                await RememberTwoFactorClientAsync(user);  // <---------calls `Context.SignInAsync(IdentityConstants.TwoFactorRememberMeScheme, principal, ...)`
                /*
                the principal contains a new ClaimsIdentity(IdentityConstants.TwoFactorRememberMeScheme) which contains:
                   1. new Claim(ClaimTypes.Name, userId) and 
                   2. new Claim(Options.ClaimsIdentity.SecurityStampClaimType, stamp)

                so the CookieAuthenticationHandler add this principal into "TwoFactorRememberMeScheme" cookie
                */  
            }
        }
        await SignInWithClaimsAsync(user, isPersistent, claims);  // <------------normal SignIn with IdentityConstants.ApplicationScheme
        return SignInResult.Success;
    }

    public virtual async Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient)
    {
        var twoFactorInfo = await RetrieveTwoFactorInfoAsync();
        if (twoFactorInfo == null)
        {
            return SignInResult.Failed;
        }
 
        var user = twoFactorInfo.User;
        var error = await PreSignInCheck(user);
        if (error != null)
        {
            return error;
        }
 
        if (await UserManager.VerifyTwoFactorTokenAsync(user, Options.Tokens.AuthenticatorTokenProvider, code))
        {
            return await DoTwoFactorSignInAsync(user, twoFactorInfo, isPersistent, rememberClient);
        }
        // If the token is incorrect, record the failure which also may cause the user to be locked out
        if (UserManager.SupportsUserLockout)
        {
            var incrementLockoutResult = await UserManager.AccessFailedAsync(user) ?? IdentityResult.Success;
            if (!incrementLockoutResult.Succeeded)
            {
                // Return the same failure we do when resetting the lockout fails after a correct two factor code.
                // This is currently redundant, but it's here in case the code gets copied elsewhere.
                return SignInResult.Failed;
            }
 
            if (await UserManager.IsLockedOutAsync(user))
            {
                return await LockedOut(user);
            }
        }
        return SignInResult.Failed;
    }

    public virtual async Task<SignInResult> TwoFactorSignInAsync(string provider, string code, bool isPersistent, bool rememberClient) // <----------------------
    {
        var twoFactorInfo = await RetrieveTwoFactorInfoAsync();  // calls Context.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme)
        if (twoFactorInfo == null)
        {
            return SignInResult.Failed;
        }
 
        var user = twoFactorInfo.User;
        var error = await PreSignInCheck(user);
        if (error != null)
        {
            return error;
        }
        if (await UserManager.VerifyTwoFactorTokenAsync(user, provider, code))  // <-----------------------------provider is used to retrieve tokenProvider
        {
            return await DoTwoFactorSignInAsync(user, twoFactorInfo, isPersistent, rememberClient);  // <--------------------------------
        }
        // If the token is incorrect, record the failure which also may cause the user to be locked out
        if (UserManager.SupportsUserLockout)
        {
            var incrementLockoutResult = await UserManager.AccessFailedAsync(user) ?? IdentityResult.Success;
            if (!incrementLockoutResult.Succeeded)
            {
                // Return the same failure we do when resetting the lockout fails after a correct two factor code.
                // This is currently redundant, but it's here in case the code gets copied elsewhere.
                return SignInResult.Failed;
            }
 
            if (await UserManager.IsLockedOutAsync(user))
            {
                return await LockedOut(user);
            }
        }
        return SignInResult.Failed;
    }

    public virtual async Task<TUser?> GetTwoFactorAuthenticationUserAsync()
    {
        TwoFactorAuthenticationInfo info = await RetrieveTwoFactorInfoAsync();
        if (info == null)
        {
            return null;
        }
 
        return info.User;
    }

    public virtual Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent)
        => ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent, bypassTwoFactor: false);

    public virtual async Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent, bool bypassTwoFactor)
    {
        var user = await UserManager.FindByLoginAsync(loginProvider, providerKey);
        if (user == null)
        {
            return SignInResult.Failed;
        }
 
        var error = await PreSignInCheck(user);
        if (error != null)
        {
            return error;
        }
        return await SignInOrTwoFactorAsync(user, isPersistent, loginProvider, bypassTwoFactor);
    }

    public virtual async Task<IEnumerable<AuthenticationScheme>> GetExternalAuthenticationSchemesAsync()  // <----------------
    {
        var schemes = await _schemes.GetAllSchemesAsync();
        return schemes.Where(s => !string.IsNullOrEmpty(s.DisplayName));  // <--------------scheme that has DisplayName is considered as "external" scheme
    }

    public virtual async Task<ExternalLoginInfo?> GetExternalLoginInfoAsync(string? expectedXsrf = null)  // <----------------
    {
        AuthenticateResult auth = await Context.AuthenticateAsync(IdentityConstants.ExternalScheme);  // <------------------
        IDictionary<string, string?> items = auth?.Properties?.Items;   // <-----------------AuthenticationProperties.Items haven't got a provider key/userid yet

        if (auth?.Principal == null || items == null || !items.TryGetValue(LoginProviderKey, out var provider))  // LoginProviderKey is "LoginProvider", don't get it mixed with
        {                                                                                                        // "login provider key" which will be set soon
            return null;
        }
 
        if (expectedXsrf != null)
        {
            if (!items.TryGetValue(XsrfKey, out var userId) ||
                userId != expectedXsrf)
            {
                return null;
            }
        }
 
        var providerKey =  auth.Principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? auth.Principal.FindFirstValue("sub");  // <---------normally get userid as providerKey

        if (providerKey == null || provider == null)
        {
            return null;
        }
 
        var providerDisplayName = (await GetExternalAuthenticationSchemesAsync()).FirstOrDefault(p => p.Name == provider)?.DisplayName ?? provider;
        
        return new ExternalLoginInfo(auth.Principal, provider, providerKey, providerDisplayName)  // <------------pass both provider, provider key and Principal
        {
            AuthenticationTokens = auth.Properties?.GetTokens(),
            AuthenticationProperties = auth.Properties
        };
    }

    public virtual async Task<IdentityResult> UpdateExternalAuthenticationTokensAsync(ExternalLoginInfo externalLogin)
    {
        if (externalLogin.AuthenticationTokens != null && externalLogin.AuthenticationTokens.Any())
        {
            var user = await UserManager.FindByLoginAsync(externalLogin.LoginProvider, externalLogin.ProviderKey);
            if (user == null)
            {
                return IdentityResult.Failed();
            }
 
            foreach (var token in externalLogin.AuthenticationTokens)
            {
                var result = await UserManager.SetAuthenticationTokenAsync(user, externalLogin.LoginProvider, token.Name, token.Value);
                if (!result.Succeeded)
                {
                    return result;
                }
            }
        }
 
        return IdentityResult.Success;
    }

    public virtual AuthenticationProperties ConfigureExternalAuthenticationProperties(string? provider, string? redirectUrl, string? userId = null)
    {
        var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
        properties.Items[LoginProviderKey] = provider;
        if (userId != null)
        {
            properties.Items[XsrfKey] = userId;
        }
        return properties;
    }

    internal async Task<ClaimsPrincipal> StoreRememberClient(TUser user)
    {
        var userId = await UserManager.GetUserIdAsync(user);
        var rememberBrowserIdentity = new ClaimsIdentity(IdentityConstants.TwoFactorRememberMeScheme);
        rememberBrowserIdentity.AddClaim(new Claim(ClaimTypes.Name, userId));
        if (UserManager.SupportsUserSecurityStamp)
        {
            var stamp = await UserManager.GetSecurityStampAsync(user);
            rememberBrowserIdentity.AddClaim(new Claim(Options.ClaimsIdentity.SecurityStampClaimType, stamp));
        }
        return new ClaimsPrincipal(rememberBrowserIdentity);
    }

    public virtual async Task<bool> IsTwoFactorEnabledAsync(TUser user)
        => UserManager.SupportsUserTwoFactor && await UserManager.GetTwoFactorEnabledAsync(user) && (await UserManager.GetValidTwoFactorProvidersAsync(user)).Count > 0;

    protected virtual async Task<SignInResult> SignInOrTwoFactorAsync(TUser user, bool isPersistent, string? loginProvider = null, bool bypassTwoFactor = false)
    {
        if (!bypassTwoFactor && await IsTwoFactorEnabledAsync(user))
        {
            // bypass mfa by calling Context.AuthenticateAsync(IdentityConstants.TwoFactorRememberMeScheme) which reads the cookie
            if (!await IsTwoFactorClientRememberedAsync(user))  // <------------------------------------------
            {
                _twoFactorInfo = new()
                {
                    User = user,
                    LoginProvider = loginProvider,
                };
 
                if (await _schemes.GetSchemeAsync(IdentityConstants.TwoFactorUserIdScheme) != null)
                {
                    // Store the userId for use after two factor check
                    var userId = await UserManager.GetUserIdAsync(user);

                    /* 
                       StoreTwoFactorInfo generates a limited subsut of claims which only contains:
                           new Claim(ClaimTypes.Name, userId) and optional new Claim(ClaimTypes.AuthenticationMethod, loginProvider)
                      
                       while a normal non-mfa SignIns like SignInWithClaimsAsync gererats full claims by calling:
                           Context.SignInAsync(AuthenticationScheme, ...)  where AuthenticationScheme is IdentityConstants.ApplicationScheme (i.e "Identity.Application")
                    */
                    await Context.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, StoreTwoFactorInfo(userId, loginProvider));  // <--------add userId as a claim 
                    // and make CookieAuthenticationHandler to generate a cookie based on it, so that userId can be retrieved in the request (token input page) 
                }
 
                return SignInResult.TwoFactorRequired;
            }
        }
        // Cleanup external cookie
        if (loginProvider != null)
        {
            await Context.SignOutAsync(IdentityConstants.ExternalScheme);
        }
        if (loginProvider == null)
        {
            await SignInWithClaimsAsync(user, isPersistent, new Claim[] { new Claim("amr", "pwd") });  // <-------------most of SignIns and bypassTwoFactor fall into here
        }
        else
        {
            await SignInAsync(user, isPersistent, loginProvider);
        }
        return SignInResult.Success;
    }

    internal static ClaimsPrincipal StoreTwoFactorInfo(string userId, string? loginProvider)
    {
        var identity = new ClaimsIdentity(IdentityConstants.TwoFactorUserIdScheme);
        identity.AddClaim(new Claim(ClaimTypes.Name, userId));
        if (loginProvider != null)
        {
            identity.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, loginProvider));  // <--------------AuthenticationMethod can be external IAuthenticationHandler's scheme
        }
        return new ClaimsPrincipal(identity);
    }

    private async Task<TwoFactorAuthenticationInfo?> RetrieveTwoFactorInfoAsync()
    {
        /* .NET 8
        if (_twoFactorInfo != null)
        {
            return _twoFactorInfo;
        }
        */
 
        var result = await Context.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);  // <-------------for cookie authentication, the client sends userId cookie created 
                                                                                                // in SignInOrTwoFactorAsync so CookieAuthenticationHandler can generate a
                                                                                                // ClaimsPrincipal only contains new Claim(ClaimTypes.Name, userId)
        if (result?.Principal == null)
        {
            return null;
        }
 
        var userId = result.Principal.FindFirstValue(ClaimTypes.Name);
        if (userId == null)
        {
            return null;
        }
 
        var user = await UserManager.FindByIdAsync(userId);
        if (user == null)
        {
            return null;
        }
 
        return new TwoFactorAuthenticationInfo
        {
            User = user,
            LoginProvider = result.Principal.FindFirstValue(ClaimTypes.AuthenticationMethod),
        };
    }

    protected virtual async Task<bool> IsLockedOut(TUser user)
    {
        return UserManager.SupportsUserLockout && await UserManager.IsLockedOutAsync(user);
    }

    protected virtual Task<SignInResult> LockedOut(TUser user)
    {
        return Task.FromResult(SignInResult.LockedOut);
    }

    protected virtual async Task<SignInResult?> PreSignInCheck(TUser user)
    {
        if (!await CanSignInAsync(user))
            return SignInResult.NotAllowed;

        if (await IsLockedOut(user))
            return await LockedOut(user);

        return null;
    }

    protected virtual async Task ResetLockout(TUser user)
    {
        if (UserManager.SupportsUserLockout)
        {
            // The IdentityResult should not be null according to the annotations, but our own tests return null and I'm trying to limit breakages.
            var result = await UserManager.ResetAccessFailedCountAsync(user) ?? IdentityResult.Success;
 
            if (!result.Succeeded)
                throw new IdentityResultException(result);
        }
    }

    private async Task<IdentityResult> ResetLockoutWithResult(TUser user)
    {
        // Avoid relying on throwing an exception if we're not in a derived class.
        if (GetType() == typeof(SignInManager<TUser>))
        {
            if (!UserManager.SupportsUserLockout)
            {
                return IdentityResult.Success;
            }
 
            return await UserManager.ResetAccessFailedCountAsync(user) ?? IdentityResult.Success;
        }
 
        try
        {
            var resetLockoutTask = ResetLockout(user);
 
            if (resetLockoutTask is Task<IdentityResult> resultTask)
            {
                return await resultTask ?? IdentityResult.Success;
            }
 
            await resetLockoutTask;
            return IdentityResult.Success;
        }
        catch (IdentityResultException ex)
        {
            return ex.IdentityResult;
        }
    }

    private sealed class IdentityResultException : Exception
    {
        internal IdentityResultException(IdentityResult result) : base()
        {
            IdentityResult = result;
        }
 
        internal IdentityResult IdentityResult { get; set; }
 
        public override string Message
        {
            get
            {
                var sb = new StringBuilder("ResetLockout failed.");
 
                foreach (var error in IdentityResult.Errors)
                {
                    sb.AppendLine();
                    sb.Append(error.Code);
                    sb.Append(": ");
                    sb.Append(error.Description);
                }
 
                return sb.ToString();
            }
        }
    }
 
    internal sealed class TwoFactorAuthenticationInfo
    {
        public required TUser User { get; init; }
        public string? LoginProvider { get; init; }
    }
}
```


```C#
//-----------------------V
public class SignInResult
{
    private static readonly SignInResult _success = new SignInResult { Succeeded = true };
    private static readonly SignInResult _failed = new SignInResult();
    private static readonly SignInResult _lockedOut = new SignInResult { IsLockedOut = true };
    private static readonly SignInResult _notAllowed = new SignInResult { IsNotAllowed = true };
    private static readonly SignInResult _twoFactorRequired = new SignInResult { RequiresTwoFactor = true };
 
    public bool Succeeded { get; protected set; }
    public bool IsLockedOut { get; protected set; }
    public bool IsNotAllowed { get; protected set; }
    public bool RequiresTwoFactor { get; protected set; }
    public static SignInResult Success => _success;
    public static SignInResult Failed => _failed;
    public static SignInResult LockedOut => _lockedOut;
    public static SignInResult NotAllowed => _notAllowed;
    public static SignInResult TwoFactorRequired => _twoFactorRequired;

    public override string ToString()
    {
        return IsLockedOut ? "LockedOut" :
               IsNotAllowed ? "NotAllowed" :
               RequiresTwoFactor ? "RequiresTwoFactor" :
               Succeeded ? "Succeeded" : "Failed";
    }
}
//-----------------------Ʌ

//----------------------------------V
public partial class ChallengeResult : ActionResult
{
    public ChallengeResult() : this(Array.Empty<string>()) { } 
    public ChallengeResult(string authenticationScheme) : this(new[] { authenticationScheme }) { }
    public ChallengeResult(string authenticationScheme, AuthenticationProperties? properties) : this(new[] { authenticationScheme }, properties) { }
    public ChallengeResult(IList<string> authenticationSchemes) : this(authenticationSchemes, properties: null) { }
    // ...
    public ChallengeResult(IList<string> authenticationSchemes, AuthenticationProperties? properties) 
    {
        AuthenticationSchemes = authenticationSchemes;
        Properties = properties;
    }

    public IList<string> AuthenticationSchemes { get; set; }
    public AuthenticationProperties? Properties { get; set; }

    public override async Task ExecuteResultAsync(ActionContext context)
    {
        var httpContext = context.HttpContext;
        // ...

        if (AuthenticationSchemes != null && AuthenticationSchemes.Count > 0)
        {
            foreach (var scheme in AuthenticationSchemes)
            {
                await httpContext.ChallengeAsync(scheme, Properties);
            }
        }
        else
        {
            await httpContext.ChallengeAsync(Properties);
        }
    }
}
//----------------------------------Ʌ

//------------------------V
public class UserLoginInfo
{
    public UserLoginInfo(string loginProvider, string providerKey, string? displayName)
    {
        LoginProvider = loginProvider;
        ProviderKey = providerKey;
        ProviderDisplayName = displayName;
    }

    public string LoginProvider { get; set; }
    public string ProviderKey { get; set; }
    public string? ProviderDisplayName { get; set; }  // Examples of the display name may be "local", "FACEBOOK", "Google", etc
}
//------------------------Ʌ

//----------------------------V
public class ExternalLoginInfo : UserLoginInfo 
{
    public ExternalLoginInfo(ClaimsPrincipal principal, string loginProvider, string providerKey, string displayName) : base(loginProvider, providerKey, displayName)
    {
        Principal = principal;
    }

    public ClaimsPrincipal Principal { get; set; }

    public IEnumerable<AuthenticationToken>? AuthenticationTokens { get; set; }

    public AuthenticationProperties? AuthenticationProperties { get; set; }
}
//----------------------------Ʌ
```