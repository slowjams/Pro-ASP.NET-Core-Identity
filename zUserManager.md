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
        .AddSignInManager();  // <--------------------------------------

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

        await SignInManager.SignInAsync(user, false);  // <--------------------------

        // ...
    }
}
//----------------------Ʌ
```


## `UserManager` 

```C#
//-------------------------------------------V
public class UserManager<TUser> : IDisposable
{
    public const string ResetPasswordTokenPurpose = "ResetPassword";

    public const string ChangePhoneNumberTokenPurpose = "ChangePhoneNumber";

    public const string ConfirmEmailTokenPurpose = "EmailConfirmation";

    private readonly Dictionary<string, IUserTwoFactorTokenProvider<TUser>> _tokenProviders =   // <---------------------------------t2.0
        new Dictionary<string, IUserTwoFactorTokenProvider<TUser>>();

    private readonly IServiceProvider _services;

    protected virtual CancellationToken CancellationToken => CancellationToken.None;

    //
    protected internal IUserStore<TUser> Store { get; set; }  // <------------------------ DI
    public virtual ILogger Logger { get; set; }
    public IPasswordHasher<TUser> PasswordHasher { get; set; }
    public IList<IUserValidator<TUser>> UserValidators { get; } = new List<IUserValidator<TUser>>();
    public IList<IPasswordValidator<TUser>> PasswordValidators { get; } = new List<IPasswordValidator<TUser>>();
    public ILookupNormalizer KeyNormalizer { get; set; }
    public IdentityErrorDescriber ErrorDescriber { get; set; }
    public IdentityOptions Options { get; set; }  // <------------------------------------ DI
    //

    public UserManager(
        IUserStore<TUser> store,  // <------------------------------------
        IOptions<IdentityOptions> optionsAccessor, 
        IPasswordHasher<TUser> passwordHasher, 
        IEnumerable<IUserValidator<TUser>> userValidators, 
        IEnumerable<IPasswordValidator<TUser>> passwordValidators, 
        ILookupNormalizer keyNormalizer, 
        IdentityErrorDescriber errors, 
        IServiceProvider services,  
        ILogger<UserManager<TUser>> logger)
    {
        Store = store;
        Options = optionsAccessor?.Value ?? new IdentityOptions();
        PasswordHasher = passwordHasher;
        KeyNormalizer = keyNormalizer;
        ErrorDescriber = errors;
        Logger = logger;
 
        if (userValidators != null)
        {
            foreach (var v in userValidators)
                UserValidators.Add(v);
        }

        if (passwordValidators != null)
        {
            foreach (var v in passwordValidators)
                PasswordValidators.Add(v);
        }
 
        _services = services;

        if (services != null)
        {
            foreach (var providerName in Options.Tokens.ProviderMap.Keys)
            {
                var description = Options.Tokens.ProviderMap[providerName];
 
                var provider = description.ProviderInstance as IUserTwoFactorTokenProvider<TUser>;
                if (provider == null && description.GetProviderType<IUserTwoFactorTokenProvider<TUser>>() is Type providerType)
                {
                    provider = (IUserTwoFactorTokenProvider<TUser>)services.GetRequiredService(providerType);  // <---------------t2.1 retrieve token providers here
                }                                                                                              //  so you don't need to setup DI in startup.cs
 
                if (provider != null)
                {
                    RegisterTokenProvider(providerName, provider);  // <------------------------t2.2
                }
            }
        }
 
        // ...
    }

    // simplified, all have ThrowIfDisposed();
    public virtual bool SupportsUserAuthenticationTokens => Store is IUserAuthenticationTokenStore<TUser>;
    public virtual bool SupportsUserAuthenticatorKey => Store is IUserAuthenticatorKeyStore<TUser>;
    public virtual bool SupportsUserTwoFactorRecoveryCodes => Store is IUserTwoFactorRecoveryCodeStore<TUser>;
    public virtual bool SupportsUserTwoFactor => Store is IUserTwoFactorStore<TUser>;
    public virtual bool SupportsUserPassword => Store is IUserPasswordStore<TUser>;
    public virtual bool SupportsUserSecurityStamp => Store is IUserSecurityStampStore<TUser>;
    public virtual bool SupportsUserRole => Store is   <TUser>;
    public virtual bool SupportsUserLogin => Store is IUserLoginStore<TUser>;
    public virtual bool SupportsUserEmail => Store is IUserEmailStore<TUser>;
    public virtual bool SupportsUserPhoneNumber => Store is IUserPhoneNumberStore<TUser>;
    public virtual bool SupportsUserClaim => Store is IUserClaimStore<TUser>;
    public virtual bool SupportsUserLockout => Store is IUserLockoutStore<TUser>;
    public virtual bool SupportsQueryableUsers => Store is IQueryableUserStore<TUser>;   // <-----------------------------
    //

    public virtual IQueryable<TUser> Users
    {
        get {
            var queryableStore = Store as IQueryableUserStore<TUser>;
            if (queryableStore == null)
                throw new NotSupportedException(Resources.StoreNotIQueryableUserStore);
            return queryableStore.Users;
        }
    }

    public virtual string? GetUserName(ClaimsPrincipal principal) => principal.FindFirstValue(Options.ClaimsIdentity.UserNameClaimType);

    public virtual string? GetUserId(ClaimsPrincipal principal) => principal.FindFirstValue(Options.ClaimsIdentity.UserIdClaimType);

    public virtual Task<TUser?> GetUserAsync(ClaimsPrincipal principal)
    {
        var id = GetUserId(principal);
        return id == null ? Task.FromResult<TUser?>(null) : FindByIdAsync(id);
    }

    public virtual Task<string> GenerateConcurrencyStampAsync(TUser user) => Task.FromResult(Guid.NewGuid().ToString());

    public virtual async Task<IdentityResult> CreateAsync(TUser user)  // <-----------------------------------------!
    {
        await UpdateSecurityStampInternal(user).ConfigureAwait(false);
        
        var result = await ValidateUserAsync(user).ConfigureAwait(false);
        
        if (!result.Succeeded)
        {
            return result;
        }
        
        if (Options.Lockout.AllowedForNewUsers && SupportsUserLockout)
        {
            await GetUserLockoutStore().SetLockoutEnabledAsync(user, true, CancellationToken).ConfigureAwait(false);
        }
        
        await UpdateNormalizedUserNameAsync(user).ConfigureAwait(false);
        await UpdateNormalizedEmailAsync(user).ConfigureAwait(false);
 
        return await Store.CreateAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual Task<IdentityResult> UpdateAsync(TUser user) => UpdateUserAsync(user);
    public virtual Task<IdentityResult> DeleteAsync(TUser user) => Store.DeleteAsync(user, CancellationToken);
    public virtual Task<TUser?> FindByIdAsync(string userId) => Store.FindByIdAsync(userId, CancellationToken);

    public virtual async Task<TUser?> FindByNameAsync(string userName)
    {
        userName = NormalizeName(userName);
 
        var user = await Store.FindByNameAsync(userName, CancellationToken).ConfigureAwait(false);
 
        // Need to potentially check all keys
        if (user == null && Options.Stores.ProtectPersonalData)
        {
            var keyRing = _services.GetService<ILookupProtectorKeyRing>();
            var protector = _services.GetService<ILookupProtector>();
            if (keyRing != null && protector != null)
            {
                foreach (var key in keyRing.GetAllKeyIds())
                {
                    var oldKey = protector.Protect(key, userName);
                    user = await Store.FindByNameAsync(oldKey, CancellationToken).ConfigureAwait(false);
                    if (user != null)
                    {
                        return user;
                    }
                }
            }
        }

        return user;
    }

    public virtual async Task<IdentityResult> CreateAsync(TUser user, string password)
    {
        var passwordStore = GetPasswordStore();

        var result = await UpdatePasswordHash(passwordStore, user, password).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return result;
        }

        return await CreateAsync(user).ConfigureAwait(false);
    }

    public virtual string? NormalizeName(string? name) => (KeyNormalizer == null) ? name : KeyNormalizer.NormalizeName(name);

    public virtual string? NormalizeEmail(string? email) => (KeyNormalizer == null) ? email : KeyNormalizer.NormalizeEmail(email);

    public virtual async Task UpdateNormalizedUserNameAsync(TUser user);
    
    public virtual async Task<string?> GetUserNameAsync(TUser user)
    {
        return await Store.GetUserNameAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> SetUserNameAsync(TUser user, string? userName)
    { 
        await Store.SetUserNameAsync(user, userName, CancellationToken).ConfigureAwait(false);
        await UpdateSecurityStampInternal(user).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<string> GetUserIdAsync(TUser user)
    {
        return await Store.GetUserIdAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual async Task<bool> CheckPasswordAsync(TUser user, string password)   // <-------------------p2.2-
    {
        var passwordStore = GetPasswordStore();
        
        if (user == null)
        {
            return false;
        }
 
        var result = await VerifyPasswordAsync(passwordStore, user, password).ConfigureAwait(false);   // <-------------------p2.3-
        
        if (result == PasswordVerificationResult.SuccessRehashNeeded)
        {
            await UpdatePasswordHash(passwordStore, user, password, validatePassword: false).ConfigureAwait(false);  // <-----------------p2.4-
            await UpdateUserAsync(user).ConfigureAwait(false);
        }
 
        var success = result != PasswordVerificationResult.Failed;
        
        if (!success)
        {
            Logger.LogDebug(LoggerEventIds.InvalidPassword, "Invalid password for user.");
        }

        return success;
    }

    public virtual Task<bool> HasPasswordAsync(TUser user)
    {
        var passwordStore = GetPasswordStore();
        return passwordStore.HasPasswordAsync(user, CancellationToken);
    }

    public virtual async Task<IdentityResult> AddPasswordAsync(TUser user, string password)
    {
        var passwordStore = GetPasswordStore();
 
        var hash = await passwordStore.GetPasswordHashAsync(user, CancellationToken).ConfigureAwait(false);
        
        if (hash != null)
        {
            Logger.LogDebug(LoggerEventIds.UserAlreadyHasPassword, "User already has a password.");
            return IdentityResult.Failed(ErrorDescriber.UserAlreadyHasPassword());
        }
        
        var result = await UpdatePasswordHash(passwordStore, user, password).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return result;
        }
        
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }
    
    public virtual async Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword)
    {
        var passwordStore = GetPasswordStore();
 
        if (await VerifyPasswordAsync(passwordStore, user, currentPassword).ConfigureAwait(false) != PasswordVerificationResult.Failed)
        {
            var result = await UpdatePasswordHash(passwordStore, user, newPassword).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                return result;
            }
            return await UpdateUserAsync(user).ConfigureAwait(false);
        }

        Logger.LogDebug(LoggerEventIds.ChangePasswordFailed, "Change password failed for user.");
        
        return IdentityResult.Failed(ErrorDescriber.PasswordMismatch());
    }

    public virtual async Task<IdentityResult> RemovePasswordAsync(TUser user)
    {
        var passwordStore = GetPasswordStore();
 
        await UpdatePasswordHash(passwordStore, user, null, validatePassword: false).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    protected virtual async Task<PasswordVerificationResult> VerifyPasswordAsync(IUserPasswordStore<TUser> store, TUser user, string password)  // <-------p2.3
    {
        var hash = await store.GetPasswordHashAsync(user, CancellationToken).ConfigureAwait(false);   // <-----------------------p2.3.1
        if (hash == null)
        {
            return PasswordVerificationResult.Failed;
        }
        return PasswordHasher.VerifyHashedPassword(user, hash, password);   // <-----------------------p2.3.2.
    }

    public virtual async Task<string> GetSecurityStampAsync(TUser user)
    {
        var securityStore = GetSecurityStore();
        var stamp = await securityStore.GetSecurityStampAsync(user, CancellationToken).ConfigureAwait(false);
        if (stamp == null)
        {
            Logger.LogDebug(LoggerEventIds.GetSecurityStampFailed, "GetSecurityStampAsync for user failed because stamp was null.");
            throw new InvalidOperationException(Resources.NullSecurityStamp);
        }
        return stamp;
    }

    public virtual async Task<IdentityResult> UpdateSecurityStampAsync(TUser user)
    {
        GetSecurityStore();
 
        await UpdateSecurityStampInternal(user).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual Task<string> GeneratePasswordResetTokenAsync(TUser user)
    {
        return GenerateUserTokenAsync(user, Options.Tokens.PasswordResetTokenProvider, ResetPasswordTokenPurpose);
    }

    public virtual async Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword)  // <---------------------------
    { 
        // Make sure the token is valid and the stamp matches
        if (!await VerifyUserTokenAsync(user, Options.Tokens.PasswordResetTokenProvider, ResetPasswordTokenPurpose, token).ConfigureAwait(false))
        {
            return IdentityResult.Failed(ErrorDescriber.InvalidToken());
        }

        var result = await UpdatePasswordHash(user, newPassword, validatePassword: true).ConfigureAwait(false);
        
        if (!result.Succeeded)
        {
            return result;
        }

        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual Task<TUser?> FindByLoginAsync(string loginProvider, string providerKey)
    {
        var loginStore = GetLoginStore();

        return loginStore.FindByLoginAsync(loginProvider, providerKey, CancellationToken);
    }

    public virtual async Task<IdentityResult> RemoveLoginAsync(TUser user, string loginProvider, string providerKey)
    {
        var loginStore = GetLoginStore();
 
        await loginStore.RemoveLoginAsync(user, loginProvider, providerKey, CancellationToken).ConfigureAwait(false);
        await UpdateSecurityStampInternal(user).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> AddLoginAsync(TUser user, UserLoginInfo login)
    {
        var loginStore = GetLoginStore();
 
        var existingUser = await FindByLoginAsync(login.LoginProvider, login.ProviderKey).ConfigureAwait(false);
        
        if (existingUser != null)
        {
            Logger.LogDebug(LoggerEventIds.AddLoginFailed, "AddLogin for user failed because it was already associated with another user.");
            return IdentityResult.Failed(ErrorDescriber.LoginAlreadyAssociated());
        }

        await loginStore.AddLoginAsync(user, login, CancellationToken).ConfigureAwait(false);
        
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
    {
        var loginStore = GetLoginStore();

        return await loginStore.GetLoginsAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual Task<IdentityResult> AddClaimAsync(TUser user, Claim claim)
    {
        GetClaimStore();

        return AddClaimsAsync(user, new Claim[] { claim });
    }

    public virtual async Task<IdentityResult> AddClaimsAsync(TUser user, IEnumerable<Claim> claims)
    {
        var claimStore = GetClaimStore();
 
        await claimStore.AddClaimsAsync(user, claims, CancellationToken).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim)
    {
        var claimStore = GetClaimStore();
 
        await claimStore.ReplaceClaimAsync(user, claim, newClaim, CancellationToken).ConfigureAwait(false);
        
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual Task<IdentityResult> RemoveClaimAsync(TUser user, Claim claim)
    {
        GetClaimStore();
        return RemoveClaimsAsync(user, new Claim[] { claim });
    }

    public virtual async Task<IdentityResult> RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims)
    {
        var claimStore = GetClaimStore();
 
        await claimStore.RemoveClaimsAsync(user, claims, CancellationToken).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<IList<Claim>> GetClaimsAsync(TUser user)
    {
        var claimStore = GetClaimStore();

        return await claimStore.GetClaimsAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> AddToRoleAsync(TUser user, string role)
    {
        var userRoleStore = GetUserRoleStore();
 
        var normalizedRole = NormalizeName(role);
        
        if (await userRoleStore.IsInRoleAsync(user, normalizedRole, CancellationToken).ConfigureAwait(false))
        {
            return UserAlreadyInRoleError(role);
        }

        await userRoleStore.AddToRoleAsync(user, normalizedRole, CancellationToken).ConfigureAwait(false);
        
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> AddToRolesAsync(TUser user, IEnumerable<string> roles)
    {
        var userRoleStore = GetUserRoleStore();
 
        foreach (var role in roles.Distinct())
        {
            var normalizedRole = NormalizeName(role);
            if (await userRoleStore.IsInRoleAsync(user, normalizedRole, CancellationToken).ConfigureAwait(false))
            {
                return UserAlreadyInRoleError(role);
            }
            await userRoleStore.AddToRoleAsync(user, normalizedRole, CancellationToken).ConfigureAwait(false);
        }

        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> RemoveFromRoleAsync(TUser user, string role)
    {
        var userRoleStore = GetUserRoleStore();
 
        var normalizedRole = NormalizeName(role);
        
        if (!await userRoleStore.IsInRoleAsync(user, normalizedRole, CancellationToken).ConfigureAwait(false))
        {
            return UserNotInRoleError(role);
        }

        await userRoleStore.RemoveFromRoleAsync(user, normalizedRole, CancellationToken).ConfigureAwait(false);
        
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    private IdentityResult UserAlreadyInRoleError(string role)
    {
        if (Logger.IsEnabled(LogLevel.Debug))
        {
            Logger.LogDebug(LoggerEventIds.UserAlreadyInRole, "User is already in role {role}.", role);
        }
        return IdentityResult.Failed(ErrorDescriber.UserAlreadyInRole(role));
    }
 
    private IdentityResult UserNotInRoleError(string role)
    {
        if (Logger.IsEnabled(LogLevel.Debug))
        {
            Logger.LogDebug(LoggerEventIds.UserNotInRole, "User is not in role {role}.", role);
        }
        return IdentityResult.Failed(ErrorDescriber.UserNotInRole(role));
    }

    public virtual async Task<IdentityResult> RemoveFromRolesAsync(TUser user, IEnumerable<string> roles)
    {
        var userRoleStore = GetUserRoleStore();
 
        foreach (var role in roles)
        {
            var normalizedRole = NormalizeName(role);
            if (!await userRoleStore.IsInRoleAsync(user, normalizedRole, CancellationToken).ConfigureAwait(false))
            {
                return UserNotInRoleError(role);
            }
            await userRoleStore.RemoveFromRoleAsync(user, normalizedRole, CancellationToken).ConfigureAwait(false);
        }

        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<IList<string>> GetRolesAsync(TUser user)
    {
        var userRoleStore = GetUserRoleStore();
        return await userRoleStore.GetRolesAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual async Task<bool> IsInRoleAsync(TUser user, string role)
    {
        var userRoleStore = GetUserRoleStore();
        return await userRoleStore.IsInRoleAsync(user, NormalizeName(role), CancellationToken).ConfigureAwait(false);
    }

    public virtual async Task<string?> GetEmailAsync(TUser user)
    {
        var store = GetEmailStore();
        return await store.GetEmailAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> SetEmailAsync(TUser user, string? email)
    {
        var store = GetEmailStore();
 
        await store.SetEmailAsync(user, email, CancellationToken).ConfigureAwait(false);
        await store.SetEmailConfirmedAsync(user, false, CancellationToken).ConfigureAwait(false);
        await UpdateSecurityStampInternal(user).ConfigureAwait(false);
        
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<TUser?> FindByEmailAsync(string email)
    {
        var store = GetEmailStore();
 
        email = NormalizeEmail(email);
        var user = await store.FindByEmailAsync(email, CancellationToken).ConfigureAwait(false);
 
        // Need to potentially check all keys
        if (user == null && Options.Stores.ProtectPersonalData)
        {
            var keyRing = _services.GetService<ILookupProtectorKeyRing>();
            var protector = _services.GetService<ILookupProtector>();
            if (keyRing != null && protector != null)
            {
                foreach (var key in keyRing.GetAllKeyIds())
                {
                    var oldKey = protector.Protect(key, email);
                    user = await store.FindByEmailAsync(oldKey, CancellationToken).ConfigureAwait(false);
                    if (user != null)
                    {
                        return user;
                    }
                }
            }
        }
        return user;
    }

    public virtual async Task UpdateNormalizedEmailAsync(TUser user)
    {
        var store = GetOptionalEmailStore();
        if (store != null)
        {
            var email = await GetEmailAsync(user).ConfigureAwait(false);
            await store.SetNormalizedEmailAsync(user, ProtectPersonalData(NormalizeEmail(email)!), CancellationToken).ConfigureAwait(false);
        }
    }

    public virtual Task<string> GenerateEmailConfirmationTokenAsync(TUser user)
    {
        return GenerateUserTokenAsync(user, Options.Tokens.EmailConfirmationTokenProvider, ConfirmEmailTokenPurpose);
    }

    public virtual async Task<IdentityResult> ConfirmEmailAsync(TUser user, string token)
    {
        var store = GetEmailStore();
 
        if (!await VerifyUserTokenAsync(user, Options.Tokens.EmailConfirmationTokenProvider, ConfirmEmailTokenPurpose, token).ConfigureAwait(false))
        {
            return IdentityResult.Failed(ErrorDescriber.InvalidToken());
        }

        await store.SetEmailConfirmedAsync(user, true, CancellationToken).ConfigureAwait(false);
        
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<bool> IsEmailConfirmedAsync(TUser user)
    {
        var store = GetEmailStore();
       
        return await store.GetEmailConfirmedAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> ChangeEmailAsync(TUser user, string newEmail, string token)  // <------------t4.0 user enter token on UI and submit
    { 
        // Make sure the token is valid and the stamp matches
        if (!await VerifyUserTokenAsync(user, Options.Tokens.ChangeEmailTokenProvider, GetChangeEmailTokenPurpose(newEmail), token).ConfigureAwait(false))
        {
            return IdentityResult.Failed(ErrorDescriber.InvalidToken());
        }

        var store = GetEmailStore();
        await store.SetEmailAsync(user, newEmail, CancellationToken).ConfigureAwait(false);  // <-----------------------t4.2
        await store.SetEmailConfirmedAsync(user, true, CancellationToken).ConfigureAwait(false);
        await UpdateSecurityStampInternal(user).ConfigureAwait(false);  // <-----------------------t4.3
        
        return await UpdateUserAsync(user).ConfigureAwait(false);  // <-----------------------t4.4
    }

    public virtual async Task<string?> GetPhoneNumberAsync(TUser user)
    {
        var store = GetPhoneNumberStore();
        
        return await store.GetPhoneNumberAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> SetPhoneNumberAsync(TUser user, string? phoneNumber)
    {
        var store = GetPhoneNumberStore();
 
        await store.SetPhoneNumberAsync(user, phoneNumber, CancellationToken).ConfigureAwait(false);
        await store.SetPhoneNumberConfirmedAsync(user, false, CancellationToken).ConfigureAwait(false);
        await UpdateSecurityStampInternal(user).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> ChangePhoneNumberAsync(TUser user, string phoneNumber, string token)
    {
        var store = GetPhoneNumberStore();
 
        if (!await VerifyChangePhoneNumberTokenAsync(user, token, phoneNumber).ConfigureAwait(false))
        {
            Logger.LogDebug(LoggerEventIds.PhoneNumberChanged, "Change phone number for user failed with invalid token.");
            return IdentityResult.Failed(ErrorDescriber.InvalidToken());
        }

        await store.SetPhoneNumberAsync(user, phoneNumber, CancellationToken).ConfigureAwait(false);
        await store.SetPhoneNumberConfirmedAsync(user, true, CancellationToken).ConfigureAwait(false);
        await UpdateSecurityStampInternal(user).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual Task<bool> IsPhoneNumberConfirmedAsync(TUser user)
    {
        var store = GetPhoneNumberStore();
        return store.GetPhoneNumberConfirmedAsync(user, CancellationToken);
    }

    public static string GetChangeEmailTokenPurpose(string newEmail) => "ChangeEmail:" + newEmail;

    public virtual Task<string> GenerateChangeEmailTokenAsync(TUser user, string newEmail)  // <-----------------------t3
    {
        return GenerateUserTokenAsync(user, Options.Tokens.ChangeEmailTokenProvider, GetChangeEmailTokenPurpose(newEmail));
    }

    public virtual Task<string> GenerateChangePhoneNumberTokenAsync(TUser user, string phoneNumber)
    {
        return GenerateUserTokenAsync(user, Options.Tokens.ChangePhoneNumberTokenProvider, ChangePhoneNumberTokenPurpose + ":" + phoneNumber);
    }

    public virtual Task<string> GenerateUserTokenAsync(TUser user, string tokenProvider, string purpose)  // <----------------------t3.1.
    { 
        if (!_tokenProviders.TryGetValue(tokenProvider, out var provider))
            throw new NotSupportedException(Resources.FormatNoTokenProvider(nameof(TUser), tokenProvider));
 
        return provider.GenerateAsync(purpose, this, user);  // <----------------------t3.1.
    }

    public virtual Task<bool> VerifyChangePhoneNumberTokenAsync(TUser user, string token, string phoneNumber)
    {
        // Make sure the token is valid and the stamp matches
        return VerifyUserTokenAsync(user, Options.Tokens.ChangePhoneNumberTokenProvider, ChangePhoneNumberTokenPurpose + ":" + phoneNumber, token);
    }

    public virtual async Task<bool> VerifyUserTokenAsync(TUser user, string tokenProvider, string purpose, string token)  // <---------------------t4.1
    {
        if (!_tokenProviders.TryGetValue(tokenProvider, out var provider))
            throw new NotSupportedException(Resources.FormatNoTokenProvider(nameof(TUser), tokenProvider));

        // Make sure the token is valid
        var result = await provider.ValidateAsync(purpose, token, this, user).ConfigureAwait(false);  // <---------------------t4.1.
 
        if (!result && Logger.IsEnabled(LogLevel.Debug))
        {
            Logger.LogDebug(LoggerEventIds.VerifyUserTokenFailed, "VerifyUserTokenAsync() failed with purpose: {purpose} for user.", purpose);
        }

        return result;
    }

    public virtual void RegisterTokenProvider(string providerName, IUserTwoFactorTokenProvider<TUser> provider)  // <--------------------t2.3.
    {
        _tokenProviders[providerName] = provider;
    }

    public virtual async Task<IList<string>> GetValidTwoFactorProvidersAsync(TUser user)
    {
        var results = new List<string>();
        
        foreach (var f in _tokenProviders)
        {
            if (await f.Value.CanGenerateTwoFactorTokenAsync(this, user).ConfigureAwait(false))
            {
                results.Add(f.Key);
            }
        }

        return results;
    }

    public virtual async Task<bool> VerifyTwoFactorTokenAsync(TUser user, string tokenProvider, string token)
    {
        if (!_tokenProviders.TryGetValue(tokenProvider, out var provider))
            throw new NotSupportedException(Resources.FormatNoTokenProvider(nameof(TUser), tokenProvider));
 
        // Make sure the token is valid
        var result = await provider.ValidateAsync("TwoFactor", token, this, user).ConfigureAwait(false);
        
        if (!result)
        {
            Logger.LogDebug(LoggerEventIds.VerifyTwoFactorTokenFailed, $"{nameof(VerifyTwoFactorTokenAsync)}() failed for user.");
        }

        return result;
    }

    public virtual Task<string> GenerateTwoFactorTokenAsync(TUser user, string tokenProvider)
    {
        if (!_tokenProviders.TryGetValue(tokenProvider, out var provider))
        {
            throw new NotSupportedException(Resources.FormatNoTokenProvider(nameof(TUser), tokenProvider));
        }
 
        return provider.GenerateAsync("TwoFactor", this, user);
    }

    public virtual async Task<bool> GetTwoFactorEnabledAsync(TUser user)
    {
        var store = GetUserTwoFactorStore();
        return await store.GetTwoFactorEnabledAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> SetTwoFactorEnabledAsync(TUser user, bool enabled)
    {
        var store = GetUserTwoFactorStore();
 
        await store.SetTwoFactorEnabledAsync(user, enabled, CancellationToken).ConfigureAwait(false);
        await UpdateSecurityStampInternal(user).ConfigureAwait(false);
        
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<bool> IsLockedOutAsync(TUser user)
    {
        var store = GetUserLockoutStore();
        
        if (!await store.GetLockoutEnabledAsync(user, CancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        var lockoutTime = await store.GetLockoutEndDateAsync(user, CancellationToken).ConfigureAwait(false);
        
        return lockoutTime >= DateTimeOffset.UtcNow;
    }

    public virtual async Task<IdentityResult> SetLockoutEnabledAsync(TUser user, bool enabled)
    {
        var store = GetUserLockoutStore();
 
        await store.SetLockoutEnabledAsync(user, enabled, CancellationToken).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<bool> GetLockoutEnabledAsync(TUser user)
    {
        var store = GetUserLockoutStore();
        return await store.GetLockoutEnabledAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual async Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user)
    {
        var store = GetUserLockoutStore();
        return await store.GetLockoutEndDateAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd)
    {
        var store = GetUserLockoutStore();
 
        if (!await store.GetLockoutEnabledAsync(user, CancellationToken).ConfigureAwait(false))
        {
            Logger.LogDebug(LoggerEventIds.LockoutFailed, "Lockout for user failed because lockout is not enabled for this user.");
            return IdentityResult.Failed(ErrorDescriber.UserLockoutNotEnabled());
        }

        await store.SetLockoutEndDateAsync(user, lockoutEnd, CancellationToken).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> AccessFailedAsync(TUser user)
    {
        var store = GetUserLockoutStore();
 
        // If this puts the user over the threshold for lockout, lock them out and reset the access failed count
        var count = await store.IncrementAccessFailedCountAsync(user, CancellationToken).ConfigureAwait(false);
        if (count < Options.Lockout.MaxFailedAccessAttempts)
        {
            return await UpdateUserAsync(user).ConfigureAwait(false);
        }

        Logger.LogDebug(LoggerEventIds.UserLockedOut, "User is locked out.");
        
        await store.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.Add(Options.Lockout.DefaultLockoutTimeSpan),  // default lockout time span is 5mins
            CancellationToken).ConfigureAwait(false);
        await store.ResetAccessFailedCountAsync(user, CancellationToken).ConfigureAwait(false);
        
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> ResetAccessFailedCountAsync(TUser user)
    {
        var store = GetUserLockoutStore();
 
        if (await GetAccessFailedCountAsync(user).ConfigureAwait(false) == 0)
        {
            return IdentityResult.Success;
        }
        await store.ResetAccessFailedCountAsync(user, CancellationToken).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<int> GetAccessFailedCountAsync(TUser user)
    {
        var store = GetUserLockoutStore();
        return await store.GetAccessFailedCountAsync(user, CancellationToken).ConfigureAwait(false);
    }

    public virtual Task<IList<TUser>> GetUsersForClaimAsync(Claim claim)
    {
        var store = GetClaimStore();
        return store.GetUsersForClaimAsync(claim, CancellationToken);
    }

    public virtual Task<IList<TUser>> GetUsersInRoleAsync(string roleName)
    {
        var store = GetUserRoleStore();
 
        return store.GetUsersInRoleAsync(NormalizeName(roleName), CancellationToken);
    }

    public virtual Task<string?> GetAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName)
    {
        var store = GetAuthenticationTokenStore();
        return store.GetTokenAsync(user, loginProvider, tokenName, CancellationToken);
    }

    public virtual async Task<IdentityResult> SetAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName, string? tokenValue)
    {
        var store = GetAuthenticationTokenStore();

        // REVIEW: should updating any tokens affect the security stamp?
        await store.SetTokenAsync(user, loginProvider, tokenName, tokenValue, CancellationToken).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> RemoveAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName)
    {
        var store = GetAuthenticationTokenStore();

        await store.RemoveTokenAsync(user, loginProvider, tokenName, CancellationToken).ConfigureAwait(false);
        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    public virtual Task<string?> GetAuthenticatorKeyAsync(TUser user)
    {
        var store = GetAuthenticatorKeyStore();
        return store.GetAuthenticatorKeyAsync(user, CancellationToken);
    }

    public virtual async Task<IdentityResult> ResetAuthenticatorKeyAsync(TUser user)  // <-------------------reset current key to a new security stamp 
    {
        var store = GetAuthenticatorKeyStore();
        await store.SetAuthenticatorKeyAsync(user, GenerateNewAuthenticatorKey(), CancellationToken).ConfigureAwait(false);
        await UpdateSecurityStampInternal(user).ConfigureAwait(false);
        return await UpdateAsync(user).ConfigureAwait(false);
    }

    public virtual string GenerateNewAuthenticatorKey() => NewSecurityStamp();

    public virtual async Task<IEnumerable<string>?> GenerateNewTwoFactorRecoveryCodesAsync(TUser user, int number)
    {
        var store = GetRecoveryCodeStore();
 
        var newCodes = new List<string>(number);
        for (var i = 0; i < number; i++)
        {
            newCodes.Add(CreateTwoFactorRecoveryCode());
        }
 
        await store.ReplaceCodesAsync(user, newCodes.Distinct(), CancellationToken).ConfigureAwait(false);
        var update = await UpdateAsync(user).ConfigureAwait(false);
        if (update.Succeeded)
        {
            return newCodes;
        }
        return null;
    }

    protected virtual string CreateTwoFactorRecoveryCode()
    {
#if NET6_0_OR_GREATER
        return string.Create(11, 0, static (buffer, _) =>
        {
            buffer[10] = GetRandomRecoveryCodeChar();
            buffer[9] = GetRandomRecoveryCodeChar();
            buffer[8] = GetRandomRecoveryCodeChar();
            buffer[7] = GetRandomRecoveryCodeChar();
            buffer[6] = GetRandomRecoveryCodeChar();
            buffer[5] = '-';
            buffer[4] = GetRandomRecoveryCodeChar();
            buffer[3] = GetRandomRecoveryCodeChar();
            buffer[2] = GetRandomRecoveryCodeChar();
            buffer[1] = GetRandomRecoveryCodeChar();
            buffer[0] = GetRandomRecoveryCodeChar();
        });
#else
        var recoveryCode = new StringBuilder(11);
        recoveryCode.Append(GetRandomRecoveryCodeChar());
        recoveryCode.Append(GetRandomRecoveryCodeChar());
        recoveryCode.Append(GetRandomRecoveryCodeChar());
        recoveryCode.Append(GetRandomRecoveryCodeChar());
        recoveryCode.Append(GetRandomRecoveryCodeChar());
        recoveryCode.Append('-');
        recoveryCode.Append(GetRandomRecoveryCodeChar());
        recoveryCode.Append(GetRandomRecoveryCodeChar());
        recoveryCode.Append(GetRandomRecoveryCodeChar());
        recoveryCode.Append(GetRandomRecoveryCodeChar());
        recoveryCode.Append(GetRandomRecoveryCodeChar());
        return recoveryCode.ToString();
#endif
    }

    private static readonly char[] AllowedChars = "23456789BCDFGHJKMNPQRTVWXY".ToCharArray();
    
    private static char GetRandomRecoveryCodeChar()
    {
        // Based on RandomNumberGenerator implementation of GetInt32
        uint range = (uint)AllowedChars.Length - 1;
 
        // Create a mask for the bits that we care about for the range. The other bits will be
        // masked away.
        uint mask = range;
        mask |= mask >> 1;
        mask |= mask >> 2;
        mask |= mask >> 4;
        mask |= mask >> 8;
        mask |= mask >> 16;

#if NETCOREAPP
        Span<uint> resultBuffer = stackalloc uint[1];
#else
        var resultBuffer = new byte[1];
#endif
        uint result;
 
        do
        {
#if NETCOREAPP
            RandomNumberGenerator.Fill(MemoryMarshal.AsBytes(resultBuffer));
#else
            _rng.GetBytes(resultBuffer);
#endif
            result = mask & resultBuffer[0];
        }
        while (result > range);
 
        return AllowedChars[(int)result];
    }

    public virtual async Task<IdentityResult> RedeemTwoFactorRecoveryCodeAsync(TUser user, string code)
    {
        var store = GetRecoveryCodeStore();
 
        var success = await store.RedeemCodeAsync(user, code, CancellationToken).ConfigureAwait(false);
        
        if (success)
        {
            return await UpdateAsync(user).ConfigureAwait(false);
        }

        return IdentityResult.Failed(ErrorDescriber.RecoveryCodeRedemptionFailed());
    }

    public virtual Task<int> CountRecoveryCodesAsync(TUser user)
    {
        var store = GetRecoveryCodeStore();
 
        return store.CountCodesAsync(user, CancellationToken);
    }

    private IUserTwoFactorStore<TUser> GetUserTwoFactorStore()
    {
        var cast = Store as IUserTwoFactorStore<TUser>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIUserTwoFactorStore);
        }
        return cast;
    }
 
    private IUserLockoutStore<TUser> GetUserLockoutStore()
    {
        var cast = Store as IUserLockoutStore<TUser>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIUserLockoutStore);
        }
        return cast;
    }
 
    private IUserEmailStore<TUser> GetEmailStore()
    {
        if (Store is not IUserEmailStore<TUser> emailStore)
        {
            throw new NotSupportedException(Resources.StoreNotIUserEmailStore);
        }
        return emailStore;
    }
 
    private IUserEmailStore<TUser>? GetOptionalEmailStore()
    {
        return Store as IUserEmailStore<TUser>;
    }
 
    private IUserPhoneNumberStore<TUser> GetPhoneNumberStore()
    {
        var cast = Store as IUserPhoneNumberStore<TUser>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIUserPhoneNumberStore);
        }
        return cast;
    }

    public virtual async Task<byte[]> CreateSecurityTokenAsync(TUser user)
    {
        return Encoding.Unicode.GetBytes(await GetSecurityStampAsync(user).ConfigureAwait(false));
    }
 
    // update the security stamp if the store supports it
    private async Task UpdateSecurityStampInternal(TUser user)  // <-----------------------------------
    {
        if (SupportsUserSecurityStamp)
        {
            await GetSecurityStore().SetSecurityStampAsync(user, NewSecurityStamp(), CancellationToken).ConfigureAwait(false);
        }
    }

    protected virtual Task<IdentityResult> UpdatePasswordHash(TUser user, string newPassword, bool validatePassword)  // <-----------------p2.4-
    {
        UpdatePasswordHash(GetPasswordStore(), user, newPassword, validatePassword);  // <-----------------p2.4.1
    }

    private async Task<IdentityResult> UpdatePasswordHash(IUserPasswordStore<TUser> passwordStore, TUser user, string? newPassword, bool validatePassword = true) // <-----p2.4.2
    {
        if (validatePassword)
        {
            var validate = await ValidatePasswordAsync(user, newPassword).ConfigureAwait(false);   // <--------------------p2.4.3
            if (!validate.Succeeded)
            {
                return validate;
            }
        }

        var hash = newPassword != null ? PasswordHasher.HashPassword(user, newPassword) : null;
        await passwordStore.SetPasswordHashAsync(user, hash, CancellationToken).ConfigureAwait(false);   // <--------------------p2.4.4
        await UpdateSecurityStampInternal(user).ConfigureAwait(false);
        
        return IdentityResult.Success;
    }

    private IUserRoleStore<TUser> GetUserRoleStore()
    {
        var cast = Store as IUserRoleStore<TUser>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIUserRoleStore);
        }
        return cast;
    }

    private static string NewSecurityStamp()  // <-----------------has nothing to do with TUser's fields
    {
#if NETSTANDARD2_0 || NETFRAMEWORK
        byte[] bytes = new byte[20];
        _rng.GetBytes(bytes);
        return Base32.ToBase32(bytes);
#else
        return Base32.GenerateBase32();
#endif
    }
 
    // IUserLoginStore methods
    private IUserLoginStore<TUser> GetLoginStore()
    {
        var cast = Store as IUserLoginStore<TUser>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIUserLoginStore);
        }
        return cast;
    }
 
    private IUserSecurityStampStore<TUser> GetSecurityStore()
    {
        var cast = Store as IUserSecurityStampStore<TUser>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIUserSecurityStampStore);
        }
        return cast;
    }

    private IUserClaimStore<TUser> GetClaimStore()
    {
        var cast = Store as IUserClaimStore<TUser>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIUserClaimStore);
        }
        return cast;
    }

    protected async Task<IdentityResult> ValidateUserAsync(TUser user)
    {
        if (SupportsUserSecurityStamp)
        {
            var stamp = await GetSecurityStampAsync(user).ConfigureAwait(false);
            if (stamp == null)
            {
                throw new InvalidOperationException(Resources.NullSecurityStamp);
            }
        }
        List<IdentityError>? errors = null;
        foreach (var v in UserValidators)
        {
            var result = await v.ValidateAsync(this, user).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                errors ??= new List<IdentityError>();
                errors.AddRange(result.Errors);
            }
        }
        if (errors?.Count > 0)
        {
            if (Logger.IsEnabled(LogLevel.Debug))
            {
                Logger.LogDebug(LoggerEventIds.UserValidationFailed, "User validation failed: {errors}.", string.Join(";", errors.Select(e => e.Code)));
            }
            return IdentityResult.Failed(errors);
        }
        return IdentityResult.Success;
    }

    protected async Task<IdentityResult> ValidatePasswordAsync(TUser user, string? password)   // <----------------------p2.4.3.1
    {
        List<IdentityError>? errors = null;
        var isValid = true;
        foreach (var v in PasswordValidators)
        {
            var result = await v.ValidateAsync(this, user, password).ConfigureAwait(false);   // <----------------------p2.4.3.2.
            if (!result.Succeeded)
            {
                if (result.Errors.Any())
                {
                    errors ??= new List<IdentityError>();
                    errors.AddRange(result.Errors);
                }
 
                isValid = false;
            }
        }
        if (!isValid)
        {
            if (Logger.IsEnabled(LogLevel.Debug))
            {
                Logger.LogDebug(LoggerEventIds.PasswordValidationFailed, "User password validation failed: {errors}.", string.Join(";", errors?.Select(e => e.Code) ?? Array.Empty<string>()));
            }
            return IdentityResult.Failed(errors);
        }
        return IdentityResult.Success;
    }

    protected virtual async Task<IdentityResult> UpdateUserAsync(TUser user)  // <--------------! doesn't call UpdateSecurityStampInternal(user) like others such as CreateAsync
    {                                                                         // SetUserNameAsync, because you will have a lot extra user defined properties on TUser   
        var result = await ValidateUserAsync(user).ConfigureAwait(false);   // <----------------call all registered IUserValidator<TUser>
        if (!result.Succeeded)
        {
            return result;
        }
        await UpdateNormalizedUserNameAsync(user).ConfigureAwait(false);
        await UpdateNormalizedEmailAsync(user).ConfigureAwait(false);
        return await Store.UpdateAsync(user, CancellationToken).ConfigureAwait(false);  // <----------------------only update TUser when all validations pass
    }
 
    private IUserAuthenticatorKeyStore<TUser> GetAuthenticatorKeyStore()
    {
        var cast = Store as IUserAuthenticatorKeyStore<TUser>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIUserAuthenticatorKeyStore);
        }
        return cast;
    }
 
    private IUserTwoFactorRecoveryCodeStore<TUser> GetRecoveryCodeStore()
    {
        var cast = Store as IUserTwoFactorRecoveryCodeStore<TUser>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIUserTwoFactorRecoveryCodeStore);
        }
        return cast;
    }

    private IUserAuthenticationTokenStore<TUser> GetAuthenticationTokenStore()
    {
        var cast = Store as IUserAuthenticationTokenStore<TUser>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIUserAuthenticationTokenStore);
        }
        return cast;
    }
 
    private IUserPasswordStore<TUser> GetPasswordStore()
    {
        var cast = Store as IUserPasswordStore<TUser>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIUserPasswordStore);
        }
        return cast;
    }
}
//-------------------------------------------Ʌ
```