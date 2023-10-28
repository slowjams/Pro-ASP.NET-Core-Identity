.NET Identity Source Code
==============================

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



## Source Code

```C#
//-----------------------------------------------------V
public static class IdentityServiceCollectionExtensions
{
   public static IdentityBuilder AddIdentityCore<TUser>(this IServiceCollection services)
        => services.AddIdentityCore<TUser>(o => { });

   public static IdentityBuilder AddIdentityCore<TUser>(this IServiceCollection services, Action<IdentityOptions> setupAction)
   {
        // Services identity depends on
        services.AddOptions().AddLogging();
 
        // Services used by identity
        services.TryAddScoped<IUserValidator<TUser>, UserValidator<TUser>>();
        services.TryAddScoped<IPasswordValidator<TUser>, PasswordValidator<TUser>>();
        services.TryAddScoped<IPasswordHasher<TUser>, PasswordHasher<TUser>>();
        services.TryAddScoped<ILookupNormalizer, UpperInvariantLookupNormalizer>();  // <--------------------default uppercase normalizaer
        services.TryAddScoped<IUserConfirmation<TUser>, DefaultUserConfirmation<TUser>>(); // <-----------------used by SignInManager's PreSignInCheck -> CanSignInAsync
        // No interface for the error describer so we can add errors without rev'ing the interface
        services.TryAddScoped<IdentityErrorDescriber>();
        services.TryAddScoped<IUserClaimsPrincipalFactory<TUser>, UserClaimsPrincipalFactory<TUser>>();
        services.TryAddScoped<UserManager<TUser>>();  // <----------------------------------------------! register UserManager<TUser>
 
        if (setupAction != null)
        {
            services.Configure(setupAction);
        }
 
        return new IdentityBuilder(typeof(TUser), services);  // <--------------------pass TUser to IdentityBuilder.UserType and TUser can be used in AddSignInManager
   }
}
//-----------------------------------------------------Ʌ

//-------------------------------------------V
public static class IdentityBuilderExtensions
{
    public static IdentityBuilder AddDefaultTokenProviders(this IdentityBuilder builder)
    {
        var dataProtectionProviderType = typeof(DataProtectorTokenProvider<>).MakeGenericType(builder.UserType);
        var phoneNumberProviderType = typeof(PhoneNumberTokenProvider<>).MakeGenericType(builder.UserType);
        var emailTokenProviderType = typeof(EmailTokenProvider<>).MakeGenericType(builder.UserType);
        var authenticatorProviderType = typeof(AuthenticatorTokenProvider<>).MakeGenericType(builder.UserType);
        return builder
            .AddTokenProvider(TokenOptions.DefaultProvider, dataProtectionProviderType)
            .AddTokenProvider(TokenOptions.DefaultEmailProvider, emailTokenProviderType)
            .AddTokenProvider(TokenOptions.DefaultPhoneProvider, phoneNumberProviderType)
            .AddTokenProvider(TokenOptions.DefaultAuthenticatorProvider, authenticatorProviderType);
    }

    private static void AddSignInManagerDeps(this IdentityBuilder builder)
    {
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddScoped(typeof(ISecurityStampValidator), typeof(SecurityStampValidator<>).MakeGenericType(builder.UserType));
        builder.Services.AddScoped(typeof(ITwoFactorSecurityStampValidator), typeof(TwoFactorSecurityStampValidator<>).MakeGenericType(builder.UserType));
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<SecurityStampValidatorOptions>, PostConfigureSecurityStampValidatorOptions>());
    }

    public static IdentityBuilder AddSignInManager(this IdentityBuilder builder)  // <-------------------------s0
    {
        builder.AddSignInManagerDeps();
        var managerType = typeof(SignInManager<>).MakeGenericType(builder.UserType);  // <------------------check AddIdentityCore above
        builder.Services.AddScoped(managerType);  // <-------------------------------s0.1 register SignInManager<TUser>
        return builder;
    }

    public static IdentityBuilder AddSignInManager<TSignInManager>(this IdentityBuilder builder)
    {
        builder.AddSignInManagerDeps();
        var managerType = typeof(SignInManager<>).MakeGenericType(builder.UserType);  
        var customType = typeof(TSignInManager);
        if (!managerType.IsAssignableFrom(customType))
        {
            throw new InvalidOperationException(Resources.FormatInvalidManagerType(customType.Name, "SignInManager", builder.UserType.Name));
        }
        if (managerType != customType)
        {
            builder.Services.AddScoped(typeof(TSignInManager), services => services.GetRequiredService(managerType));
        }
        builder.Services.AddScoped(managerType, typeof(TSignInManager));
        return builder;
    }

    public static IdentityBuilder AddApiEndpoints(this IdentityBuilder builder)
    {
        builder.AddSignInManager();
        builder.AddDefaultTokenProviders();
        builder.Services.TryAddTransient(typeof(IEmailSender<>), typeof(DefaultMessageEmailSender<>));
        builder.Services.TryAddTransient<IEmailSender, NoOpEmailSender>();
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<JsonOptions>, IdentityEndpointsJsonOptionsSetup>());
        return builder;
    }

    private sealed class PostConfigureSecurityStampValidatorOptions : IPostConfigureOptions<SecurityStampValidatorOptions>
    {
        public PostConfigureSecurityStampValidatorOptions(TimeProvider timeProvider)
        {
            TimeProvider = timeProvider;
        }
 
        private TimeProvider TimeProvider { get; }
 
        public void PostConfigure(string? name, SecurityStampValidatorOptions options)
        {
            options.TimeProvider ??= TimeProvider;
        }
    }
}
//-------------------------------------------Ʌ

//--------------------------V
public class IdentityBuilder
{
    public IdentityBuilder(Type user, IServiceCollection services)
    {
        if (user.IsValueType)
            throw new ArgumentException("User type can't be a value type.", nameof(user));
 
        UserType = user;
        Services = services;
    }

    public IdentityBuilder(Type user, Type role, IServiceCollection services) : this(user, services)
    {
        if (role.IsValueType)
            throw new ArgumentException("Role type can't be a value type.", nameof(role));
 
        RoleType = role;
    }

    public Type UserType { get; }
    public Type? RoleType { get; private set; }
    public IServiceCollection Services { get; }

    private IdentityBuilder AddScoped(Type serviceType, Type concreteType)
    {
        Services.AddScoped(serviceType, concreteType);
        return this;
    }

    public virtual IdentityBuilder AddUserValidator<TValidator>() 
    {
        return AddScoped(typeof(IUserValidator<>).MakeGenericType(UserType), typeof(TValidator));
    }

    public virtual IdentityBuilder AddClaimsPrincipalFactory<TFactory>() 
    {
        return AddScoped(typeof(IUserClaimsPrincipalFactory<>).MakeGenericType(UserType), typeof(TFactory));
    }

    public virtual IdentityBuilder AddErrorDescriber<TDescriber>() where TDescriber : IdentityErrorDescriber
    {
        Services.AddScoped<IdentityErrorDescriber, TDescriber>();
        return this;
    }

    public virtual IdentityBuilder AddPasswordValidator<TValidator>() 
    {
        return AddScoped(typeof(IPasswordValidator<>).MakeGenericType(UserType), typeof(TValidator));
    }
    
    public virtual IdentityBuilder AddUserStore<TStore>()
    {
        return AddScoped(typeof(IUserStore<>).MakeGenericType(UserType), typeof(TStore));
    }

    public virtual IdentityBuilder AddTokenProvider<TProvider>(string providerName)  // <---------------------------t1
    {
        return AddTokenProvider(providerName, typeof(TProvider));
    }

    public virtual IdentityBuilder AddTokenProvider(string providerName, Type provider)
    {
        if (!typeof(IUserTwoFactorTokenProvider<>).MakeGenericType(UserType).IsAssignableFrom(provider))
        {
            throw new InvalidOperationException(Resources.FormatInvalidManagerType(provider.Name, "IUserTwoFactorTokenProvider", UserType.Name));
        }

        Services.Configure<IdentityOptions>(options =>
        {
            if (options.Tokens.ProviderMap.TryGetValue(providerName, out var descriptor))  // providerName is used as a dict key
            {
                descriptor.ProviderInstance = null;
                descriptor.AddProviderType(provider);
            }
            else
            {
                options.Tokens.ProviderMap[providerName] = new TokenProviderDescriptor(provider);  // <---------------------------t1.1
            }
        });

        Services.AddTransient(provider);  // <-----------------------------t1.2. DI registeration here
                                          // check UserManager<TUser> source code starting from t2
        return this;
    } 

    public virtual IdentityBuilder AddUserManager<TUserManager>()
    {
        var userManagerType = typeof(UserManager<>).MakeGenericType(UserType);
        var customType = typeof(TUserManager);
        if (!userManagerType.IsAssignableFrom(customType))
        {
            throw new InvalidOperationException(Resources.FormatInvalidManagerType(customType.Name, "UserManager", UserType.Name));
        }
        if (userManagerType != customType)
        {
            Services.AddScoped(customType, services => services.GetRequiredService(userManagerType));
        }
        return AddScoped(userManagerType, customType);
    }

    public virtual IdentityBuilder AddRoles<TRole>()
    {
        RoleType = typeof(TRole);
        AddRoleValidator<RoleValidator<TRole>>();
        Services.TryAddScoped<RoleManager<TRole>>();
        Services.AddScoped(typeof(IUserClaimsPrincipalFactory<>).MakeGenericType(UserType), typeof(UserClaimsPrincipalFactory<,>).MakeGenericType(UserType, RoleType));
        return this;
    }

    public virtual IdentityBuilder AddRoleValidator<TRole>() where TRole : class
    {
        if (RoleType == null)
            throw new InvalidOperationException(Resources.NoRoleType);
        
        return AddScoped(typeof(IRoleValidator<>).MakeGenericType(RoleType), typeof(TRole));
    }

    public virtual IdentityBuilder AddPersonalDataProtection<TProtector, TKeyRing>()
    {
        Services.AddSingleton<IPersonalDataProtector, DefaultPersonalDataProtector>();
        Services.AddSingleton<ILookupProtector, TProtector>();
        Services.AddSingleton<ILookupProtectorKeyRing, TKeyRing>();
        return this;
    }

    public virtual IdentityBuilder AddRoleStore<TStore>() where TStore : class
    {
        if (RoleType == null)
            throw new InvalidOperationException(Resources.NoRoleType);
        
        return AddScoped(typeof(IRoleStore<>).MakeGenericType(RoleType), typeof(TStore));
    }

    public virtual IdentityBuilder AddRoleManager<TRoleManager>() 
    {
        if (RoleType == null)
            throw new InvalidOperationException(Resources.NoRoleType);
        
        var managerType = typeof(RoleManager<>).MakeGenericType(RoleType);
        var customType = typeof(TRoleManager);

        if (!managerType.IsAssignableFrom(customType))
            throw new InvalidOperationException(Resources.FormatInvalidManagerType(customType.Name, "RoleManager", RoleType.Name));

        if (managerType != customType)
        {
            Services.AddScoped(typeof(TRoleManager), services => services.GetRequiredService(managerType));
        }

        return AddScoped(managerType, typeof(TRoleManager));
    }

    public virtual IdentityBuilder AddUserConfirmation<TUserConfirmation>()
    {
        return AddScoped(typeof(IUserConfirmation<>).MakeGenericType(UserType), typeof(TUserConfirmation));
    }
}
//--------------------------Ʌ

//------------------------V
public class IdentityError
{
    public string Code { get; set; } = default!;
    public string Description { get; set; } = default!;
}
//------------------------Ʌ

//-------------------------V
public class IdentityResult
{
    private static readonly IdentityResult _success = new IdentityResult { Succeeded = true };
    private readonly List<IdentityError> _errors = new List<IdentityError>();
    
    public bool Succeeded { get; protected set; }
    
    public IEnumerable<IdentityError> Errors => _errors;
    public static IdentityResult Success => _success;

    public static IdentityResult Failed(params IdentityError[] errors)
    {
        var result = new IdentityResult { Succeeded = false };
        if (errors != null)
        {
            result._errors.AddRange(errors);
        }
        return result;
    }

    internal static IdentityResult Failed(List<IdentityError>? errors)
    {
        var result = new IdentityResult { Succeeded = false };
        if (errors != null)
        {
            result._errors.AddRange(errors);
        }
        return result;
    }

    public override string ToString()
    {
        return Succeeded ? "Succeeded" : string.Format(CultureInfo.InvariantCulture, "{0} : {1}", "Failed", string.Join(",", Errors.Select(x => x.Code).ToList()));
    }
}
//-------------------------Ʌ

//---------------------------------V
public class IdentityErrorDescriber
{
    public virtual IdentityError DefaultError() => new IdentityError { Code = nameof(DefaultError), Description = Resources.DefaultError };
    
    public virtual IdentityError ConcurrencyFailure() => new IdentityError { Code = nameof(ConcurrencyFailure), Description = Resources.ConcurrencyFailure };
   
    public virtual IdentityError PasswordMismatch() => new IdentityError { Code = nameof(PasswordMismatch), Description = Resources.PasswordMismatch };

    public virtual IdentityError InvalidToken() => new IdentityError { Code = nameof(InvalidToken), Description = Resources.InvalidToken };

    public virtual IdentityError RecoveryCodeRedemptionFailed() => new IdentityError { Code = nameof(RecoveryCodeRedemptionFailed), Description = Resources.xxx };
    
    public virtual IdentityError LoginAlreadyAssociated() => new IdentityError { Code = nameof(LoginAlreadyAssociated), Description = Resources.LoginAlreadyAssociated };
    
    public virtual IdentityError InvalidUserName(string? userName) => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };
   
    public virtual IdentityError InvalidEmail(string? email) => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError DuplicateUserName(string userName)  => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError DuplicateEmail(string email) => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError InvalidRoleName(string? role) => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError DuplicateRoleName(string role) => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError UserAlreadyHasPassword() => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError UserLockoutNotEnabled() => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError UserAlreadyInRole(string role) => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError UserNotInRole(string role) => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError PasswordTooShort(int length) => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };
   
    public virtual IdentityError PasswordRequiresUniqueChars(int uniqueChars) => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError PasswordRequiresNonAlphanumeric() => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError PasswordRequiresDigit() => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError PasswordRequiresLower() => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };

    public virtual IdentityError PasswordRequiresUpper() => new IdentityError { Code = nameof(xxx), Description = Resources.xxx };
}
//---------------------------------Ʌ

//------------------------------------>>
public interface IUserValidator<TUser>
{
    Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user);
}
//------------------------------------<<

//-------------------------------V
public class UserValidator<TUser> : IUserValidator<TUser>
{
    public UserValidator(IdentityErrorDescriber? errors = null)
    {
        Describer = errors ?? new IdentityErrorDescriber();
    }

    public IdentityErrorDescriber Describer { get; private set; }

    public virtual async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user)
    {
        var errors = await ValidateUserName(manager, user).ConfigureAwait(false);
        
        if (manager.Options.User.RequireUniqueEmail)  // <-----------------------------------------i1
            errors = await ValidateEmail(manager, user, errors).ConfigureAwait(false);

        return errors?.Count > 0 ? IdentityResult.Failed(errors) : IdentityResult.Success;
    }

    private async Task<List<IdentityError>?> ValidateUserName(UserManager<TUser> manager, TUser user)
    {
        List<IdentityError>? errors = null;
        var userName = await manager.GetUserNameAsync(user).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(userName))
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.InvalidUserName(userName));
        }
        else if (!string.IsNullOrEmpty(manager.Options.User.AllowedUserNameCharacters) && userName.Any(c => !manager.Options.User.AllowedUserNameCharacters.Contains(c)))
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.InvalidUserName(userName));
        }
        else
        {
            var owner = await manager.FindByNameAsync(userName).ConfigureAwait(false);
            if (owner != null &&
                !string.Equals(await manager.GetUserIdAsync(owner).ConfigureAwait(false), await manager.GetUserIdAsync(user).ConfigureAwait(false)))
            {
                errors ??= new List<IdentityError>();
                errors.Add(Describer.DuplicateUserName(userName));
            }
        }
 
        return errors;
    }

    private async Task<List<IdentityError>?> ValidateEmail(UserManager<TUser> manager, TUser user, List<IdentityError>? errors)
    {
        var email = await manager.GetEmailAsync(user).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(email))
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.InvalidEmail(email));
            return errors;
        }
        if (!new EmailAddressAttribute().IsValid(email))
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.InvalidEmail(email));
            return errors;
        }
        var owner = await manager.FindByEmailAsync(email).ConfigureAwait(false);
        if (owner != null &&
            !string.Equals(await manager.GetUserIdAsync(owner).ConfigureAwait(false), await manager.GetUserIdAsync(user).ConfigureAwait(false)))
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.DuplicateEmail(email));
        }
        return errors;
    }
}
//-------------------------------Ʌ

//---------------------------------------->>
public interface IPasswordValidator<TUser>
{
    Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string? password);
}
//----------------------------------------<<

//-----------------------------------V
public class PasswordValidator<TUser> : IPasswordValidator<TUser>
{
    public PasswordValidator(IdentityErrorDescriber? errors = null)
    {
        Describer = errors ?? new IdentityErrorDescriber();
    }

    public IdentityErrorDescriber Describer { get; private set; }

    public virtual Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string? password)
    {
        List<IdentityError>? errors = null;
        
        var options = manager.Options.Password;
        
        if (string.IsNullOrWhiteSpace(password) || password.Length < options.RequiredLength)
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.PasswordTooShort(options.RequiredLength));
        }

        if (options.RequireNonAlphanumeric && password.All(IsLetterOrDigit))
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.PasswordRequiresNonAlphanumeric());
        }

        if (options.RequireDigit && !password.Any(IsDigit))
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.PasswordRequiresDigit());
        }

        if (options.RequireLowercase && !password.Any(IsLower))
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.PasswordRequiresLower());
        }

        if (options.RequireUppercase && !password.Any(IsUpper))
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.PasswordRequiresUpper());
        }

        if (options.RequiredUniqueChars >= 1 && password.Distinct().Count() < options.RequiredUniqueChars)
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.PasswordRequiresUniqueChars(options.RequiredUniqueChars));
        }

        return Task.FromResult(errors?.Count > 0 ? IdentityResult.Failed(errors) : IdentityResult.Success);
    }

    public virtual bool IsDigit(char c)
    {
        return c >= '0' && c <= '9';
    }

    public virtual bool IsLower(char c)
    {
        return c >= 'a' && c <= 'z';
    }

    public virtual bool IsUpper(char c)
    {
        return c >= 'A' && c <= 'Z';
    }

    public virtual bool IsLetterOrDigit(char c)
    {
        return IsUpper(c) || IsLower(c) || IsDigit(c);
    }
}
//-----------------------------------Ʌ

//------------------------------------->>
public interface IPasswordHasher<TUser>
{
    string HashPassword(TUser user, string password);
    PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword);
}

public enum PasswordVerificationResult
{
    Failed = 0,
    Success = 1,
    SuccessRehashNeeded = 2
}
//-------------------------------------<<

//--------------------------------V
public class PasswordHasher<TUser> : IPasswordHasher<TUser>
{
    /* =======================
     * HASHED PASSWORD FORMATS
     * =======================
     *
     * Version 2:
     * PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.
     * (See also: SDL crypto guidelines v5.1, Part III)
     * Format: { 0x00, salt, subkey }
     *
     * Version 3:
     * PBKDF2 with HMAC-SHA512, 128-bit salt, 256-bit subkey, 100000 iterations.
     * Format: { 0x01, prf (UInt32), iter count (UInt32), salt length (UInt32), salt, subkey }
     * (All UInt32s are stored big-endian.)
     */

     private readonly PasswordHasherCompatibilityMode _compatibilityMode;
     private readonly int _iterCount;
     private readonly RandomNumberGenerator _rng;

     private static readonly PasswordHasherOptions DefaultOptions = new PasswordHasherOptions();

     public PasswordHasher(IOptions<PasswordHasherOptions>? optionsAccessor = null)
     {
        var options = optionsAccessor?.Value ?? DefaultOptions;
 
        _compatibilityMode = options.CompatibilityMode;
        switch (_compatibilityMode)
        {
            case PasswordHasherCompatibilityMode.IdentityV2:
                // nothing else to do
                break;
 
            case PasswordHasherCompatibilityMode.IdentityV3:
                _iterCount = options.IterationCount;
                if (_iterCount < 1)
                {
                    throw new InvalidOperationException(Resources.InvalidPasswordHasherIterationCount);
                }
                break;
 
            default:
                throw new InvalidOperationException(Resources.InvalidPasswordHasherCompatibilityMode);
        }
 
        _rng = options.Rng;
    }

    private static bool ByteArraysEqual(byte[] a, byte[] b)
    {
        if (a == null && b == null)
        {
            return true;
        }
        if (a == null || b == null || a.Length != b.Length)
        {
            return false;
        }
        var areSame = true;
        for (var i = 0; i < a.Length; i++)
        {
            areSame &= (a[i] == b[i]);
        }
        return areSame;
    }

    public virtual string HashPassword(TUser user, string password)
    {
        ArgumentNullThrowHelper.ThrowIfNull(password);
 
        if (_compatibilityMode == PasswordHasherCompatibilityMode.IdentityV2)
        {
            return Convert.ToBase64String(HashPasswordV2(password, _rng));
        }
        else
        {
            return Convert.ToBase64String(HashPasswordV3(password, _rng));
        }
    }

    private static byte[] HashPasswordV2(string password, RandomNumberGenerator rng)
    {
        const KeyDerivationPrf Pbkdf2Prf = KeyDerivationPrf.HMACSHA1; // default for Rfc2898DeriveBytes
        const int Pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
        const int Pbkdf2SubkeyLength = 256 / 8; // 256 bits
        const int SaltSize = 128 / 8; // 128 bits
 
        // Produce a version 2 (see comment above) text hash.
        byte[] salt = new byte[SaltSize];
        rng.GetBytes(salt);
        byte[] subkey = KeyDerivation.Pbkdf2(password, salt, Pbkdf2Prf, Pbkdf2IterCount, Pbkdf2SubkeyLength);
 
        var outputBytes = new byte[1 + SaltSize + Pbkdf2SubkeyLength];
        outputBytes[0] = 0x00; // format marker
        Buffer.BlockCopy(salt, 0, outputBytes, 1, SaltSize);
        Buffer.BlockCopy(subkey, 0, outputBytes, 1 + SaltSize, Pbkdf2SubkeyLength);
        return outputBytes;
    }

    private byte[] HashPasswordV3(string password, RandomNumberGenerator rng)
    {
        return HashPasswordV3(password, rng,
            prf: KeyDerivationPrf.HMACSHA512,
            iterCount: _iterCount,
            saltSize: 128 / 8,
            numBytesRequested: 256 / 8);
    }

    private static byte[] HashPasswordV3(string password, RandomNumberGenerator rng, KeyDerivationPrf prf, int iterCount, int saltSize, int numBytesRequested)
    {
        // Produce a version 3 (see comment above) text hash.
        byte[] salt = new byte[saltSize];
        rng.GetBytes(salt);
        byte[] subkey = KeyDerivation.Pbkdf2(password, salt, prf, iterCount, numBytesRequested);
 
        var outputBytes = new byte[13 + salt.Length + subkey.Length];
        outputBytes[0] = 0x01; // format marker
        WriteNetworkByteOrder(outputBytes, 1, (uint)prf);
        WriteNetworkByteOrder(outputBytes, 5, (uint)iterCount);
        WriteNetworkByteOrder(outputBytes, 9, (uint)saltSize);
        Buffer.BlockCopy(salt, 0, outputBytes, 13, salt.Length);
        Buffer.BlockCopy(subkey, 0, outputBytes, 13 + saltSize, subkey.Length);
        return outputBytes;
    }

    public virtual PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        byte[] decodedHashedPassword = Convert.FromBase64String(hashedPassword);
 
        // read the format marker from the hashed password
        if (decodedHashedPassword.Length == 0)
        {
            return PasswordVerificationResult.Failed;
        }
        switch (decodedHashedPassword[0])
        {
            case 0x00:
                if (VerifyHashedPasswordV2(decodedHashedPassword, providedPassword))
                {
                    // This is an old password hash format - the caller needs to rehash if we're not running in an older compat mode.
                    return (_compatibilityMode == PasswordHasherCompatibilityMode.IdentityV3)
                        ? PasswordVerificationResult.SuccessRehashNeeded
                        : PasswordVerificationResult.Success;
                }
                else
                {
                    return PasswordVerificationResult.Failed;
                }
 
            case 0x01:
                if (VerifyHashedPasswordV3(decodedHashedPassword, providedPassword, out int embeddedIterCount, out KeyDerivationPrf prf))
                {
                    // If this hasher was configured with a higher iteration count, change the entry now.
                    if (embeddedIterCount < _iterCount)
                    {
                        return PasswordVerificationResult.SuccessRehashNeeded;
                    }
 
                    // V3 now requires SHA512. If the old PRF is SHA1 or SHA256, upgrade to SHA512 and rehash.
                    if (prf == KeyDerivationPrf.HMACSHA1 || prf == KeyDerivationPrf.HMACSHA256)
                    {
                        return PasswordVerificationResult.SuccessRehashNeeded;
                    }
 
                    return PasswordVerificationResult.Success;
                }
                else
                {
                    return PasswordVerificationResult.Failed;
                }
 
            default:
                return PasswordVerificationResult.Failed; // unknown format marker
        }
    }

    private static bool VerifyHashedPasswordV2(byte[] hashedPassword, string password)
    {
        // ...
    }

    private static bool VerifyHashedPasswordV3(byte[] hashedPassword, string password, out int iterCount, out KeyDerivationPrf prf)
    {
        // ...
    }

    // ...
}
//--------------------------------Ʌ

//------------------------------------>>
public interface IRoleValidator<TRole>
{
    Task<IdentityResult> ValidateAsync(RoleManager<TRole> manager, TRole role);
}
//------------------------------------<<

//--------------------------------------->>
public interface IUserConfirmation<TUser>
{
    Task<bool> IsConfirmedAsync(UserManager<TUser> manager, TUser user); // <-----------------used by SignInManager's PreSignInCheck -> CanSignInAsync
}
//---------------------------------------<<

//-----------------------------------------V
public class DefaultUserConfirmation<TUser> : IUserConfirmation<TUser>
{
    public virtual async Task<bool> IsConfirmedAsync(UserManager<TUser> manager, TUser user)
    {
        return await manager.IsEmailConfirmedAsync(user).ConfigureAwait(false);
    }
}
//-----------------------------------------Ʌ
```

```C#
//----------------------------------V
public class TokenProviderDescriptor
{
    private readonly Stack<Type> _providerTypes = new(1);

    public TokenProviderDescriptor(Type type)
    {
        _providerTypes.Push(type);
    }

    public Type ProviderType => _providerTypes.Peek();

    // if specified, the instance to be used for the token provider
    public object? ProviderInstance { get; set; }
 
    internal void AddProviderType(Type type) => _providerTypes.Push(type);
 
    internal Type? GetProviderType<T>()
    {
        foreach (var providerType in _providerTypes)
        {
            if (typeof(T).IsAssignableFrom(providerType))
                return providerType;
        }
        return null;
    }
}
//----------------------------------Ʌ
```

```C#
//--------------------------VV
public class IdentityOptions
{
    public ClaimsIdentityOptions ClaimsIdentity { get; set; } = new ClaimsIdentityOptions();
    public UserOptions User { get; set; } = new UserOptions();
    public PasswordOptions Password { get; set; } = new PasswordOptions();
    public LockoutOptions Lockout { get; set; } = new LockoutOptions();
    public SignInOptions SignIn { get; set; } = new SignInOptions();
    public TokenOptions Tokens { get; set; } = new TokenOptions();
    public StoreOptions Stores { get; set; } = new StoreOptions();
}
//--------------------------Ʌ

public class ClaimsIdentityOptions
{
    public string RoleClaimType { get; set; } = ClaimTypes.Role;
    public string UserNameClaimType { get; set; } = ClaimTypes.Name;
    public string UserIdClaimType { get; set; } = ClaimTypes.NameIdentifier;
    public string EmailClaimType { get; set; } = ClaimTypes.Email;
    public string SecurityStampClaimType { get; set; } = "AspNet.Identity.SecurityStamp";
}

public class UserOptions
{
    public string AllowedUserNameCharacters { get; set; } = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    public bool RequireUniqueEmail { get; set; }
}

public class PasswordOptions
{
    public int RequiredLength { get; set; } = 6;
    public int RequiredUniqueChars { get; set; } = 1;
    public bool RequireNonAlphanumeric { get; set; } = true;
    public bool RequireLowercase { get; set; } = true;
    public bool RequireUppercase { get; set; } = true;
    public bool RequireDigit { get; set; } = true;
}

public class LockoutOptions
{
    public bool AllowedForNewUsers { get; set; } = true;
    public int MaxFailedAccessAttempts { get; set; } = 5;
    public TimeSpan DefaultLockoutTimeSpan { get; set; } = TimeSpan.FromMinutes(5);  // <------------
}

public class SignInOptions
{
    public bool RequireConfirmedEmail { get; set; }
    public bool RequireConfirmedPhoneNumber { get; set; }
    public bool RequireConfirmedAccount { get; set; }
}

public class TokenOptions
{
    public static readonly string DefaultProvider = "Default";
    public static readonly string DefaultEmailProvider = "Email";
    public static readonly string DefaultPhoneProvider = "Phone";
    public static readonly string DefaultAuthenticatorProvider = "Authenticator";
    public Dictionary<string, TokenProviderDescriptor> ProviderMap { get; set; } = new Dictionary<string, TokenProviderDescriptor>();  // <-----------------------
    public string EmailConfirmationTokenProvider { get; set; } = DefaultProvider;
    public string PasswordResetTokenProvider { get; set; } = DefaultProvider;
    public string ChangeEmailTokenProvider { get; set; } = DefaultProvider;
    public string ChangePhoneNumberTokenProvider { get; set; } = DefaultPhoneProvider;
    public string AuthenticatorTokenProvider { get; set; } = DefaultAuthenticatorProvider;
    public string AuthenticatorIssuer { get; set; } = "Microsoft.AspNetCore.Identity.UI";
}

public class StoreOptions
{
    public int MaxLengthForKeys { get; set; }
    public bool ProtectPersonalData { get; set; }
    public Version SchemaVersion { get; set; } = IdentitySchemaVersions.Default;
}
//--------------------------ɅɅ
```

```C#
//------------------------------------------------->>
public interface IUserClaimsPrincipalFactory<TUser>  // <-----------note that IUserClaimsPrincipalFactory only being used in "SignIn" process like HttpContext.SignInAsync()
{                                                    // or SignInManager.PasswordSignInAsync() etc
   Task<ClaimsPrincipal> CreateAsync(TUser user);
}
//-------------------------------------------------<<

//--------------------------------------------V
public class UserClaimsPrincipalFactory<TUser> : IUserClaimsPrincipalFactory<TUser>
{
    public UserClaimsPrincipalFactory(UserManager<TUser> userManager, IOptions<IdentityOptions> optionsAccessor)
    {
        if (optionsAccessor == null || optionsAccessor.Value == null)
            throw new ArgumentException($"{nameof(optionsAccessor)} cannot wrap a null value.", nameof(optionsAccessor));

        UserManager = userManager;
        Options = optionsAccessor.Value;
    }

    public UserManager<TUser> UserManager { get; private set; }

    public IdentityOptions Options { get; private set; }

    public virtual async Task<ClaimsPrincipal> CreateAsync(TUser user)
    {
        var id = await GenerateClaimsAsync(user).ConfigureAwait(false);
        return new ClaimsPrincipal(id);
    }

    protected virtual async Task<ClaimsIdentity> GenerateClaimsAsync(TUser user)
    {
        var userId = await UserManager.GetUserIdAsync(user).ConfigureAwait(false);
        var userName = await UserManager.GetUserNameAsync(user).ConfigureAwait(false);
        
        // <------------------------"Identity.Application" is the default auth type
        var id = new ClaimsIdentity("Identity.Application", Options.ClaimsIdentity.UserNameClaimType, Options.ClaimsIdentity.RoleClaimType);

        id.AddClaim(new Claim(Options.ClaimsIdentity.UserIdClaimType, userId));
        id.AddClaim(new Claim(Options.ClaimsIdentity.UserNameClaimType, userName!));

        if (UserManager.SupportsUserEmail)
        {
            var email = await UserManager.GetEmailAsync(user).ConfigureAwait(false);

            if (!string.IsNullOrEmpty(email))
                id.AddClaim(new Claim(Options.ClaimsIdentity.EmailClaimType, email));
        }

        if (UserManager.SupportsUserSecurityStamp)
        {
            id.AddClaim(new Claim(Options.ClaimsIdentity.SecurityStampClaimType, await UserManager.GetSecurityStampAsync(user).ConfigureAwait(false)));
        }

        if (UserManager.SupportsUserClaim)
        {
            id.AddClaims(await UserManager.GetClaimsAsync(user).ConfigureAwait(false));
        }
        return id;
    }
}
//--------------------------------------------Ʌ

//---------------------------------------------------V
public class UserClaimsPrincipalFactory<TUser, TRole> : UserClaimsPrincipalFactory<TUser>
{
    public UserClaimsPrincipalFactory(UserManager<TUser> userManager, RoleManager<TRole> roleManager, IOptions<IdentityOptions> options) : base(userManager, options)
    {
        RoleManager = roleManager;
    }

    public RoleManager<TRole> RoleManager { get; private set; }

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(TUser user)
    {
        var id = await base.GenerateClaimsAsync(user).ConfigureAwait(false);

        if (UserManager.SupportsUserRole)
        {
            var roles = await UserManager.GetRolesAsync(user).ConfigureAwait(false);

            foreach (var roleName in roles)
            {
                id.AddClaim(new Claim(Options.ClaimsIdentity.RoleClaimType, roleName));
                
                if (RoleManager.SupportsRoleClaims)
                {
                    var role = await RoleManager.FindByNameAsync(roleName).ConfigureAwait(false);
                    
                    if (role != null)
                    {
                        id.AddClaims(await RoleManager.GetClaimsAsync(role).ConfigureAwait(false));
                    }
                }
            }
        }

        return id;
    }
}
//---------------------------------------------------Ʌ
```

```C#
//----------------------------------------------V
public interface IUserStore<TUser> : IDisposable
{
    Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken);
    Task<string?> GetUserNameAsync(TUser user, CancellationToken cancellationToken);
    Task SetUserNameAsync(TUser user, string? userName, CancellationToken cancellationToken);
    Task<string?> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken);
    Task SetNormalizedUserNameAsync(TUser user, string? normalizedName, CancellationToken cancellationToken);
    Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken);
    Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken);
    Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken);
    Task<TUser?> FindByIdAsync(string userId, CancellationToken cancellationToken);
    Task<TUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken);
}
//----------------------------------------------Ʌ

//-------------------------------------V
public interface IUserClaimStore<TUser> : IUserStore<TUser>
{
    Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken);
    Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken);
    Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken);
    Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken);
    Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken);
}
//-------------------------------------Ʌ

//------------------------------------v
public interface IUserRoleStore<TUser> : IUserStore<TUser>
{
    Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken);
    Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken);
    Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken);
    Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken);
    Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken);
}
//------------------------------------Ʌ

//--------------------------------V
public interface IRoleStore<TRole> : IDisposable where TRole : class
{
    Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken);
    Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken);
    Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken);
    Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken);
    Task<string?> GetRoleNameAsync(TRole role, CancellationToken cancellationToken);
    Task SetRoleNameAsync(TRole role, string? roleName, CancellationToken cancellationToken);
    Task<string?> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken);
    Task SetNormalizedRoleNameAsync(TRole role, string? normalizedName, CancellationToken cancellationToken);
    Task<TRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken);
    Task<TRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken);
}
//--------------------------------Ʌ

//---------------------------------------------V
public interface IUserSecurityStampStore<TUser> : IUserStore<TUser>
{
    Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken);
    Task<string?> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken);
}
//--------------------------------------------Ʌ

//------------------------------------------------V
public interface IUserAuthenticatorKeyStore<TUser> : IUserStore<TUser>
{
    Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken);
    Task<string?> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken);
}
//------------------------------------------------Ʌ

//-----------------------------------------V
public interface IQueryableUserStore<TUser> : IUserStore<TUser>
{
    IQueryable<TUser> Users { get; }
}
//-----------------------------------------Ʌ

//-------------------------------------V
public interface IUserEmailStore<TUser> : IUserStore<TUser>
{
    Task SetEmailAsync(TUser user, string? email, CancellationToken cancellationToken);
    Task<string?> GetEmailAsync(TUser user, CancellationToken cancellationToken);
    Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken);
    Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken);
    Task<TUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken);
    Task<string?> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken);
    Task SetNormalizedEmailAsync(TUser user, string? normalizedEmail, CancellationToken cancellationToken);
}
//-------------------------------------Ʌ

//-------------------------------------------V
public interface IUserPhoneNumberStore<TUser> : IUserStore<TUser>
{
    Task SetPhoneNumberAsync(TUser user, string? phoneNumber, CancellationToken cancellationToken);
    Task<string?> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken);
    Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken);
    Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken);
}
//-------------------------------------------Ʌ

//----------------------------------------V
public interface IUserPasswordStore<TUser> : IUserStore<TUser>
{
    Task SetPasswordHashAsync(TUser user, string? passwordHash, CancellationToken cancellationToken);
    Task<string?> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken);
    Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken);
}
//----------------------------------------Ʌ

//---------------------------------------V
public interface IUserLockoutStore<TUser> : IUserStore<TUser>
{
    Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken);
    Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken);
    Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken);
    Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken);
    Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken);
    Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken);
    Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken);
}
//---------------------------------------Ʌ

//-----------------------------------------V
public interface IUserTwoFactorStore<TUser> : IUserStore<TUser>
{
    Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken);
    Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken);
}
//-----------------------------------------Ʌ

//------------------------------------------------V
public interface IUserAuthenticatorKeyStore<TUser> : IUserStore<TUser>
{
    Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken);
    Task<string?> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken);
}
//------------------------------------------------Ʌ

//-----------------------------------------------------V
public interface IUserTwoFactorRecoveryCodeStore<TUser> : IUserStore<TUser>
{
    Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken);
    Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken);
    Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken);
}
//-----------------------------------------------------Ʌ

//-------------------------------------V
public interface IUserLoginStore<TUser> : IUserStore<TUser>
{
    Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken);
    Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken);
    Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken);
    Task<TUser?> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken);
}
//-------------------------------------Ʌ

//---------------------------------------------------V
public interface IUserAuthenticationTokenStore<TUser> : IUserStore<TUser>
{
    Task SetTokenAsync(TUser user, string loginProvider, string name, string? value, CancellationToken cancellationToken);
    Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken);
    Task<string?> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken);
}
//---------------------------------------------------Ʌ

//-----------------------------V
public class UserManager<TUser> : IDisposable
{
    public const string ResetPasswordTokenPurpose = "ResetPassword";
    public const string ChangePhoneNumberTokenPurpose = "ChangePhoneNumber";
    public const string ConfirmEmailTokenPurpose = "EmailConfirmation";

    public UserManager(IUserStore<TUser> store, IOptions<IdentityOptions> optionsAccessor, IPasswordHasher<TUser> passwordHasher, 
                       IEnumerable<IUserValidator<TUser>> userValidators, IEnumerable<IPasswordValidator<TUser>> passwordValidators, 
                       ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<TUser>> logger);
    
    public IPasswordHasher<TUser> PasswordHasher { get; set; }
    public IList<IUserValidator<TUser>> UserValidators { get; }
    public IList<IPasswordValidator<TUser>> PasswordValidators { get; }
    public ILookupNormalizer KeyNormalizer { get; set; }
    public IdentityErrorDescriber ErrorDescriber { get; set; }
    public IdentityOptions Options { get; set; }
    public virtual bool SupportsUserAuthenticationTokens { get; }
    public virtual bool SupportsUserAuthenticatorKey { get; }
    public virtual bool SupportsUserTwoFactorRecoveryCodes { get; }
    public virtual bool SupportsUserPassword { get; }
    public virtual ILogger Logger { get; set; }
    public virtual bool SupportsUserSecurityStamp { get; }
    public virtual bool SupportsUserRole { get; }
    public virtual bool SupportsUserLogin { get; }
    public virtual bool SupportsUserEmail { get; }
    public virtual bool SupportsUserPhoneNumber { get; }
    public virtual bool SupportsUserClaim { get; }
    public virtual bool SupportsUserLockout { get; }
    public virtual bool SupportsUserTwoFactor { get; }
    public virtual bool SupportsQueryableUsers { get; }
    public virtual IQueryable<TUser> Users { get; }
    protected virtual CancellationToken CancellationToken { get; }
    protected internal IUserStore<TUser> Store { get; set; }

    public static string GetChangeEmailTokenPurpose(string newEmail);
    public virtual Task<IdentityResult> AccessFailedAsync(TUser user);
    public virtual Task<IdentityResult> AddClaimAsync(TUser user, Claim claim);
    public virtual Task<IdentityResult> AddClaimsAsync(TUser user, IEnumerable<Claim> claims);
    public virtual Task<IdentityResult> AddLoginAsync(TUser user, UserLoginInfo login);
    public virtual Task<IdentityResult> AddPasswordAsync(TUser user, string password);
    public virtual Task<IdentityResult> AddToRoleAsync(TUser user, string role);
    public virtual Task<IdentityResult> AddToRolesAsync(TUser user, IEnumerable<string> roles);
    public virtual Task<IdentityResult> ChangeEmailAsync(TUser user, string newEmail, string token);
    public virtual Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword);
    public virtual Task<IdentityResult> ChangePhoneNumberAsync(TUser user, string phoneNumber, string token);
    public virtual Task<bool> CheckPasswordAsync(TUser user, string password);
    public virtual Task<IdentityResult> ConfirmEmailAsync(TUser user, string token);
    public virtual Task<int> CountRecoveryCodesAsync(TUser user);
    public virtual Task<IdentityResult> CreateAsync(TUser user);
    public virtual Task<IdentityResult> CreateAsync(TUser user, string password);
    public virtual Task<byte[]> CreateSecurityTokenAsync(TUser user);
    public virtual Task<IdentityResult> DeleteAsync(TUser user);
    public void Dispose();
    public virtual Task<TUser> FindByEmailAsync(string email);
    public virtual Task<TUser> FindByIdAsync(string userId);
    public virtual Task<TUser> FindByLoginAsync(string loginProvider, string providerKey);
    public virtual Task<TUser> FindByNameAsync(string userName);
    public virtual Task<string> GenerateChangeEmailTokenAsync(TUser user, string newEmail);
    public virtual Task<string> GenerateChangePhoneNumberTokenAsync(TUser user, string phoneNumber);
    public virtual Task<string> GenerateConcurrencyStampAsync(TUser user);
    public virtual Task<string> GenerateEmailConfirmationTokenAsync(TUser user);
    public virtual string GenerateNewAuthenticatorKey();
    public virtual Task<IEnumerable<string>> GenerateNewTwoFactorRecoveryCodesAsync(TUser user, int number);
    public virtual Task<string> GeneratePasswordResetTokenAsync(TUser user);
    public virtual Task<string> GenerateTwoFactorTokenAsync(TUser user, string tokenProvider);
    public virtual Task<string> GenerateUserTokenAsync(TUser user, string tokenProvider, string purpose);  // <-------------------------!
    public virtual Task<int> GetAccessFailedCountAsync(TUser user);
    public virtual Task<string> GetAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName);
    public virtual Task<string> GetAuthenticatorKeyAsync(TUser user);
    public virtual Task<IList<Claim>> GetClaimsAsync(TUser user);
    public virtual Task<string> GetEmailAsync(TUser user);
    public virtual Task<bool> GetLockoutEnabledAsync(TUser user);
    public virtual Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user);
    public virtual Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user);
    public virtual Task<string> GetPhoneNumberAsync(TUser user);
    public virtual Task<IList<string>> GetRolesAsync(TUser user);
    public virtual Task<string> GetSecurityStampAsync(TUser user);
    public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user);
    public virtual Task<TUser> GetUserAsync(ClaimsPrincipal principal);
    public virtual string GetUserId(ClaimsPrincipal principal);
    public virtual Task<string> GetUserIdAsync(TUser user);
    public virtual string GetUserName(ClaimsPrincipal principal);
    public virtual Task<string> GetUserNameAsync(TUser user);
    public virtual Task<IList<TUser>> GetUsersForClaimAsync(Claim claim);
    public virtual Task<IList<TUser>> GetUsersInRoleAsync(string roleName);
    public virtual Task<IList<string>> GetValidTwoFactorProvidersAsync(TUser user);
    public virtual Task<bool> HasPasswordAsync(TUser user);
    public virtual Task<bool> IsEmailConfirmedAsync(TUser user);
    public virtual Task<bool> IsInRoleAsync(TUser user, string role);
    public virtual Task<bool> IsLockedOutAsync(TUser user);
    public virtual Task<bool> IsPhoneNumberConfirmedAsync(TUser user);
    public virtual string NormalizeEmail(string email);
    public virtual string NormalizeName(string name);
    public virtual Task<IdentityResult> RedeemTwoFactorRecoveryCodeAsync(TUser user, string code);
    public virtual void RegisterTokenProvider(string providerName, IUserTwoFactorTokenProvider<TUser> provider);
    public virtual Task<IdentityResult> RemoveAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName);
    public virtual Task<IdentityResult> RemoveClaimAsync(TUser user, Claim claim);
    public virtual Task<IdentityResult> RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims);
    public virtual Task<IdentityResult> RemoveFromRoleAsync(TUser user, string role);
    public virtual Task<IdentityResult> RemoveFromRolesAsync(TUser user, IEnumerable<string> roles);
    public virtual Task<IdentityResult> RemoveLoginAsync(TUser user, string loginProvider, string providerKey);
    public virtual Task<IdentityResult> RemovePasswordAsync(TUser user);
    public virtual Task<IdentityResult> ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim);
    public virtual Task<IdentityResult> ResetAccessFailedCountAsync(TUser user);
    public virtual Task<IdentityResult> ResetAuthenticatorKeyAsync(TUser user);
    public virtual Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword);
    public virtual Task<IdentityResult> SetAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName, string tokenValue);
    public virtual Task<IdentityResult> SetEmailAsync(TUser user, string email);
    public virtual Task<IdentityResult> SetLockoutEnabledAsync(TUser user, bool enabled);
    public virtual Task<IdentityResult> SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd);
    public virtual Task<IdentityResult> SetPhoneNumberAsync(TUser user, string phoneNumber);
    public virtual Task<IdentityResult> SetTwoFactorEnabledAsync(TUser user, bool enabled);
    public virtual Task<IdentityResult> SetUserNameAsync(TUser user, string userName);
    public virtual Task<IdentityResult> UpdateAsync(TUser user);
    public virtual Task UpdateNormalizedEmailAsync(TUser user);
    public virtual Task UpdateNormalizedUserNameAsync(TUser user);
    public virtual Task<IdentityResult> UpdateSecurityStampAsync(TUser user);
    public virtual Task<bool> VerifyChangePhoneNumberTokenAsync(TUser user, string token, string phoneNumber);
    public virtual Task<bool> VerifyChangePhoneNumberTokenAsync(TUser user, string token, string phoneNumber);
    public virtual Task<bool> VerifyTwoFactorTokenAsync(TUser user, string tokenProvider, string token);
    public virtual Task<bool> VerifyUserTokenAsync(TUser user, string tokenProvider, string purpose, string token);  // <---------------------------!
    protected virtual string CreateTwoFactorRecoveryCode();
    protected virtual void Dispose(bool disposing);
    protected void ThrowIfDisposed();
    protected virtual Task<IdentityResult> UpdatePasswordHash(TUser user, string newPassword, bool validatePassword);
    protected virtual Task<IdentityResult> UpdateUserAsync(TUser user);
    protected Task<IdentityResult> ValidatePasswordAsync(TUser user, string password);
    protected Task<IdentityResult> ValidateUserAsync(TUser user);
    protected virtual Task<PasswordVerificationResult> VerifyPasswordAsync(IUserPasswordStore<TUser> store, TUser user, string password);
}
//-----------------------------Ʌ
```

```C#
//------------------------------>>
public interface IRoleClaimStore
{
    Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken));
    Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken));
    Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken));
}
//------------------------------<<

//-------------------------------------------V
public class RoleManager<TRole> : IDisposable
{
    private bool _disposed;
    protected virtual CancellationToken CancellationToken => CancellationToken.None;

    public RoleManager(IRoleStore<TRole> store, IEnumerable<IRoleValidator<TRole>> roleValidators, 
                       ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, ILogger<RoleManager<TRole>> logger)
    {
        Store = store;
        KeyNormalizer = keyNormalizer;
        ErrorDescriber = errors;
        Logger = logger;
 
        if (roleValidators != null)
        {
            foreach (var v in roleValidators)
            {
                RoleValidators.Add(v);
            }
        }
    }

    protected IRoleStore<TRole> Store { get; private set; }

    public virtual ILogger Logger { get; set; }

    public IList<IRoleValidator<TRole>> RoleValidators { get; } = new List<IRoleValidator<TRole>>();

    public IdentityErrorDescriber ErrorDescriber { get; set; }

    public ILookupNormalizer KeyNormalizer { get; set; }

    public virtual IQueryable<TRole> Roles
    {
        get
        {
            var queryableStore = Store as IQueryableRoleStore<TRole>;
            if (queryableStore == null)
            {
                throw new NotSupportedException(Resources.StoreNotIQueryableRoleStore);
            }
            return queryableStore.Roles;
        }
    }

    public virtual bool SupportsQueryableRoles
    {
        get
        {
            return Store is IQueryableRoleStore<TRole>;
        }
    }

    public virtual bool SupportsRoleClaims
    {
        get
        {
            return Store is IRoleClaimStore<TRole>;
        }
    }

    public virtual async Task<IdentityResult> CreateAsync(TRole role)
    {
        var result = await ValidateRoleAsync(role).ConfigureAwait(false);
        
        if (!result.Succeeded)
        {
            return result;
        }

        await UpdateNormalizedRoleNameAsync(role).ConfigureAwait(false);
        result = await Store.CreateAsync(role, CancellationToken).ConfigureAwait(false);
        
        return result;
    }

    public virtual async Task UpdateNormalizedRoleNameAsync(TRole role)
    {
        var name = await GetRoleNameAsync(role).ConfigureAwait(false);
        await Store.SetNormalizedRoleNameAsync(role, NormalizeKey(name), CancellationToken).ConfigureAwait(false);
    }

    public virtual Task<IdentityResult> UpdateAsync(TRole role) => UpdateRoleAsync(role);
   
    public virtual Task<IdentityResult> DeleteAsync(TRole role) => Store.DeleteAsync(role, CancellationToken);

    public virtual async Task<bool> RoleExistsAsync(string roleName) => await FindByNameAsync(roleName).ConfigureAwait(false) != null;

    public virtual string? NormalizeKey(string? key) => (KeyNormalizer == null) ? key : KeyNormalizer.NormalizeName(key);

    public virtual Task<TRole?> FindByIdAsync(string roleId) => Store.FindByIdAsync(roleId, CancellationToken);

    public virtual Task<string?> GetRoleNameAsync(TRole role) => Store.GetRoleNameAsync(role, CancellationToken);

    public virtual async Task<IdentityResult> SetRoleNameAsync(TRole role, string? name)
    {
        await Store.SetRoleNameAsync(role, name, CancellationToken).ConfigureAwait(false);
        await UpdateNormalizedRoleNameAsync(role).ConfigureAwait(false);
        return IdentityResult.Success;
    }

    public virtual Task<string> GetRoleIdAsync(TRole role) => Store.GetRoleIdAsync(role, CancellationToken);

    public virtual Task<TRole?> FindByNameAsync(string roleName) => Store.FindByNameAsync(NormalizeKey(roleName), CancellationToken);
   
    public virtual async Task<IdentityResult> AddClaimAsync(TRole role, Claim claim)
    {
        var claimStore = GetClaimStore();
 
        await claimStore.AddClaimAsync(role, claim, CancellationToken).ConfigureAwait(false);
        return await UpdateRoleAsync(role).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> RemoveClaimAsync(TRole role, Claim claim)
    {
        var claimStore = GetClaimStore();
 
        await claimStore.RemoveClaimAsync(role, claim, CancellationToken).ConfigureAwait(false);
        return await UpdateRoleAsync(role).ConfigureAwait(false);
    }

    public virtual Task<IList<Claim>> GetClaimsAsync(TRole role)
    {
        var claimStore = GetClaimStore();
        return claimStore.GetClaimsAsync(role, CancellationToken);
    }

    protected virtual async Task<IdentityResult> ValidateRoleAsync(TRole role)
    {
        List<IdentityError>? errors = null;
        foreach (var v in RoleValidators)
        {
            var result = await v.ValidateAsync(this, role).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                errors ??= new List<IdentityError>();
                errors.AddRange(result.Errors);
            }
        }
        if (errors?.Count > 0)
        {
            if (Logger.IsEnabled(LogLevel.Warning))
            {
                Logger.LogWarning(LoggerEventIds.RoleValidationFailed, "Role {roleId} validation failed: {errors}.", await GetRoleIdAsync(role).ConfigureAwait(false), string.Join(";", errors.Select(e => e.Code)));
            }
            return IdentityResult.Failed(errors);
        }
        return IdentityResult.Success;
    }

    protected virtual async Task<IdentityResult> UpdateRoleAsync(TRole role)
    {
        var result = await ValidateRoleAsync(role).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return result;
        }
        await UpdateNormalizedRoleNameAsync(role).ConfigureAwait(false);
        return await Store.UpdateAsync(role, CancellationToken).ConfigureAwait(false);
    }

    private IRoleClaimStore<TRole> GetClaimStore()
    {
        var cast = Store as IRoleClaimStore<TRole>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIRoleClaimStore);
        }
        return cast;
    }
}
//-------------------------------------------Ʌ

//----------------------------V
public class IdentityConstants
{
    private const string IdentityPrefix = "Identity";
    public static readonly string ApplicationScheme = IdentityPrefix + ".Application";
    public static readonly string BearerScheme = IdentityPrefix + ".Bearer";
    internal const string BearerAndApplicationScheme = IdentityPrefix + ".BearerAndApplication";
    public static readonly string ExternalScheme = IdentityPrefix + ".External";
    public static readonly string TwoFactorRememberMeScheme = IdentityPrefix + ".TwoFactorRememberMe";
    public static readonly string TwoFactorUserIdScheme = IdentityPrefix + ".TwoFactorUserId";
}
//----------------------------Ʌ
```


```C#
//------------------------------------------------->>
public interface IUserTwoFactorTokenProvider<TUser>
{
    Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user);
    Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user);
    Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user);
}
//-------------------------------------------------<<

//--------------------------------------------------------------V
public abstract class TotpSecurityStampBasedTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser>
{
    public virtual async Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
    {
        var token = await manager.CreateSecurityTokenAsync(user).ConfigureAwait(false);
        var modifier = await GetUserModifierAsync(purpose, manager, user).ConfigureAwait(false);
 
        return Rfc6238AuthenticationService.GenerateCode(token, modifier).ToString("D6", CultureInfo.InvariantCulture);
    }

    public virtual async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
    {
        int code;
        if (!int.TryParse(token, out code))
        {
            return false;
        }
        var securityToken = await manager.CreateSecurityTokenAsync(user).ConfigureAwait(false);
        var modifier = await GetUserModifierAsync(purpose, manager, user).ConfigureAwait(false);
 
        return securityToken != null && Rfc6238AuthenticationService.ValidateCode(securityToken, code, modifier);
    }

    public virtual async Task<string> GetUserModifierAsync(string purpose, UserManager<TUser> manager, TUser user)
    {
        var userId = await manager.GetUserIdAsync(user).ConfigureAwait(false);
 
        return $"Totp:{purpose}:{userId}";
    }

    public abstract Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user);
}
//--------------------------------------------------------------Ʌ

//------------------------------------V
public class EmailTokenProvider<TUser> : TotpSecurityStampBasedTokenProvider<TUser>
{
    public override async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
    {
        var email = await manager.GetEmailAsync(user).ConfigureAwait(false);
 
        return !string.IsNullOrWhiteSpace(email) && await manager.IsEmailConfirmedAsync(user).ConfigureAwait(false);
    }

    public override async Task<string> GetUserModifierAsync(string purpose, UserManager<TUser> manager, TUser user)
    {
        var email = await manager.GetEmailAsync(user).ConfigureAwait(false);
 
        return $"Email:{purpose}:{email}";
    }
}
//------------------------------------Ʌ

//------------------------------------------V
public class PhoneNumberTokenProvider<TUser> : TotpSecurityStampBasedTokenProvider<TUser>
{
    public override async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
    {
        ArgumentNullThrowHelper.ThrowIfNull(manager);
 
        var phoneNumber = await manager.GetPhoneNumberAsync(user).ConfigureAwait(false);
 
        return !string.IsNullOrWhiteSpace(phoneNumber) && await manager.IsPhoneNumberConfirmedAsync(user).ConfigureAwait(false);
    }

    public override async Task<string> GetUserModifierAsync(string purpose, UserManager<TUser> manager, TUser user)
    {
        ArgumentNullThrowHelper.ThrowIfNull(manager);
 
        var phoneNumber = await manager.GetPhoneNumberAsync(user).ConfigureAwait(false);
 
        return $"PhoneNumber:{purpose}:{phoneNumber}";
    }
}
//------------------------------------------Ʌ

//--------------------------------------------V
public class AuthenticatorTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser>
{
    public virtual async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
    {
        var key = await manager.GetAuthenticatorKeyAsync(user).ConfigureAwait(false);
 
        return !string.IsNullOrWhiteSpace(key);
    }

    public virtual Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
    {
        return Task.FromResult(string.Empty);
    }

    public virtual async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
    {
        var key = await manager.GetAuthenticatorKeyAsync(user).ConfigureAwait(false);
        int code;
        if (key == null || !int.TryParse(token, out code))
        {
            return false;
        }
 
        var keyBytes = Base32.FromBase32(key);
 
        var unixTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
 
        var timestep = Convert.ToInt64(unixTimestamp / 30);
        for (int i = -2; i <= 2; i++)
        {
            var expectedCode = Rfc6238AuthenticationService.ComputeTotp(keyBytes, (ulong)(timestep + i), modifierBytes: null);

            if (expectedCode == code)
            {
                return true;
            }
        }
 
        return false;
    }
}
//--------------------------------------------Ʌ
```

```C#
//--------------------------------------V
public interface ILookupProtectorKeyRing
{
    string CurrentKeyId { get; }
    string this[string keyId] { get; }
    IEnumerable<string> GetAllKeyIds();
}
//--------------------------------------Ʌ

//-------------------------------V
public interface ILookupProtector
{
    string? Protect(string keyId, string? data);
    string? Unprotect(string keyId, string? data);
}
//-------------------------------Ʌ
```