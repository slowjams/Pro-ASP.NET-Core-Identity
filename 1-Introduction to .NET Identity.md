Introduction to .NET Identity
==============================

```C#
/*
public static class ClaimTypes
{
   public const string Actor = "http://schemas.xmlsoap.org/ws/2009/09/identity/claims/actor";
   public const string Role = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
   public const string Rsa = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/rsa";
   public const string Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
   public const string Email = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
   public const string Gender = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender";
   public const string GivenName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";
   // ...
}
*/

//----------------V
public class Claim
{
   private enum SerializationMask
   {
      None = 0,
      NameClaimType = 1,
      RoleClaimType = 2,
      StringType = 4,
      Issuer = 8,
      OriginalIssuerEqualsIssuer = 16,
      OriginalIssuer = 32,
      HasProperties = 64,
      UserData = 128,
   }
   
   private readonly byte[] _userSerializationData;
 
   private readonly string _issuer;
   private readonly string _originalIssuer;
   private Dictionary<string, string> _properties;
 
   private readonly ClaimsIdentity _subject;
   private readonly string _type;
   private readonly string _value;
   private readonly string _valueType;

   public Claim(BinaryReader reader) : this(reader, null) { }

   public Claim(BinaryReader reader, ClaimsIdentity subject)
   {
      _subject = subject;

      SerializationMask mask = (SerializationMask)reader.ReadInt32();
      int numPropertiesRead = 1;
      int numPropertiesToRead = reader.ReadInt32();
      _value = reader.ReadString();

      if ((mask & SerializationMask.NameClaimType) == SerializationMask.NameClaimType) {
         _type = ClaimsIdentity.DefaultNameClaimType;
      }
      else if ((mask & SerializationMask.RoleClaimType) == SerializationMask.RoleClaimType) {
         _type = ClaimsIdentity.DefaultRoleClaimType;
      }
      else {
         _type = reader.ReadString();
      }

      // ...
   }

   protected Claim(Claim other) : this(other, (other == null ? (ClaimsIdentity)null : other._subject)) { }

   protected Claim(Claim other, ClaimsIdentity? subject) {
       // ...
   }

   public Claim(string type, string value) : this(type, value, ClaimValueTypes.String, ClaimsIdentity.DefaultIssuer, ClaimsIdentity.DefaultIssuer, (ClaimsIdentity?)null) { }

   internal Claim(string type, string value, string valueType, string issuer, string originalIssuer, ClaimsIdentity subject, string propertyKey, string propertyValue)
   {
      _type = type;
      _value = value;
      _valueType = string.IsNullOrEmpty(valueType) ? ClaimValueTypes.String : valueType;
      _issuer = string.IsNullOrEmpty(issuer) ? ClaimsIdentity.DefaultIssuer : issuer;
      _originalIssuer = string.IsNullOrEmpty(originalIssuer) ? _issuer : originalIssuer;
      _subject = subject;
 
      if (propertyKey != null)
      {
         _properties = new Dictionary<string, string>();
         _properties[propertyKey] = propertyValue!;
      }
   }

   protected virtual byte[] CustomSerializationData => _userSerializationData;

   //
   public string Issuer => _issuer;

   public string OriginalIssuer => _originalIssuer;

   public IDictionary<string, string> Properties => _properties ??= new Dictionary<string, string>();

   public ClaimsIdentity Subject => _subject;

   public string Type => _type;

   public string Value => _value;

   public string ValueType => _valueType;
   //

   public virtual Claim Clone()
   {
      return Clone((ClaimsIdentity)null);
   }

   public virtual Claim Clone(ClaimsIdentity identity)
   {
      return new Claim(this, identity);
   }

   public virtual void WriteTo(BinaryWriter writer)
   {
      WriteTo(writer, null);
   }

   protected virtual void WriteTo(BinaryWriter writer, byte[] userData)
   {
      // ...
   }
   public override string ToString()
   {
      return _type + ": " + _value;
   }
}
//----------------Ʌ

//------------------------>>
public interface IIdentity
{
   string AuthenticationType { get; }
   bool IsAuthenticated { get; }
   string Name { get; }
}
//------------------------<<

//-------------------------V
public class ClaimsIdentity : IIdentity
{
   private enum SerializationMask
   {
      None = 0,
      AuthenticationType = 1,
      BootstrapConext = 2,
      NameClaimType = 4,
      RoleClaimType = 8,
      HasClaims = 16,
      HasLabel = 32,
      Actor = 64,
      UserData = 128,
   }

   private byte[]? _userSerializationData;
   private ClaimsIdentity? _actor;
   private string? _authenticationType;
   private object? _bootstrapContext;
   private List<List<Claim>>? _externalClaims;
   private string? _label;
   private readonly List<Claim> _instanceClaims = new List<Claim>();
   private string _nameClaimType = DefaultNameClaimType;
   private string _roleClaimType = DefaultRoleClaimType;
 
   public const string DefaultIssuer = @"LOCAL AUTHORITY";
   public const string DefaultNameClaimType = ClaimTypes.Name;
   public const string DefaultRoleClaimType = ClaimTypes.Role;

   public ClaimsIdentity() : this((IIdentity?)null, (IEnumerable<Claim>?)null, (string?)null, (string?)null, (string?)null) { }

   public ClaimsIdentity(IIdentity identity) : this(identity, (IEnumerable<Claim>?)null, (string?)null, (string?)null, (string?)null) { }

   public ClaimsIdentity(string? authenticationType) : this((IIdentity?)null, (IEnumerable<Claim>?)null, authenticationType, (string?)null, (string?)null) { }

   public ClaimsIdentity(IEnumerable<Claim>? claims, string? authenticationType) : this((IIdentity?)null, claims, authenticationType, (string?)null, (string?)null) { }

   public ClaimsIdentity(IIdentity? identity, IEnumerable<Claim>? claims) : this(identity, claims, (string?)null, (string?)null, (string?)null) { }

   public ClaimsIdentity(string? authenticationType, string? nameType, string? roleType) : this(...) { }

   public ClaimsIdentity(IEnumerable<Claim>? claims, string? authenticationType, string? nameType, string? roleType) : this(...) { }

   public ClaimsIdentity(IIdentity? identity, IEnumerable<Claim>? claims, string? authenticationType, string? nameType, string? roleType)
   {
      ClaimsIdentity? claimsIdentity = identity as ClaimsIdentity;

      _authenticationType = (identity != null && string.IsNullOrEmpty(authenticationType)) ? identity.AuthenticationType : authenticationType;
      _nameClaimType = !string.IsNullOrEmpty(nameType) ? nameType : (claimsIdentity != null ? claimsIdentity._nameClaimType : DefaultNameClaimType);
      _roleClaimType = !string.IsNullOrEmpty(roleType) ? roleType : (claimsIdentity != null ? claimsIdentity._roleClaimType : DefaultRoleClaimType);

      if (claimsIdentity != null)
      {
         _label = claimsIdentity._label;
         _bootstrapContext = claimsIdentity._bootstrapContext;

         if (claimsIdentity.Actor != null)
         {
            if (!IsCircular(claimsIdentity.Actor))
            {
               _actor = claimsIdentity.Actor;
            }
            else
            {
               throw new InvalidOperationException(SR.InvalidOperationException_ActorGraphCircular);
            }
         }
         SafeAddClaims(claimsIdentity._instanceClaims);
      }
      else {
         if (identity != null && !string.IsNullOrEmpty(identity.Name))
         {
            SafeAddClaim(new Claim(_nameClaimType, identity.Name, ClaimValueTypes.String, DefaultIssuer, DefaultIssuer, this));
         }
      }

      if (claims != null)
      {
         SafeAddClaims(claims);
      }
   }

   public ClaimsIdentity(BinaryReader reader) 
   {
      Initialize(reader);
   }

   protected ClaimsIdentity(ClaimsIdentity other)
   {
      if (other._actor != null)
      {
         _actor = other._actor.Clone();
      }
 
      _authenticationType = other._authenticationType;
      _bootstrapContext = other._bootstrapContext;
      _label = other._label;
      _nameClaimType = other._nameClaimType;
      _roleClaimType = other._roleClaimType;
      if (other._userSerializationData != null)
      {
         _userSerializationData = other._userSerializationData.Clone() as byte[];
      }
 
      SafeAddClaims(other._instanceClaims);
   }

   protected virtual byte[]? CustomSerializationData => _userSerializationData;

   internal List<List<Claim>> ExternalClaims => _externalClaims ??= new List<List<Claim>>();

   public string? Label { get { return _label; } set { _label = value; } }

   public string NameClaimType => _nameClaimType;

   public string RoleClaimType => _roleClaimType;
  
   public virtual string? AuthenticationType => _authenticationType;

   public virtual bool IsAuthenticated
   {
      get { return !string.IsNullOrEmpty(_authenticationType); }
   } 

   public virtual string? Name
   {
      get {
         Claim? claim = FindFirst(_nameClaimType);
         if (claim != null)
            return claim.Value;
 
         return null;
      }      
   }

   public ClaimsIdentity? Actor
   {
      get { return _actor; }
      set {
         if (value != null) 
         {
            if (IsCircular(value))
               throw new InvalidOperationException(SR.InvalidOperationException_ActorGraphCircular);                  
         }
         _actor = value;
      }
   } 

   public object? BootstrapContext
   {
      get { return _bootstrapContext; }
      set { _bootstrapContext = value; }
   }

   public virtual IEnumerable<Claim> Claims
   {
      get {
         if (_externalClaims == null)
             return _instanceClaims;
 
         return CombinedClaimsIterator();
      }
   }

   private IEnumerable<Claim> CombinedClaimsIterator()
   {
      for (int i = 0; i < _instanceClaims.Count; i++)
         yield return _instanceClaims[i];
 
      for (int j = 0; j < _externalClaims!.Count; j++)
      {
         if (_externalClaims[j] != null)
         {
            foreach (Claim claim in _externalClaims[j])
               yield return claim;
         }
      }
   }

   public virtual void AddClaim(Claim claim)
   {
      ArgumentNullException.ThrowIfNull(claims);

      if (object.ReferenceEquals(claim.Subject, this))
         _instanceClaims.Add(claim);
      else
         _instanceClaims.Add(claim.Clone(this));
   }

   public virtual void AddClaims(IEnumerable<Claim?> claims);

   // no ArgumentNullException.ThrowIfNull(claims);
   private void SafeAddClaim(Claim? claim);
   private void SafeAddClaims(IEnumerable<Claim?> claims);
   //

   public virtual bool TryRemoveClaim(Claim? claim)
   {
      if (claim == null)
         return false;
 
      bool removed = false;
 
      for (int i = 0; i < _instanceClaims.Count; i++)
      {
         if (object.ReferenceEquals(_instanceClaims[i], claim))
         {
            _instanceClaims.RemoveAt(i);
            removed = true;
            break;
         }
      }
      return removed;
   }

   public virtual void RemoveClaim(Claim? claim)
   {
      if (!TryRemoveClaim(claim))
         throw new InvalidOperationException(SR.Format(SR.InvalidOperation_ClaimCannotBeRemoved, claim));
            
   }

   public virtual IEnumerable<Claim> FindAll(Predicate<Claim> match)
   {
      return Core(match);
 
      IEnumerable<Claim> Core(Predicate<Claim> match)
      {
         foreach (Claim claim in Claims)
         {
            if (match(claim))
               yield return claim;
         }
      }
   }

   public virtual IEnumerable<Claim> FindAll(string type);

   public virtual Claim? FindFirst(Predicate<Claim> match);

   public virtual Claim? FindFirst(string type);

   public virtual bool HasClaim(Predicate<Claim> match);

   public virtual bool HasClaim(string type, string value);

   private bool IsCircular(ClaimsIdentity subject)
   {
      if (ReferenceEquals(this, subject))
         return true;
 
      ClaimsIdentity currSubject = subject;
 
      while (currSubject.Actor != null)
      {
         if (ReferenceEquals(this, currSubject.Actor))
            return true;
 
         currSubject = currSubject.Actor;
      }
 
      return false;
   }

   // ...  BinaryWriter related methods leaved out

   public virtual ClaimsIdentity Clone()
   {
      return new ClaimsIdentity(this);
   }
}
//-------------------------Ʌ

//------------------------->>
public interface IPrincipal
{
   IIdentity Identity { get; }
   bool IsInRole(string role);
}
//-------------------------<<

//--------------------------V
public class ClaimsPrincipal : IPrincipal
{
   private enum SerializationMask
   {
      None = 0,
      HasIdentities = 1,
      UserData = 2
   }

   private readonly List<ClaimsIdentity> _identities = new List<ClaimsIdentity>();
   private readonly byte[]? _userSerializationData;
 
   private static Func<IEnumerable<ClaimsIdentity>, ClaimsIdentity?> s_identitySelector = SelectPrimaryIdentity;
   private static Func<ClaimsPrincipal> s_principalSelector = ClaimsPrincipalSelector;
 
   public ClaimsPrincipal() { }

   public ClaimsPrincipal(IEnumerable<ClaimsIdentity> identities)
   {
      _identities.AddRange(identities);
   }

   public ClaimsPrincipal(IIdentity identity)
   { 
      if (identity is ClaimsIdentity ci)
         identities.Add(ci);
      else
         _identities.Add(new ClaimsIdentity(identity));
   }

   public ClaimsPrincipal(IPrincipal principal)
   {
      ClaimsPrincipal? cp = principal as ClaimsPrincipal;
      if (null == cp)
         _identities.Add(new ClaimsIdentity(principal.Identity));
      else
         if (null != cp.Identities)
            _identities.AddRange(cp.Identities);          
   }

   private static ClaimsPrincipal? SelectClaimsPrincipal()
   {
      IPrincipal? threadPrincipal = Thread.CurrentPrincipal;
 
      return threadPrincipal switch {
         ClaimsPrincipal claimsPrincipal => claimsPrincipal, not null => new ClaimsPrincipal(threadPrincipal), null => null
      };
   }

   private static ClaimsIdentity? SelectPrimaryIdentity(IEnumerable<ClaimsIdentity> identities)
   { 
      foreach (ClaimsIdentity identity in identities)
      {
         if (identity != null)        
            return identity;              
      }
 
      return null;
   }

   public static Func<IEnumerable<ClaimsIdentity>, ClaimsIdentity?> PrimaryIdentitySelector
   {
      get {
         return s_identitySelector;
      }
      set {
         s_identitySelector = value;
      }
   }

   public static Func<ClaimsPrincipal> ClaimsPrincipalSelector
   {
      get {
         return s_principalSelector;
      }
      set {
         s_principalSelector = value;
      }
   }

   public virtual void AddIdentity(ClaimsIdentity identity)
   { 
      _identities.Add(identity);
   }

   public virtual void AddIdentities(IEnumerable<ClaimsIdentity> identities)
   { 
      _identities.AddRange(identities);
   }

   public virtual IEnumerable<Claim> Claims
   {
      get {
         foreach (ClaimsIdentity identity in Identities) {
            foreach (Claim claim in identity.Claims) {
               yield return claim;
            }
         }
      }
   }

   protected virtual byte[]? CustomSerializationData => _userSerializationData;
  
   public virtual ClaimsPrincipal Clone() => new ClaimsPrincipal(this);

   public static ClaimsPrincipal? Current
   {
      get {
         return s_principalSelector is not null ? s_principalSelector() : SelectClaimsPrincipal();
      }
   }

   public virtual IEnumerable<Claim> FindAll(Predicate<Claim> match)
   {
      return Core(match);
 
      IEnumerable<Claim> Core(Predicate<Claim> match)
      {
         foreach (ClaimsIdentity identity in Identities)
         {
            if (identity != null)
            {
               foreach (Claim claim in identity.FindAll(match))                 
                  yield return claim;                       
            }
         }
      }
   }

   public virtual IEnumerable<Claim> FindAll(string type);

   public virtual Claim? FindFirst(Predicate<Claim> match);

   public virtual Claim? FindFirst(string type);

   public virtual bool HasClaim(Predicate<Claim> match)
   { 
      for (int i = 0; i < _identities.Count; i++)
      {
         if (_identities[i] != null)
         {
            if (_identities[i].HasClaim(match))                   
               return true;                  
         }
      }
 
      return false;
   }

   public virtual bool HasClaim(string type, string value);

   public virtual IEnumerable<ClaimsIdentity> Identities => _identities;

   public virtual System.Security.Principal.IIdentity? Identity
   {
      get {
         if (s_identitySelector != null)                
            return s_identitySelector(_identities);               
         else               
            return SelectPrimaryIdentity(_identities);               
      }
   }

   public virtual bool IsInRole(string role)
   {
      for (int i = 0; i < _identities.Count; i++)
      {
         if (_identities[i] != null)
         {
            if (_identities[i].HasClaim(_identities[i].RoleClaimType, role))             
               return true;                  
         }
      }
 
      return false;
   }
}
//--------------------------Ʌ
```