using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ExampleApp.Identity
{
    public abstract class SimpleTokenGenerator : IUserTwoFactorTokenProvider<AppUser>
    {
        protected virtual int CodeLength { get; } = 6;

        public virtual Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<AppUser> manager, AppUser user)
        {
            return Task.FromResult(manager.SupportsUserSecurityStamp);
        }

        public virtual Task<string> GenerateAsync(string purpose, UserManager<AppUser> manager, AppUser user)
            => Task.FromResult(GenerateCode(purpose, user));

        public virtual Task<bool> ValidateAsync(string purpose, string token, UserManager<AppUser> manager, AppUser user)    
            => Task.FromResult(GenerateCode(purpose, user).Equals(token));


        // it is important for purpose to contains new email/phone value, becuase if it doesn't and only contains  "ChangeEmail" or "ChangePhoneNumber"
        // user can do tricky things such as change email address once to get the token, and then before entering token in UI to validate, users changes 
        // the email address again then validate token. user.SecurityStamp is used to prevent the scenario that users change some other properties then validate with token
        protected virtual string GenerateCode(string purpose, AppUser user)  // purpose contains "ChangeEmail:" or "ChangePhoneNumber:" prefix plus new value of email/number
        {                                                                    // such as "ChangeEmail:newEmailAddress" or "ChangePhoneNumber:newNumber"
            HMACSHA1 hashAlgorithm = new HMACSHA1(Encoding.UTF8.GetBytes(user.SecurityStamp));
           
            byte[] hashCode = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(GetData(purpose, user)));

            string token = BitConverter.ToString(hashCode[^CodeLength..]).Replace("-", "");  // token is associated to purpose and user.SecurityStamp only
                                                                                             // doesn't associated with user's other properties
            return token;
        }
        
        protected virtual string GetData(string purpose, AppUser user) => $"{purpose}{user.SecurityStamp}";
    }

    public class EmailConfirmationTokenGenerator : SimpleTokenGenerator
    {
        protected override int CodeLength => 12;
        public async override Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<AppUser> manager, AppUser user)
        {
            return await base.CanGenerateTwoFactorTokenAsync(manager, user) && !string.IsNullOrEmpty(user.EmailAddress) && !user.EmailAddressConfirmed;
        }
    }

    public class PhoneConfirmationTokenGenerator : SimpleTokenGenerator
    {
        protected override int CodeLength => 3;
        public async override Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<AppUser> manager, AppUser user)
        {
            return await base.CanGenerateTwoFactorTokenAsync(manager, user) && !string.IsNullOrEmpty(user.PhoneNumber) && !user.PhoneNumberConfirmed;
        }
    }
}