using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;
using System.Text;
using System;
using System.Threading;
using System.Threading.Tasks;
using ExampleApp.Identity;

namespace ExampleApp.Identity.Store
{
    public partial class UserStore : IUserSecurityStampStore<AppUser>  // check UserManager source code's UpdateSecurityStampInternal
    {
        public Task<string> GetSecurityStampAsync(AppUser user, CancellationToken token) => Task.FromResult(user.SecurityStamp);

        public Task SetSecurityStampAsync(AppUser user, string stamp, CancellationToken token)
        {
            user.SecurityStamp = stamp;
            return Task.CompletedTask;
        }
    }
}
