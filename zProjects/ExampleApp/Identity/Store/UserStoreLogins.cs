﻿using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace ExampleApp.Identity.Store
{
    public partial class UserStore : IUserLoginStore<AppUser>
    {
        public Task<IList<UserLoginInfo>> GetLoginsAsync(AppUser user, CancellationToken token) =>
             Task.FromResult(user.UserLogins ?? new List<UserLoginInfo>());

        public Task AddLoginAsync(AppUser user, UserLoginInfo login, CancellationToken token)
        {
            if (user.UserLogins == null)
            {
                user.UserLogins = new List<UserLoginInfo>();
            }

            user.UserLogins.Add(login);
            
            return Task.CompletedTask;
        }

        public async Task RemoveLoginAsync(AppUser user, string loginProvider, string providerKey, CancellationToken token)
        {
            user.UserLogins = 
                (await GetLoginsAsync(user, token))
                .Where(login => !login.LoginProvider.Equals(loginProvider) && !login.ProviderKey.Equals(providerKey)).ToList();
        }

        public Task<AppUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken token)
        {
            return Task.FromResult(
                Users.FirstOrDefault(u => 
                    u.UserLogins != null && u.UserLogins.Any(login => login.LoginProvider.Equals(loginProvider) && login.ProviderKey.Equals(providerKey))));
        }
    }
}
