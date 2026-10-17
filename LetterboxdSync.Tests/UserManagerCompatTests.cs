using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Library;
using Xunit;

namespace LetterboxdSync.Tests;

public class UserManagerCompatTests
{
    // Shape of IUserManager on Jellyfin <= 10.11.8.
    public interface ILegacyUserManager
    {
        IEnumerable<User> Users { get; }
    }

    // Shape of IUserManager on Jellyfin >= 10.11.9 (including 12.x).
    public interface ICurrentUserManager
    {
        IEnumerable<User> GetUsers();
    }

    public interface IUnsupportedUserManager
    {
        IEnumerable<Guid> UsersIds { get; }
    }

    private sealed class LegacyUserManager(IEnumerable<User> users) : ILegacyUserManager
    {
        public IEnumerable<User> Users => users;
    }

    private sealed class CurrentUserManager(IEnumerable<User> users) : ICurrentUserManager
    {
        public IEnumerable<User> GetUsers() => users;
    }

    private static User[] CreateUsers() =>
        new[]
        {
            new User("alice", "auth", "reset"),
            new User("bob", "auth", "reset"),
        };

    [Fact]
    public void CreateAccessor_LegacyUsersProperty_ReturnsUsers()
    {
        var users = CreateUsers();
        var accessor = UserManagerCompat.CreateAccessor(typeof(ILegacyUserManager));

        Assert.Equal(users, accessor(new LegacyUserManager(users)).ToArray());
    }

    [Fact]
    public void CreateAccessor_GetUsersMethod_ReturnsUsers()
    {
        var users = CreateUsers();
        var accessor = UserManagerCompat.CreateAccessor(typeof(ICurrentUserManager));

        Assert.Equal(users, accessor(new CurrentUserManager(users)).ToArray());
    }

    [Fact]
    public void CreateAccessor_NoUserList_ThrowsMissingMethod()
    {
        Assert.Throws<MissingMethodException>(() => UserManagerCompat.CreateAccessor(typeof(IUnsupportedUserManager)));
    }

    [Fact]
    public void CreateAccessor_ReferencedIUserManager_Resolves()
    {
        Assert.NotNull(UserManagerCompat.CreateAccessor(typeof(IUserManager)));
    }
}
