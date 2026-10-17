using System;
using System.Collections.Generic;
using System.Reflection;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Library;

namespace LetterboxdSync;

/// <summary>
/// Enumerates Jellyfin users across server versions with different <see cref="IUserManager"/> APIs.
/// Jellyfin 10.11.9 replaced the <c>Users</c> property with a <c>GetUsers()</c> method, so a direct call
/// to either one throws <see cref="MissingMethodException"/> on the other half of the servers.
/// The member is resolved at runtime against the server's own <see cref="IUserManager"/>.
/// </summary>
internal static class UserManagerCompat
{
    private static readonly Lazy<Func<object, IEnumerable<User>>> _getUsers =
        new(() => CreateAccessor(typeof(IUserManager)));

    /// <summary>
    /// Gets all users from the server.
    /// </summary>
    /// <param name="userManager">The server user manager.</param>
    /// <returns>The users.</returns>
    public static IEnumerable<User> GetUsers(IUserManager userManager)
    {
        ArgumentNullException.ThrowIfNull(userManager);
        return _getUsers.Value(userManager);
    }

    /// <summary>
    /// Builds an accessor for the user list exposed by <paramref name="userManagerType"/>.
    /// </summary>
    /// <param name="userManagerType">The user manager type to inspect.</param>
    /// <returns>A function that returns the users of a user manager instance.</returns>
    internal static Func<object, IEnumerable<User>> CreateAccessor(Type userManagerType)
    {
        ArgumentNullException.ThrowIfNull(userManagerType);

        // Jellyfin >= 10.11.9: IEnumerable<User> GetUsers(); Jellyfin <= 10.11.8: IEnumerable<User> Users { get; }
        var getter = userManagerType.GetMethod("GetUsers", BindingFlags.Public | BindingFlags.Instance, Type.EmptyTypes)
            ?? userManagerType.GetProperty("Users", BindingFlags.Public | BindingFlags.Instance)?.GetMethod;

        if (getter == null || !typeof(IEnumerable<User>).IsAssignableFrom(getter.ReturnType))
        {
            throw new MissingMethodException(
                $"{userManagerType.FullName} exposes neither GetUsers() nor Users returning IEnumerable<User>; this Jellyfin version is not supported.");
        }

        return target => (IEnumerable<User>)getter.Invoke(target, BindingFlags.DoNotWrapExceptions, null, null, null)!;
    }
}
