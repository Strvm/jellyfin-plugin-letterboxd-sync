using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using MediaBrowser.Controller.Playlists;

namespace LetterboxdSync;

/// <summary>
/// Adds items to playlists across server versions with different <see cref="IPlaylistManager"/> APIs.
/// Jellyfin 12.0 added an <c>int? position</c> parameter to <c>AddItemToPlaylistAsync</c>, so a direct call
/// compiled against either signature throws <see cref="MissingMethodException"/> on the other servers.
/// The overload is resolved at runtime against the server's own <see cref="IPlaylistManager"/>.
/// </summary>
internal static class PlaylistManagerCompat
{
    private static readonly Lazy<Func<object, Guid, IReadOnlyCollection<Guid>, Guid, Task>> _addItems =
        new(() => CreateAddItemsAccessor(typeof(IPlaylistManager)));

    /// <summary>
    /// Appends items to the end of a playlist.
    /// </summary>
    /// <param name="playlistManager">The server playlist manager.</param>
    /// <param name="playlistId">The playlist identifier.</param>
    /// <param name="itemIds">The item identifiers.</param>
    /// <param name="userId">The user identifier.</param>
    /// <returns>A task that completes when the items are added.</returns>
    public static Task AddItemToPlaylistAsync(
        IPlaylistManager playlistManager,
        Guid playlistId,
        IReadOnlyCollection<Guid> itemIds,
        Guid userId)
    {
        ArgumentNullException.ThrowIfNull(playlistManager);
        return _addItems.Value(playlistManager, playlistId, itemIds, userId);
    }

    /// <summary>
    /// Builds an accessor for the <c>AddItemToPlaylistAsync</c> overload exposed by <paramref name="playlistManagerType"/>.
    /// </summary>
    /// <param name="playlistManagerType">The playlist manager type to inspect.</param>
    /// <returns>A function that appends items to a playlist of a playlist manager instance.</returns>
    internal static Func<object, Guid, IReadOnlyCollection<Guid>, Guid, Task> CreateAddItemsAccessor(Type playlistManagerType)
    {
        ArgumentNullException.ThrowIfNull(playlistManagerType);

        const BindingFlags Flags = BindingFlags.Public | BindingFlags.Instance;

        // Jellyfin >= 12.0: AddItemToPlaylistAsync(Guid playlistId, IReadOnlyCollection<Guid> itemIds, int? position, Guid userId)
        var withPosition = playlistManagerType.GetMethod(
            "AddItemToPlaylistAsync",
            Flags,
            new[] { typeof(Guid), typeof(IReadOnlyCollection<Guid>), typeof(int?), typeof(Guid) });
        if (withPosition != null && typeof(Task).IsAssignableFrom(withPosition.ReturnType))
        {
            // A null position appends at the end, matching the older overload.
            return (target, playlistId, itemIds, userId) =>
                (Task)withPosition.Invoke(target, BindingFlags.DoNotWrapExceptions, null, new object?[] { playlistId, itemIds, null, userId }, null)!;
        }

        // Jellyfin <= 10.11: AddItemToPlaylistAsync(Guid playlistId, IReadOnlyCollection<Guid> itemIds, Guid userId)
        var legacy = playlistManagerType.GetMethod(
            "AddItemToPlaylistAsync",
            Flags,
            new[] { typeof(Guid), typeof(IReadOnlyCollection<Guid>), typeof(Guid) });
        if (legacy != null && typeof(Task).IsAssignableFrom(legacy.ReturnType))
        {
            return (target, playlistId, itemIds, userId) =>
                (Task)legacy.Invoke(target, BindingFlags.DoNotWrapExceptions, null, new object?[] { playlistId, itemIds, userId }, null)!;
        }

        throw new MissingMethodException(
            $"{playlistManagerType.FullName} exposes no supported AddItemToPlaylistAsync overload; this Jellyfin version is not supported.");
    }
}
