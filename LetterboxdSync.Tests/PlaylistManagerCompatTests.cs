using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using MediaBrowser.Controller.Playlists;
using Xunit;

namespace LetterboxdSync.Tests;

public class PlaylistManagerCompatTests
{
    // Shape of IPlaylistManager.AddItemToPlaylistAsync on Jellyfin <= 10.11.
    public interface ILegacyPlaylistManager
    {
        Task AddItemToPlaylistAsync(Guid playlistId, IReadOnlyCollection<Guid> itemIds, Guid userId);
    }

    // Shape of IPlaylistManager.AddItemToPlaylistAsync on Jellyfin >= 12.0.
    public interface ICurrentPlaylistManager
    {
        Task AddItemToPlaylistAsync(Guid playlistId, IReadOnlyCollection<Guid> itemIds, int? position, Guid userId);
    }

    public interface IUnsupportedPlaylistManager
    {
        Task AddItemToPlaylistAsync(string playlistId, IEnumerable<Guid> itemIds);
    }

    private sealed class LegacyPlaylistManager : ILegacyPlaylistManager
    {
        public List<object?[]> Calls { get; } = new();

        public Task AddItemToPlaylistAsync(Guid playlistId, IReadOnlyCollection<Guid> itemIds, Guid userId)
        {
            Calls.Add(new object?[] { playlistId, itemIds, userId });
            return Task.CompletedTask;
        }
    }

    private sealed class CurrentPlaylistManager : ICurrentPlaylistManager
    {
        public List<object?[]> Calls { get; } = new();

        public Task AddItemToPlaylistAsync(Guid playlistId, IReadOnlyCollection<Guid> itemIds, int? position, Guid userId)
        {
            Calls.Add(new object?[] { playlistId, itemIds, position, userId });
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingPlaylistManager : ICurrentPlaylistManager
    {
        public Task AddItemToPlaylistAsync(Guid playlistId, IReadOnlyCollection<Guid> itemIds, int? position, Guid userId) =>
            throw new InvalidOperationException("boom");
    }

    private static readonly Guid PlaylistId = Guid.NewGuid();
    private static readonly Guid UserId = Guid.NewGuid();
    private static readonly IReadOnlyCollection<Guid> ItemIds = new[] { Guid.NewGuid(), Guid.NewGuid() };

    [Fact]
    public async Task CreateAddItemsAccessor_LegacyOverload_PassesArguments()
    {
        var manager = new LegacyPlaylistManager();
        var accessor = PlaylistManagerCompat.CreateAddItemsAccessor(typeof(ILegacyPlaylistManager));

        await accessor(manager, PlaylistId, ItemIds, UserId);

        var call = Assert.Single(manager.Calls);
        Assert.Equal(new object?[] { PlaylistId, ItemIds, UserId }, call);
    }

    [Fact]
    public async Task CreateAddItemsAccessor_PositionOverload_AppendsAtEnd()
    {
        var manager = new CurrentPlaylistManager();
        var accessor = PlaylistManagerCompat.CreateAddItemsAccessor(typeof(ICurrentPlaylistManager));

        await accessor(manager, PlaylistId, ItemIds, UserId);

        var call = Assert.Single(manager.Calls);
        Assert.Equal(new object?[] { PlaylistId, ItemIds, null, UserId }, call);
    }

    [Fact]
    public async Task CreateAddItemsAccessor_ServerThrows_PropagatesOriginalException()
    {
        var accessor = PlaylistManagerCompat.CreateAddItemsAccessor(typeof(ICurrentPlaylistManager));

        await Assert.ThrowsAsync<InvalidOperationException>(() => accessor(new ThrowingPlaylistManager(), PlaylistId, ItemIds, UserId));
    }

    [Fact]
    public void CreateAddItemsAccessor_NoSupportedOverload_ThrowsMissingMethod()
    {
        Assert.Throws<MissingMethodException>(() => PlaylistManagerCompat.CreateAddItemsAccessor(typeof(IUnsupportedPlaylistManager)));
    }

    [Fact]
    public void CreateAddItemsAccessor_ReferencedIPlaylistManager_Resolves()
    {
        Assert.NotNull(PlaylistManagerCompat.CreateAddItemsAccessor(typeof(IPlaylistManager)));
    }
}
