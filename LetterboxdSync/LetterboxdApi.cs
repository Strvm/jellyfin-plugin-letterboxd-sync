using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using HtmlAgilityPack;
using Microsoft.Extensions.Logging;

namespace LetterboxdSync;

public class LetterboxdApi
{
    private string csrf = string.Empty;
    private string username = string.Empty;
    private readonly ILogger? _logger;

    public string Csrf => csrf;

    // Reused for the lifetime of this LetterboxdApi instance (one sync run)
    private readonly CookieContainer cookieContainer = new CookieContainer();
    private readonly HttpClientHandler handler;
    private readonly HttpClient client;

    private static readonly Uri BaseUri = new Uri("https://letterboxd.com/");
    private static readonly Uri ApiLogEntriesUri = new Uri("https://letterboxd.com/api/v0/production-log-entries");
    private static readonly Uri ApiFallbackLogEntriesUri = new Uri("https://letterboxd.com/api/v0/log-entries");
    private static readonly JsonSerializerOptions ApiJsonSerializerOptions = new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    internal sealed record DiaryDetailsRequest(string DiaryDate, bool Rewatch);
    internal sealed record ReviewDetailsRequest(string Text, bool ContainsSpoilers);
    internal sealed class CreateLogEntryRequest
    {
        public string ProductionId { get; init; } = string.Empty;

        public DiaryDetailsRequest? DiaryDetails { get; init; }

        public ReviewDetailsRequest? Review { get; init; }

        public string[] Tags { get; init; } = [];

        public double? Rating { get; init; }

        public bool Like { get; init; }

        public string? PrivacyPolicy { get; init; }
    }

    internal sealed class FallbackCreateLogEntryRequest
    {
        public string FilmId { get; init; } = string.Empty;

        public DiaryDetailsRequest? DiaryDetails { get; init; }

        public ReviewDetailsRequest? Review { get; init; }

        public string[] Tags { get; init; } = [];

        public double? Rating { get; init; }

        public bool Like { get; init; }

        public string? PrivacyPolicy { get; init; }
    }

    private sealed record ApiSubmissionResponse(HttpStatusCode StatusCode, string Body, string EndpointPath);
    internal sealed record ProductionIdentifier(string Lid, string Uid);

    private bool HasCookie(string name)
    {
        var cookies = cookieContainer.GetCookies(BaseUri);
        return !string.IsNullOrWhiteSpace(cookies[name]?.Value);
    }

    private bool HasAuthenticatedSession()
    {
        var cookies = cookieContainer.GetCookies(new Uri("https://letterboxd.com/"));
        return !string.IsNullOrWhiteSpace(cookies["letterboxd.user.CURRENT"]?.Value);
    }

    public void SetRawCookies(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return;

        var baseUri = new Uri("https://letterboxd.com/");
        // Split cookie header like: name=value; name2=value2; ...
        foreach (var part in raw.Split(';'))
        {
            var kv = part.Trim();
            if (string.IsNullOrEmpty(kv)) continue;
            var eq = kv.IndexOf('=');
            if (eq <= 0) continue;
            var name = kv.Substring(0, eq).Trim();
            var val = kv.Substring(eq + 1).Trim();
            try
            {
                // URL-decode value if needed
                val = WebUtility.UrlDecode(val);
                var cookie = new Cookie(name, val, "/", "letterboxd.com")
                {
                    HttpOnly = false,
                };
                cookieContainer.Add(baseUri, cookie);

                var dotCookie = new Cookie(name, val, "/", ".letterboxd.com")
                {
                    HttpOnly = false,
                };
                cookieContainer.Add(baseUri, dotCookie);

                if (string.Equals(name, "com.xk72.webparts.csrf", StringComparison.OrdinalIgnoreCase))
                {
                    this.csrf = val;
                }
            }
            catch
            {
                // ignore malformed cookie entries
            }
        }
    }

    private string GetCsrfFromCookie()
    {
        var cookies = cookieContainer.GetCookies(new Uri("https://letterboxd.com/"));
        // This is the token Letterboxd expects in the "__csrf" form field
        return cookies["com.xk72.webparts.csrf"]?.Value ?? string.Empty;
    }

    private async Task RefreshCsrfCookieAsync()
    {
        // Touch a page to ensure the CSRF cookie exists / is fresh
        using (var request = new HttpRequestMessage(HttpMethod.Get, "/"))
        {
            SetNavigationHeaders(request.Headers);
            using var _ = await client.SendAsync(request).ConfigureAwait(false);
        }

        var token = GetCsrfFromCookie();
        if (string.IsNullOrWhiteSpace(token))
            throw new Exception("Could not read CSRF cookie 'com.xk72.webparts.csrf' after refreshing.");
        this.csrf = token;
    }

    private async Task RefreshPageCsrfAsync(string path, string? referrer = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        SetNavigationHeaders(request.Headers, "same-origin", referrer);
        using var response = await client.SendAsync(request).ConfigureAwait(false);
        var html = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            var bodyPreview = html.Length > 300 ? html.Substring(0, 300) : html;
            throw new Exception(
                $"Letterboxd returned {(int)response.StatusCode} while refreshing CSRF from {path}. Body: {bodyPreview}");
        }

        var pageCsrf = ExtractSupermodelCsrf(html);
        if (string.IsNullOrWhiteSpace(pageCsrf))
        {
            pageCsrf = ExtractHiddenInput(html, "__csrf");
        }

        if (!string.IsNullOrWhiteSpace(pageCsrf))
        {
            this.csrf = pageCsrf;
            return;
        }

        var cookieCsrf = GetCsrfFromCookie();
        if (!string.IsNullOrWhiteSpace(cookieCsrf))
        {
            this.csrf = cookieCsrf;
            return;
        }

        throw new Exception($"Could not resolve CSRF token from {path}.");
    }

    private async Task<bool> IsLoggedInAsync()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/");
        SetNavigationHeaders(request.Headers);
        using var response = await client.SendAsync(request).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            return false;
        }

        var html = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        var pageCsrf = ExtractSupermodelCsrf(html);
        if (!string.IsNullOrWhiteSpace(pageCsrf))
        {
            this.csrf = pageCsrf;
        }

        return IsLoggedInHtml(html);
    }

    public LetterboxdApi(ILogger? logger = null)
    {
        _logger = logger;
        handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            AllowAutoRedirect = true
        };

        client = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://letterboxd.com")
        };

        // Use a Firefox UA if you're copying cookies from Firefox.
        client.DefaultRequestHeaders.UserAgent.Clear();
        client.DefaultRequestHeaders.UserAgent.ParseAdd(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0");

        // Keep headers minimal. Sending Chrome-only "sec-ch-ua" headers while claiming Firefox
        // can make bot detection more likely.
        client.DefaultRequestHeaders.Accept.Clear();
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml", 0.9));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*", 0.8));
        client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en-US,en;q=0.9");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate, br");
        client.DefaultRequestHeaders.Connection.Add("keep-alive");

        // Remove these (they were Chrome-specific):
        // client.DefaultRequestHeaders.TryAddWithoutValidation("sec-ch-ua", ...);
        // client.DefaultRequestHeaders.TryAddWithoutValidation("sec-ch-ua-mobile", ...);
        // client.DefaultRequestHeaders.TryAddWithoutValidation("sec-ch-ua-platform", ...);
        client.DefaultRequestHeaders.TryAddWithoutValidation("sec-fetch-dest", "document");
        client.DefaultRequestHeaders.TryAddWithoutValidation("sec-fetch-mode", "navigate");
        client.DefaultRequestHeaders.TryAddWithoutValidation("sec-fetch-site", "none");
        client.DefaultRequestHeaders.TryAddWithoutValidation("sec-fetch-user", "?1");
        client.DefaultRequestHeaders.TryAddWithoutValidation("upgrade-insecure-requests", "1");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Priority", "u=0, i");
    }

    private void SetNavigationHeaders(HttpRequestHeaders headers, string site = "none", string? referrer = null)
    {
        headers.Accept.Clear();
        headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
        headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml"));
        headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml", 0.9));
        headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/avif"));
        headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/webp"));
        headers.Accept.Add(new MediaTypeWithQualityHeaderValue("image/apng"));
        headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*", 0.8));

        headers.TryAddWithoutValidation("sec-fetch-dest", "document");
        headers.TryAddWithoutValidation("sec-fetch-mode", "navigate");
        headers.TryAddWithoutValidation("sec-fetch-site", site);
        headers.TryAddWithoutValidation("sec-fetch-user", "?1");
        headers.TryAddWithoutValidation("upgrade-insecure-requests", "1");

        // Use the same Priority header consistently
        if (headers.Contains("Priority")) headers.Remove("Priority");
        headers.TryAddWithoutValidation("Priority", "u=0, i");

        if (referrer != null)
        {
            headers.Referrer = new Uri(referrer);
        }
    }

    public async Task Authenticate(string username, string password)
    {
        this.username = username;

        // If user injected real browser cookies, don't try the login POST (Cloudflare blocks it).
        if (HasAuthenticatedSession())
        {
            try
            {
                await RefreshPageCsrfAsync("/").ConfigureAwait(false);
                return;
            }
            catch
            {
                // If refreshing CSRF fails (e.g. cookies expired), proceed to normal login.
            }
        }

        // 0) Initial delay to avoid "speeding"
        await Task.Delay(500 + Random.Shared.Next(1000)).ConfigureAwait(false);

        // 1) GET /sign-in/ to obtain cookies + __csrf
        using (var signInRequest = new HttpRequestMessage(HttpMethod.Get, "/sign-in/"))
        {
            SetNavigationHeaders(signInRequest.Headers);

            using (var signInResponse = await client.SendAsync(signInRequest).ConfigureAwait(false))
            {
                if (signInResponse.StatusCode == HttpStatusCode.Forbidden)
                {
                    // If user injected Cloudflare clearance cookie, warm up and retry once
                    if (cookieContainer.GetCookies(new Uri("https://letterboxd.com/")).Cast<Cookie>().Any(c => c.Name.Equals("cf_clearance", StringComparison.OrdinalIgnoreCase)))
                    {
                        await Task.Delay(1500).ConfigureAwait(false);
                        using var warmup = new HttpRequestMessage(HttpMethod.Get, "/");
                        SetNavigationHeaders(warmup.Headers);
                        using var _ = await client.SendAsync(warmup).ConfigureAwait(false);

                        using var retryReq = new HttpRequestMessage(HttpMethod.Get, "/sign-in/");
                        SetNavigationHeaders(retryReq.Headers);
                        using var retryRes = await client.SendAsync(retryReq).ConfigureAwait(false);
                        if (retryRes.StatusCode == HttpStatusCode.Forbidden)
                        {
                            var rbody = await retryRes.Content.ReadAsStringAsync().ConfigureAwait(false);
                            if (rbody.Length > 300) rbody = rbody.Substring(0, 300);
                            throw new Exception("Letterboxd returned 403 on /sign-in/ even after using provided Cloudflare cookies. Body: " + rbody);
                        }

                        var retryHtml = await retryRes.Content.ReadAsStringAsync().ConfigureAwait(false);
                        var csrfFromRetry = ExtractHiddenInput(retryHtml, "__csrf");
                        if (string.IsNullOrWhiteSpace(csrfFromRetry))
                            throw new Exception("Could not find __csrf token on /sign-in/ after retry.");
                        this.csrf = csrfFromRetry;
                        goto AfterSignIn;
                    }

                    var body = await signInResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (body.Length > 300) body = body.Substring(0, 300);
                    throw new Exception(
                        "Letterboxd returned 403 on /sign-in/. This is likely Cloudflare protection. " +
                        "Body: " + body);
                }

                if (signInResponse.StatusCode != HttpStatusCode.OK)
                {
                    var body = await signInResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (body.Length > 300) body = body.Substring(0, 300);
                    throw new Exception($"Letterboxd returned {(int)signInResponse.StatusCode} on /sign-in/. Body: " + body);
                }

                var signInHtml = await signInResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                var csrfFromSignIn = ExtractHiddenInput(signInHtml, "__csrf");
                if (string.IsNullOrWhiteSpace(csrfFromSignIn))
                {
                    throw new Exception("Could not find __csrf token on /sign-in/ (login flow likely changed).");
                }

                this.csrf = csrfFromSignIn;
            }
        }
        AfterSignIn:;

        // 2) POST /user/login.do with credentials + __csrf
        await Task.Delay(3000 + Random.Shared.Next(4000)).ConfigureAwait(false); // Mimic human typing/thinking time
        using (var loginRequest = new HttpRequestMessage(HttpMethod.Post, "/user/login.do"))
        {
            loginRequest.Headers.Accept.Clear();
            loginRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            loginRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/javascript"));
            loginRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*", 0.01));
            loginRequest.Headers.TryAddWithoutValidation("X-Requested-With", "XMLHttpRequest");

            loginRequest.Headers.Referrer = new Uri("https://letterboxd.com/sign-in/");
            loginRequest.Headers.TryAddWithoutValidation("Origin", "https://letterboxd.com");
            loginRequest.Headers.TryAddWithoutValidation("sec-fetch-dest", "empty");
            loginRequest.Headers.TryAddWithoutValidation("sec-fetch-mode", "cors");
            loginRequest.Headers.TryAddWithoutValidation("sec-fetch-site", "same-origin");
            loginRequest.Headers.TryAddWithoutValidation("Priority", "u=1, i");
            loginRequest.Headers.Remove("sec-fetch-user");
            loginRequest.Headers.Remove("upgrade-insecure-requests");

            loginRequest.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "username", username },
                { "password", password },
                { "__csrf", this.csrf },
                { "remember", "true" },
                { "authenticationCode", "" }
            });

            // Ensure all previously set cookies are sent.
            // CookieContainer handles this automatically as long as it's the same client/handler.
            
            using (var loginResponse = await client.SendAsync(loginRequest).ConfigureAwait(false))
            {
                if (loginResponse.StatusCode == HttpStatusCode.Forbidden)
                {
                    var body = await loginResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (body.Length > 300) body = body.Substring(0, 300);
                    throw new Exception(
                        "Letterboxd returned 403 during login. This is likely reCAPTCHA/anti-bot enforcement. " +
                        "Body: " + body
                    );
                }

                if (!loginResponse.IsSuccessStatusCode)
                {
                    var body = await loginResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (body.Length > 300) body = body.Substring(0, 300);
                    throw new Exception($"Letterboxd returned {(int)loginResponse.StatusCode} during login. Body: " + body);
                }

                var loginBody = await loginResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                using (JsonDocument doc = JsonDocument.Parse(loginBody))
                {
                    var json = doc.RootElement;
                    if (json.TryGetProperty("result", out var resultEl) && resultEl.GetString() == "error")
                    {
                        var msg = "Login failed";
                        if (json.TryGetProperty("messages", out var msgsEl))
                        {
                            var sb = new StringBuilder();
                            foreach (var m in msgsEl.EnumerateArray())
                                sb.Append(m.GetString()).Append(' ');
                            msg = sb.ToString().Trim();
                        }
                        throw new Exception("Letterboxd login error: " + msg);
                    }
                }
            }
        }

        // 3) Refresh page-scoped CSRF after login.
        await RefreshPageCsrfAsync("/", "https://letterboxd.com/sign-in/").ConfigureAwait(false);
    }

    public async Task<FilmResult> SearchFilmByTmdbId(int tmdbid)
    {
        // Add a small initial delay to avoid bursting
        await Task.Delay(500 + Random.Shared.Next(500)).ConfigureAwait(false);

        // Reuse the authenticated client + cookies from Authenticate.
        var tmdbPath = $"/tmdb/{tmdbid}";

        using (var searchRequest = new HttpRequestMessage(HttpMethod.Get, tmdbPath))
        {
            SetNavigationHeaders(searchRequest.Headers, "same-origin");

            using (var res = await client.SendAsync(searchRequest).ConfigureAwait(false))
            {
                if (res.StatusCode == HttpStatusCode.Forbidden)
                {
                    var body = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (body.Length > 300) body = body.Substring(0, 300);
                    
                    // If we got a 403, it's likely Cloudflare blocking automated lookups.
                    // We'll throw but suggest raw cookies/delays in the log elsewhere.
                    throw new Exception($"TMDB lookup returned 403 (Forbidden) for https://letterboxd.com/tmdb/{tmdbid}. This usually means Cloudflare is blocking the request. Body: " + body);
                }

                if (!res.IsSuccessStatusCode)
                {
                    var body = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (body.Length > 300) body = body.Substring(0, 300);
                    throw new Exception($"TMDB lookup returned {(int)res.StatusCode} for https://letterboxd.com/tmdb/{tmdbid}. Body: " + body);
                }

                // IMPORTANT:
                // Letterboxd may not 302 redirect here anymore; the final RequestUri can remain /tmdb/<id>.
                // So we parse the returned HTML to find a film link / canonical URL.
                var html = await res.Content.ReadAsStringAsync().ConfigureAwait(false);

                var htmlDoc = new HtmlDocument();
                htmlDoc.LoadHtml(html);

                // Best case: canonical link points at the film page.
                string filmUrl = htmlDoc.DocumentNode
                    .SelectSingleNode("//link[@rel='canonical']")
                    ?.GetAttributeValue("href", string.Empty) ?? string.Empty;

                // Fallback: any anchor to /film/<slug>/
                if (string.IsNullOrWhiteSpace(filmUrl))
                {
                    var a = htmlDoc.DocumentNode.SelectSingleNode("//a[starts-with(@href, '/film/')]");
                    var href = a?.GetAttributeValue("href", string.Empty) ?? string.Empty;

                    if (!string.IsNullOrWhiteSpace(href))
                        filmUrl = href.StartsWith("/") ? "https://letterboxd.com" + href : href;
                }

                if (string.IsNullOrWhiteSpace(filmUrl))
                {
                    // Helpful debug: show what URL we actually fetched/ended at
                    var finalUri = res?.RequestMessage?.RequestUri?.ToString() ?? string.Empty;
                    throw new Exception($"The search returned no results (Could not resolve film URL from TMDB page). FinalUrl='{finalUri}'");
                }

                // Extract slug from film URL
                var filmUri = new Uri(filmUrl, UriKind.Absolute);
                var segments = filmUri.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);

                if (segments.Length < 2 || !segments[0].Equals("film", StringComparison.OrdinalIgnoreCase))
                    throw new Exception($"TMDB page resolved to non-film URL: '{filmUrl}'");

                string filmSlug = segments[1];

                // Load film page and extract filmId
                using (var filmRequest = new HttpRequestMessage(HttpMethod.Get, $"/film/{filmSlug}/"))
                {
                    SetNavigationHeaders(filmRequest.Headers, "same-origin", $"https://letterboxd.com/tmdb/{tmdbid}");
                    using (var filmRes = await client.SendAsync(filmRequest).ConfigureAwait(false))
                    {
                        if (!filmRes.IsSuccessStatusCode)
                        {
                            var body = await filmRes.Content.ReadAsStringAsync().ConfigureAwait(false);
                            if (body.Length > 300) body = body.Substring(0, 300);
                            throw new Exception($"Film page lookup returned {(int)filmRes.StatusCode} for https://letterboxd.com/film/{filmSlug}/. Body: " + body);
                        }

                        var filmHtml = await filmRes.Content.ReadAsStringAsync().ConfigureAwait(false);
                        return ParseFilmResult(filmHtml, filmSlug, filmRes.Headers);
                    }
                }
            }
        }
    }


    public async Task MarkAsWatched(string filmSlug, string productionId, string filmId, DateTime? date, string[] tags, bool liked = false)
    {
        if (string.IsNullOrWhiteSpace(productionId))
        {
            throw new Exception($"Could not resolve productionId for /film/{filmSlug}/.");
        }

        for (int attempt = 0; attempt < 3; attempt++)
        {
            await RefreshPageCsrfAsync($"/film/{filmSlug}/").ConfigureAwait(false);
            var requestBody = BuildCreateLogEntryRequest(productionId, date, tags, liked);
            var requestJson = JsonSerializer.Serialize(requestBody, ApiJsonSerializerOptions);

            var submission = await SubmitLogEntryAsync(ApiLogEntriesUri, filmSlug, requestJson).ConfigureAwait(false);
            if (submission.StatusCode == HttpStatusCode.NotFound)
            {
                if (string.IsNullOrWhiteSpace(filmId))
                {
                    throw new Exception($"Could not resolve filmId for /film/{filmSlug}/ fallback submission.");
                }

                var fallbackRequestBody = BuildFallbackCreateLogEntryRequest(filmId, date, tags, liked);
                var fallbackRequestJson = JsonSerializer.Serialize(fallbackRequestBody, ApiJsonSerializerOptions);
                submission = await SubmitLogEntryAsync(ApiFallbackLogEntriesUri, filmSlug, fallbackRequestJson)
                    .ConfigureAwait(false);
            }

            var bodyPreview = submission.Body.Length > 300 ? submission.Body.Substring(0, 300) : submission.Body;
            if ((int)submission.StatusCode >= 200 && (int)submission.StatusCode < 300)
            {
                return;
            }

            if (submission.StatusCode == HttpStatusCode.Forbidden &&
                bodyPreview.Contains("Invalid CSRF token", StringComparison.OrdinalIgnoreCase) &&
                attempt < 2)
            {
                var delayMs = (attempt + 1) * 1500 + Random.Shared.Next(1000);
                _logger?.LogWarning(
                    "Letterboxd rejected the diary submission CSRF token for film {FilmSlug} on attempt {Attempt}. Retrying in {Delay}ms...",
                    filmSlug,
                    attempt + 1,
                    delayMs);
                await Task.Delay(delayMs).ConfigureAwait(false);
                continue;
            }

            if (submission.StatusCode == HttpStatusCode.Forbidden)
            {
                throw new Exception(
                    "Letterboxd returned 403 during diary submission via API. This is likely an authentication or anti-bot failure. " +
                    "Body: " + bodyPreview
                );
            }

            var apiMessage = TryExtractApiMessage(submission.Body);
            if (attempt < 2 &&
                (submission.StatusCode == HttpStatusCode.TooManyRequests ||
                 (int)submission.StatusCode >= 500 ||
                 apiMessage.Contains("try again", StringComparison.OrdinalIgnoreCase)))
            {
                var delayMs = (attempt + 1) * 5000 + Random.Shared.Next(3000);
                _logger?.LogWarning(
                    "Transient error on attempt {Attempt} for film {FilmSlug}: \"{Message}\". Retrying in {Delay}ms...",
                    attempt + 1,
                    filmSlug,
                    apiMessage,
                    delayMs);
                await Task.Delay(delayMs).ConfigureAwait(false);
                continue;
            }

            throw new Exception(
                $"Letterboxd returned {(int)submission.StatusCode} from {submission.EndpointPath}. " +
                $"Message: {apiMessage}. Body: {bodyPreview}");
        }

        throw new Exception("Failed to submit diary entry after retries.");
    }




    public async Task<DateTime?> GetDateLastLog(string filmSlug)
    {
        // Uses same authenticated cookie container via client.
        string url = $"/{this.username}/film/{filmSlug}/diary/";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        SetNavigationHeaders(request.Headers, "same-origin");
        using var response = await client.SendAsync(request).ConfigureAwait(false);
        var responseHtml = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        var htmlDoc = new HtmlDocument();
        htmlDoc.LoadHtml(responseHtml);

        var monthElements = htmlDoc.DocumentNode.SelectNodes("//a[contains(@class, 'month')]");
        var dayElements = htmlDoc.DocumentNode.SelectNodes("//a[contains(@class, 'date') or contains(@class, 'daydate')]");
        var yearElements = htmlDoc.DocumentNode.SelectNodes("//a[contains(@class, 'year')]");

        var lstDates = new List<DateTime>();

        if (monthElements != null && dayElements != null && yearElements != null)
        {
            var minCount = Math.Min(Math.Min(monthElements.Count, dayElements.Count), yearElements.Count);

            for (int i = 0; i < minCount; i++)
            {
                var month = monthElements[i].InnerText?.Trim();
                var day = dayElements[i].InnerText?.Trim();
                var year = yearElements[i].InnerText?.Trim();

                if (!string.IsNullOrEmpty(month) && !string.IsNullOrEmpty(day) && !string.IsNullOrEmpty(year))
                {
                    var dateString = $"{day} {month} {year}";
                    if (DateTime.TryParse(dateString, out DateTime parsedDate))
                        lstDates.Add(parsedDate);
                }
            }
        }

        return lstDates.Count > 0 ? lstDates.Max() : null;
    }

    /// <summary>
    /// Resolved target for a watchlist/list input.
    /// </summary>
    public record WatchlistTarget(string PlaylistName, string BasePath);

    /// <summary>
    /// Resolves a watchlist input (short URL, full URL, or plain username) to a scraping target.
    /// Supports: "username", "https://boxd.it/QKjHO", "https://letterboxd.com/user/watchlist/",
    /// "https://letterboxd.com/user/list/list-slug/", "letterboxd.com/user".
    /// </summary>
    public static async Task<WatchlistTarget> ResolveWatchlistInput(string input)
    {
        input = input.Trim();

        // Plain username — no dots or slashes
        if (!input.Contains('/') && !input.Contains('.'))
        {
            return new WatchlistTarget($"{input}'s Watchlist", $"/{input}/watchlist");
        }

        // Normalize missing scheme
        if (!input.StartsWith("http", StringComparison.OrdinalIgnoreCase))
        {
            input = "https://" + input;
        }

        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri))
        {
            return new WatchlistTarget($"{input}'s Watchlist", $"/{input}/watchlist");
        }

        // Short URL (boxd.it) — read Location header without following redirect (avoids Cloudflare)
        if (uri.Host.Equals("boxd.it", StringComparison.OrdinalIgnoreCase))
        {
            using var redirectHandler = new HttpClientHandler { AllowAutoRedirect = false };
            using var httpClient = new HttpClient(redirectHandler);
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0");
            using var response = await httpClient.GetAsync(uri).ConfigureAwait(false);
            var location = response.Headers.Location;
            if (location != null)
            {
                uri = location.IsAbsoluteUri ? location : new Uri(uri, location);
            }
        }

        // Extract path info from letterboxd.com URL
        if (uri.Host.Contains("letterboxd.com", StringComparison.OrdinalIgnoreCase))
        {
            var segments = uri.AbsolutePath.Trim('/').Split('/');

            // List URL: /username/list/list-slug/
            if (segments.Length >= 3 && segments[1] == "list")
            {
                var username = segments[0];
                var listSlug = segments[2];
                return new WatchlistTarget(
                    $"{username} - {listSlug}",
                    $"/{username}/list/{listSlug}");
            }

            // Watchlist or profile URL: /username/ or /username/watchlist/
            if (segments.Length > 0 && !string.IsNullOrEmpty(segments[0]))
            {
                var username = segments[0];
                return new WatchlistTarget($"{username}'s Watchlist", $"/{username}/watchlist");
            }
        }

        return new WatchlistTarget($"{input}'s Watchlist", $"/{input}/watchlist");
    }

    public async Task<List<FilmResult>> GetFilmsFromList(string basePath, int pageNum)
    {
        var films = new List<FilmResult>();

        using var request = new HttpRequestMessage(HttpMethod.Get, $"{basePath}/page/{pageNum}/");
        SetNavigationHeaders(request.Headers);

        using var response = await client.SendAsync(request).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var html = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        var htmlDoc = new HtmlDocument();
        htmlDoc.LoadHtml(html);

        var posters = htmlDoc.DocumentNode.SelectNodes("//div[@data-component-class='LazyPoster']");

        if (posters == null)
        {
            return films;
        }

        foreach (var poster in posters)
        {
            var filmSlug = poster.GetAttributeValue("data-item-slug", string.Empty);
            if (string.IsNullOrEmpty(filmSlug))
            {
                continue;
            }

            var film = await GetFilmTmdbIdFromSlug(filmSlug).ConfigureAwait(false);
            if (film != null)
            {
                films.Add(film);
            }

            await Task.Delay(2000 + Random.Shared.Next(1000)).ConfigureAwait(false);
        }

        bool isNextPage = htmlDoc.DocumentNode.SelectNodes($"//li[a/text() = '{pageNum + 1}']") is not null;

        if (isNextPage)
        {
            var nextPageFilms = await GetFilmsFromList(basePath, pageNum + 1).ConfigureAwait(false);
            films.AddRange(nextPageFilms);
        }

        return films;
    }

    public async Task<FilmResult?> GetFilmTmdbIdFromSlug(string filmSlug)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/film/{filmSlug}/");
        SetNavigationHeaders(request.Headers);

        using var response = await client.SendAsync(request).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var html = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        var htmlDoc = new HtmlDocument();
        htmlDoc.LoadHtml(html);

        var body = htmlDoc.DocumentNode.SelectSingleNode("//body");
        if (body == null)
        {
            return null;
        }

        string filmId = body.GetAttributeValue("data-tmdb-id", string.Empty);
        if (string.IsNullOrEmpty(filmId))
        {
            return null;
        }

        return new FilmResult(filmSlug, filmId);
    }

    private static string? ExtractHiddenInput(string html, string name)
    {
        // Matches: <input type="hidden" name="__csrf" value="...">
        var pattern = $@"<input[^>]*\bname\s*=\s*[""']{Regex.Escape(name)}[""'][^>]*\bvalue\s*=\s*[""']([^""']*)[""'][^>]*>";
        var m = Regex.Match(html, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return m.Success ? WebUtility.HtmlDecode(m.Groups[1].Value) : null;
    }

    internal static FilmResult ParseFilmResult(
        string html,
        string filmSlug,
        HttpResponseHeaders? headers = null)
    {
        var htmlDoc = new HtmlDocument();
        htmlDoc.LoadHtml(html);

        HtmlNode? filmNode =
            htmlDoc.DocumentNode.SelectSingleNode(
                $"//*[@data-item-slug='{filmSlug}' and @data-film-id and @data-postered-identifier]") ??
            htmlDoc.DocumentNode.SelectSingleNode(
                $"//*[@data-item-link='/film/{filmSlug}/' and @data-film-id and @data-postered-identifier]") ??
            htmlDoc.DocumentNode.SelectSingleNode("//*[@data-film-id and @data-postered-identifier]");

        if (filmNode == null)
        {
            throw new Exception("The search returned no results (No html element found to get Letterboxd film identifiers)");
        }

        var postedIdentifier = ParseProductionIdentifier(
            filmNode.GetAttributeValue("data-postered-identifier", string.Empty),
            filmSlug);

        var filmId = filmNode.GetAttributeValue("data-film-id", string.Empty);
        if (string.IsNullOrWhiteSpace(filmId) &&
            postedIdentifier.Uid.StartsWith("film:", StringComparison.OrdinalIgnoreCase))
        {
            filmId = postedIdentifier.Uid["film:".Length..];
        }

        if (string.IsNullOrWhiteSpace(filmId))
        {
            throw new Exception("The search returned no results (data-film-id attribute is empty)");
        }

        var productionId = TryGetProductionIdFromHeaders(headers) ?? postedIdentifier.Lid;
        if (string.IsNullOrWhiteSpace(productionId))
        {
            throw new Exception($"Could not resolve Letterboxd productionId from /film/{filmSlug}/.");
        }

        return new FilmResult(filmSlug, filmId, productionId);
    }

    internal static ProductionIdentifier ParseProductionIdentifier(string rawIdentifier, string filmSlug)
    {
        if (string.IsNullOrWhiteSpace(rawIdentifier))
        {
            throw new Exception($"Could not resolve posted identifier from /film/{filmSlug}/.");
        }

        using var document = JsonDocument.Parse(WebUtility.HtmlDecode(rawIdentifier));
        var root = document.RootElement;
        var lid = root.TryGetProperty("lid", out var lidElement) ? lidElement.GetString() : null;
        var uid = root.TryGetProperty("uid", out var uidElement) ? uidElement.GetString() : null;

        if (string.IsNullOrWhiteSpace(lid) || string.IsNullOrWhiteSpace(uid))
        {
            throw new Exception($"Could not resolve productionId from /film/{filmSlug}/.");
        }

        return new ProductionIdentifier(lid!, uid!);
    }

    internal static CreateLogEntryRequest BuildCreateLogEntryRequest(
        string productionId,
        DateTime? date,
        IEnumerable<string>? tags,
        bool liked)
    {
        return new CreateLogEntryRequest
        {
            ProductionId = productionId,
            DiaryDetails = date.HasValue
                ? new DiaryDetailsRequest(
                    date.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    Rewatch: false)
                : null,
            Tags = NormalizeTags(tags),
            Like = liked,
        };
    }

    internal static FallbackCreateLogEntryRequest BuildFallbackCreateLogEntryRequest(
        string filmId,
        DateTime? date,
        IEnumerable<string>? tags,
        bool liked)
    {
        return new FallbackCreateLogEntryRequest
        {
            FilmId = filmId,
            DiaryDetails = date.HasValue
                ? new DiaryDetailsRequest(
                    date.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    Rewatch: false)
                : null,
            Tags = NormalizeTags(tags),
            Like = liked,
        };
    }

    internal static string? ExtractSupermodelCsrf(string html)
    {
        var m = Regex.Match(
            html,
            @"supermodelCSRF\s*=\s*[""']([^""']+)[""']",
            RegexOptions.CultureInvariant);
        return m.Success ? WebUtility.HtmlDecode(m.Groups[1].Value) : null;
    }

    internal static bool IsLoggedInHtml(string html)
    {
        return Regex.IsMatch(
            html,
            @"\bloggedIn\s*:\s*true\b",
            RegexOptions.CultureInvariant);
    }

    private static string? TryGetProductionIdFromHeaders(HttpResponseHeaders? headers)
    {
        if (headers == null || !headers.TryGetValues("x-letterboxd-identifier", out var values))
        {
            return null;
        }

        var productionId = values.FirstOrDefault();
        return string.IsNullOrWhiteSpace(productionId) ? null : productionId;
    }

    private static string TryExtractApiMessage(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return "Unknown API error";
        }

        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.TryGetProperty("message", out var messageElement) &&
                messageElement.ValueKind == JsonValueKind.String)
            {
                return messageElement.GetString() ?? "Unknown API error";
            }
        }
        catch (JsonException)
        {
        }

        return "Unknown API error";
    }

    private async Task<ApiSubmissionResponse> SubmitLogEntryAsync(Uri endpoint, string filmSlug, string requestJson)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.Referrer = new Uri($"https://letterboxd.com/film/{filmSlug}/");
        request.Headers.TryAddWithoutValidation("Origin", "https://letterboxd.com");
        request.Headers.TryAddWithoutValidation("sec-fetch-dest", "empty");
        request.Headers.TryAddWithoutValidation("sec-fetch-mode", "cors");
        request.Headers.TryAddWithoutValidation("sec-fetch-site", "same-origin");
        request.Headers.Remove("sec-fetch-user");
        request.Headers.Remove("upgrade-insecure-requests");
        request.Headers.Accept.Clear();
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrWhiteSpace(this.csrf))
        {
            request.Headers.TryAddWithoutValidation("X-CSRF-TOKEN", this.csrf);
        }
        request.Content = new StringContent(requestJson, Encoding.UTF8, "application/json");

        using var response = await client.SendAsync(request).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        return new ApiSubmissionResponse(response.StatusCode, body, endpoint.AbsolutePath);
    }

    private static string[] NormalizeTags(IEnumerable<string>? tags)
    {
        return (tags ?? Array.Empty<string>())
            .Where(static tag => !string.IsNullOrWhiteSpace(tag))
            .Select(static tag => tag.Trim())
            .ToArray();
    }
}

public class FilmResult
{
    public string filmSlug = string.Empty;
    public string filmId = string.Empty;
    public string productionId = string.Empty;

    public FilmResult(string filmSlug, string filmId)
        : this(filmSlug, filmId, string.Empty)
    {
    }

    public FilmResult(string filmSlug, string filmId, string productionId)
    {
        this.filmSlug = filmSlug;
        this.filmId = filmId;
        this.productionId = productionId;
    }
}
