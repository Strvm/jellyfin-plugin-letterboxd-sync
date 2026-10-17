using LetterboxdSync;
using Xunit;

namespace LetterboxdSync.Tests;

public class LetterboxdSignInTests
{
    [Fact]
    public void ExtractSignInCsrf_CurrentPage_ReadsSupermodelCsrfAndSkipsEmptyDefault()
    {
        // Trimmed from the live /sign-in/ page (October 2026): no hidden __csrf input, the token is only in script.
        const string html = """
            <script>
                supermodelCSRF = "",
                configuration = { cloudflare: { turnstile: { managedSiteKey: '0x4AAAAAACeEHQVg5SDQxB2s' } } };
            </script>
            <form class="js-sign-in-form" method="post" action="/user/login.do" novalidate="true" data-captcha-action="signin">
                <input type="hidden" name="authenticationCode" value="" />
                <input type="text" name="username" id="field-username" value="" />
                <input type="password" name="password" id="field-password" value="" />
            </form>
            <script>supermodelCSRF = 'dae5083e0e3b6ac4c089'; geolocation.country = 'US';</script>
            """;

        Assert.Equal("dae5083e0e3b6ac4c089", LetterboxdApi.ExtractSignInCsrf(html));
    }

    [Fact]
    public void ExtractSignInCsrf_LegacyPage_PrefersHiddenInput()
    {
        const string html = """
            <form action="/user/login.do"><input type="hidden" name="__csrf" value="legacy-token"></form>
            <script>supermodelCSRF = 'script-token';</script>
            """;

        Assert.Equal("legacy-token", LetterboxdApi.ExtractSignInCsrf(html));
    }

    [Fact]
    public void ExtractSignInCsrf_NoToken_ReturnsNull()
    {
        Assert.Null(LetterboxdApi.ExtractSignInCsrf("<form action=\"/user/login.do\"></form>"));
    }
}
