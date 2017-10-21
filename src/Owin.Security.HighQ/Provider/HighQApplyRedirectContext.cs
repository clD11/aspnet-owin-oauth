using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Authentication.Web.OWIN.HighQ.Provider
{
    public class HighQApplyRedirectContext : BaseContext<HighQAuthenticationOptions>
    {
        public HighQApplyRedirectContext(IOwinContext context, HighQAuthenticationOptions options,
            AuthenticationProperties properties, string redirectUri) : base(context, options)
        {
            RedirectUri = redirectUri;
            Properties = properties;
        }

        public string RedirectUri { get; private set; }
        public AuthenticationProperties Properties { get; private set; }
    }
}