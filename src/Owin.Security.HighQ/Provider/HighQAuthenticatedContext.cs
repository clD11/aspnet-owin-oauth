using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;
using System.Security.Claims;
using System.Xml;

namespace Authentication.Web.OWIN.HighQ.Provider
{
    public class HighQAuthenticatedContext : BaseContext
    {
        private HighQAuthenticatedContext(IOwinContext context) : base(context) { }

        public static HighQAuthenticatedContext Create(IOwinContext context, XmlDocument user, JObject tokenResponse)
        {
            var ctx = new HighQAuthenticatedContext(context);

            ctx.User = user;
            ctx.TokenResponse = tokenResponse;

            if (tokenResponse != null)
            {
                ctx.AccessToken = tokenResponse.Value<string>("access_token");
                ctx.RefreshToken = tokenResponse.Value<string>("refresh_token");

                int expiresValue;

                if (Int32.TryParse(tokenResponse.Value<string>("expires_in"), NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
                {
                    ctx.ExpiresIn = TimeSpan.FromSeconds(expiresValue);
                }
            }

            ctx.Id = TryGetValue(user, "userid");
            ctx.FirstName = TryGetValue(user, "firstname");
            ctx.LastName = TryGetValue(user, "lastname");
            ctx.Email = TryGetValue(user, "email");

            return ctx;
        }

        public JObject TokenResponse { get; private set; }

        public string AccessToken { get; private set; }
        public string RefreshToken { get; private set; }
        public TimeSpan? ExpiresIn { get; set; }

        public XmlDocument User { get; private set; }

        public string Id { get; private set; }
        public string FirstName { get; private set; }
        public string LastName { get; private set; }
        public string Email { get; private set; }

        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(XmlDocument user, string nodeName)
        {
            XmlNodeList elemNodes = user.GetElementsByTagName(nodeName);

            if (elemNodes != null && elemNodes.Count > 0)
            {
                return elemNodes[0].InnerText;
            }

            return "";
        }
    }
}