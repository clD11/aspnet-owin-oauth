using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Authentication.Web.OWIN.HighQ.Provider
{
    public class HighQReturnEndpointContext : ReturnEndpointContext
    {
        public HighQReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket) : base (context, ticket)
        {
        }
    }
}