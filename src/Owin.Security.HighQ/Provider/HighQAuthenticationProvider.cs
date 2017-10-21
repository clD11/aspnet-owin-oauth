using System;
using System.Threading.Tasks;

namespace Authentication.Web.OWIN.HighQ.Provider
{
    public class HighQAuthenticationProvider : IHighQAuthenticationProvider
    { 
        public HighQAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnApplyRedirect = context =>
                context.Response.Redirect(context.RedirectUri);
        }

        public Func<HighQAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<HighQReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public Action<HighQApplyRedirectContext> OnApplyRedirect { get; set; }

        public virtual Task Authenticated(HighQAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(HighQReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        public virtual void ApplyRedirect(HighQApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }
    }
}