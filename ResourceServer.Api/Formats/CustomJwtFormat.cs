using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Web;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;

namespace ResourceServer.Api.Formats
{
    public class CustomJwtFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private readonly string audience = "099153c2625149bc8ecb3e85e03f0022";
        private readonly byte[] secret = TextEncodings.Base64Url.Decode("IxrAjDoa2FqElO7IhrSrUJELhUckePEPVpaePlS_Xaw");

        private readonly string _issuer = string.Empty;

        public CustomJwtFormat(string issuer)
        {
            _issuer = issuer;
        }

        public string Protect(AuthenticationTicket data)
        {
            throw new NotImplementedException();
        }

        //Based on https://github.com/aspnet/AspNetKatana/blob/9f6e09af6bf203744feb5347121fe25f6eec06d8/src/Microsoft.Owin.Security.Jwt/JwtFormat.cs
        /// <summary>
        /// Validates the specified JWT and builds an AuthenticationTicket from it.
        /// </summary>
        /// <param name="protectedText">The JWT to validate.</param>
        /// <returns>An AuthenticationTicket built from the <paramref name="protectedText"/></returns>
        /// <exception cref="System.ArgumentNullException">Thrown if the <paramref name="protectedText"/> is null.</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown if the <paramref name="protectedText"/> is not a JWT.</exception>
        public AuthenticationTicket Unprotect(string protectedText)
        {
            var TokenHandler = new JwtSecurityTokenHandler();

            if (string.IsNullOrWhiteSpace(protectedText))
            {
                throw new ArgumentNullException("protectedText");
            }

            var token = TokenHandler.ReadToken(protectedText) as JwtSecurityToken;

            if (token == null)
            {
                throw new ArgumentOutOfRangeException("protectedText", "Invalid token.");
            }

            var signingKey = new SymmetricSecurityKey(secret);

            var validationParameters = new TokenValidationParameters
            {
                ValidIssuer = _issuer,
                ValidAudiences = new[] { audience },
                IssuerSigningKeys = new[] { signingKey }
            };

            SecurityToken validatedToken;
            ClaimsPrincipal claimsPrincipal = TokenHandler.ValidateToken(protectedText, validationParameters, out validatedToken);
            var claimsIdentity = (ClaimsIdentity)claimsPrincipal.Identity;

            // Fill out the authenticationProperties issued and expires times if the equivalent claims are in the JWT
            var authenticationProperties = new AuthenticationProperties();

            DateTime issued = validatedToken.ValidFrom;
            if (issued != DateTime.MinValue)
            {
                authenticationProperties.IssuedUtc = issued.ToUniversalTime();
            }
            DateTime expires = validatedToken.ValidTo;
            if (expires != DateTime.MinValue)
            {
                authenticationProperties.ExpiresUtc = expires.ToUniversalTime();
            }

            return new AuthenticationTicket(claimsIdentity, authenticationProperties);
        }
    }
}