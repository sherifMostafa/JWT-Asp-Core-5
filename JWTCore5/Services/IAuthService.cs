using JWTCore5.Models;
using System.Threading.Tasks;

namespace JWTCore5.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);

        Task<AuthModel> GetTokenAsync(TokenRequestModel model);

        Task<string> AddToRoleAsync(AddRoleModel model);
    }
}
