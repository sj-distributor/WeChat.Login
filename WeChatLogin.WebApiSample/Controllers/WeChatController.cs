using Microsoft.AspNetCore.Mvc;

namespace WeChatLogin.WebApiSample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class WeChatController : ControllerBase
    {
        private const string weChatToken = "wechat";

        [Route("validate"), HttpGet]
        public IActionResult ValidateToken(string signature, string timestamp, string nonce, string echostr)
        {
            if (WeChatValidation.CheckSignature(weChatToken, signature, timestamp, nonce))
            {
                return Ok(echostr);
            }

            return BadRequest();
        }
    }
}