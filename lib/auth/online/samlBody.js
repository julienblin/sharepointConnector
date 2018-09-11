_ = require('underscore'),

saml = `
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">{toUrl}</a:To>
    <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      {auth}
    </o:Security>
  </s:Header>
  <s:Body>
    <t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
      <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
        <a:EndpointReference>
          <a:Address>{url}</a:Address>
        </a:EndpointReference>
      </wsp:AppliesTo>
      <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
      <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
      <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
    </t:RequestSecurityToken>
  </s:Body>
</s:Envelope>
`;

auth = `
<o:UsernameToken>
  <o:Username>{username}</o:Username>
  <o:Password>{password}</o:Password>
</o:UsernameToken>
`;

module.exports = function(client, httpOpts, toUrl, url, assertion, waterfallCb){
  var samlBody = _.clone(saml),
  authBody = _.clone(auth);
  
  authBody = authBody.replace('{username}', client.auth.username);
  authBody = authBody.replace('{password}', client.auth.password);
  // If an assertion was passed in, put it in the {auth} placeholder. Otherwise, username and password.
  samlBody = samlBody.replace('{auth}', assertion || authBody);
  samlBody = samlBody.replace('{url}', url);
  samlBody = samlBody.replace('{toUrl}', toUrl);
  return waterfallCb(null, client, httpOpts, toUrl, samlBody);
};
