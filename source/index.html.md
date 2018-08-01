---
title: API Reference

language_tabs: # must be one of https://git.io/vQNgJ
  - cURL
  - ruby
  - python 
  - java
  - php
  - json
  - csharp

toc_footers:
  - <a href='https://dash.sendwyre.com/register'>Sign Up for a Wyre Account!</a>



search: true
---

# Overview

Wyre offers a powerful REST API that supports wire transfers, mass international payouts, cryptocurrency wallet management, and virtual banking services for your personal or enterprise needs. 

Our API uses HTTPS response codes and returns all error responses in JSON. To explore the API as much as possible, we offer a test environment in addition to production. Any transfers made in the test environment will never hit the actual blockchain network or incur any fees. Both sandbox and production rely on API keys for authentication.

The legacy API documentation can be found [here](https://docs.sendwyre.com/docs/overview).

# Getting Started

The Wyre API is designed for enterprises who need to send cross-border payments for end-to-end delivery in a matter of hours. Wyre transfers value instantly, achieves FX conversions equal to or better than midmarket, and utilizes local banking networks to complete bank-to-bank transfers.  

**How to get Started**

**Step 1. Read the documentation** <br>
We recommend that you read the API documentation and familiarize yourself with the different API functions and calls so you can get the most out of the Wyre API! <br>

**Step 2. Register a test account** <br>
Sign up [here](https://www.testwyre.com) to interact with our test environment. The test API uses live market rates but does not execute real transactions. <br>

**Step 3. Verify your test account** <br>
Contact our support team at support@sendwyre.com so we can auto verify your test account and add test funds that you can start using. <br>

**Step 4. Assign a dedicated support engineer**<br>
Wyre will assign a support engineer to your integration at no additional cost to assist you with any integration related questions during your testing. <br>

**Step 5. Register a production account** <br>
Once testing has completed, you can register a live account [here](https://sendwyre.com). You must go through the entire onboarding and verification process before you are allowed to send funds.<br>

**Step 6. Prefund your production account**<br>
To learn more about topping up your account, please refer to more information [here](https://support.sendwyre.com/getting-started/get-started-on-the-right-foot/video-adding-funds-to-your-account). 

**Step 7. Start sending funds**<br>
You are ready to send your first live payment!

# General

## Supported Currencies  

We support a number of fiat currencies and cryptocurrencies including BTC and ETH (just launched). <br>

![Supported Currencies](SupportedCurrency.png)<p>

Learn more about our supported currency pairs <a href="https://support.sendwyre.com/sending-money/supported-currencies" target="_blank">here</a>. 


## Transport Method

Wyre provides a REST API that will always return a JSON Object as the response.<br>
    
During troubleshooting, please note that if your error response does not follow the previously mentioned format, the error is most likely due to a different endpoint. 

```json

For successful API calls:<br>

{
        "parameter": "en",<br>
        "parameter": "ABCDEF" <br>
    
}
   
For unsuccessful API calls:<br>

{
        "language":"en",<br>
        "exceptionId":"ABCDEF",<br>
        "compositeType":"",<br>
        "subType":"",<br>
        "message":"Error Message",<br>
        "type":"ErrorTypeException",<br>
        "transient":false <br>
}

```

## Production/Test Endpoints

We have two environments, `testwyre` for API integration testing and `sendwyre`, our production environment. The test environment also uses the same live exchange rates as our production environment.

Environment | Endpoint
--------- | -----------
Test | <a href="https://www.testwyre.com" target="_blank">https://www.testwyre.com </a>
Production | <a href="https://sendwyre.com" target="_blank">https://sendwyre.com </a>

**Bitcoin Test Environment** <p>
Please note that our test environment is live on TestNet3 for BTC.  For BTC TestNet funds, please refer <a href="https://testnet.manu.backend.hamburg/faucet" target="_blank">here</a>. You will expect to receive 1 confirmation on the network. 
  
**Ethereum Test Environment** <p>
The test environment for ETH is Ropsten. For ETH TestNet funds, please refer <a href="http://faucet.ropsten.be:3001/" target = "_blank">here</a>. The Ethereum Block Explorer is also <a href="https://ropsten.etherscan.io/" target="_blank">here</a>. You will expect to receive 10 confirmations on the network. 

## Pagination

We split our tabular data into pages of 25 items. You can apply the parameters below to any request for tabular to adjust the pagination.

Parameter | Description
--------- | -----------
offset | How many items are skipped before the first item that is shown (default: 0).
limit | Number of items returned per page (default: 25).
from | The lower bound of a creation time filter for the displayed items. Formatted in millisecond Epoch format. (default: 0)
to | The upper bound of a creation time filter for the displayed items. Formatted in millisecond Epoch format. (default: current time)

## Authentication
```ruby
require 'uri'
require 'net/http'
require 'openssl'
require 'json'

class WyreApi
  ACCOUNT_ID = 'AC-1234556'
  API_KEY = 'sdkdsfkjsdfkjasdkjasda'
  SEC_KEY = 'kasdas9d8as9d8asdasdas'
  API_URL = 'https://api.sendwyre.com'

def create_transfer options
    api_post '/transfers', options
  end

  private

  def api_post path, post_data = {}
    params = {
      'timestamp' => (Time.now.to_i * 1000).to_s
    }

    url = API_URL + path + '?' + URI.encode_www_form(params)

    headers = {
      'X-Api-Key' => API_KEY,
      'X-Api-Signature' => calc_auth_sig_hash(url + post_data.to_json.to_s),
      'X-Api-Version' => '2',
      'content-type' => 'application/json'
    }

    uri = URI API_URL
    Net::HTTP.start(uri.host, uri.port, :use_ssl => true) do |http|
      http.request_post(url, post_data.to_json.to_s, headers) do |res|
        response = JSON.parse res.body
        raise response.to_s if res.code != '200'
        return response
      end
    end
  end

  def calc_auth_sig_hash url_body
    return OpenSSL::HMAC.hexdigest("SHA256", SEC_KEY, url_body)
  end
end

api = WyreApi.new
puts api.create_transfer({'sourceAmount'=>50,'sourceCurrency'=>'USD','dest'=>'sam@sendwyre.com', 'destCurrency'=>'EUR', 'message'=>'buy sam pizza'})
```

```python
#dependencies:
#python3
#pip3 install requests

import json
import hmac
import time
from requests import request

class MassPay_API(object):
    def __init__(self, account_id, api_version, api_key, api_secret):
        self.account_id = account_id
        self.api_url = 'https://api.sendwyre.com/{}'.format(api_version)
        self.api_version = api_version
        self.api_key = api_key
        self.api_secret = api_secret

    #authentication decorator. May raise ValueError if no json content is returned
    def authenticate_request(func):
        def wrap(self, *args, **kwargs):
            url, method, body = func(self, *args, **kwargs)
            params = {}
            timestamp = int(time.time() * 1000)
            url += '?timestamp={}'.format(timestamp)
            bodyJson = json.dumps(body) if body != '' else ''
            headers = {}
            headers['Content-Type'] = 'application/json'
            headers['X-Api-Version'] = self.api_version
            headers['X-Api-Key'] = self.api_key
            headers['X-Api-Signature'] = hmac.new(self.api_secret.encode('utf-8'), (url + bodyJson).encode('utf-8'), 'SHA256').hexdigest()
            print(headers['X-Api-Signature'])
            resp = request(method=method, url=url, params=params, data=(json.dumps(body) if body != '' else None), json=None, headers=headers)
            if resp.text is not None: #Wyre will always try to give an err body
                return resp.status_code, resp.json()
            return 404, {}
        return wrap

    @authenticate_request
    def retrieve_exchange_rates(self):
        url = self.api_url + '/rates'
        method = 'GET'
        body = ''
        return url, method, body

    @authenticate_request
    def retrieve_account(self):
        url = self.api_url + '/account'
        method = 'GET'
        body = ''
        return url, method, body

    @authenticate_request
    def create_transfer(self, sourceAmount, sourceCurrency, destAmount, destCurrency, destAddress, message, autoConfirm):
        url = self.api_url + '/transfers'
        method = 'POST'
        #ONLY use either sourceAmount or destAmount, see documentation
        body = {'sourceCurrency':sourceCurrency,
                'dest':destAddress,
                'destCurrency':destCurrency,
                'message':message}
        if sourceAmount:
            body["sourceAmount"] = sourceAmount
        elif destAmount:
            body["destAmount"] = destAmount
        if autoConfirm:
            body['autoConfirm'] = True
        return url, method, body 

    @authenticate_request
    def confirm_transfer(self, transfer_id):
        url = self.api_url + '/transfer/{}/confirm'.format(transfer_id)
        method = 'POST'
        body = ''
        return url, method, body  

    @authenticate_request
    def status_transfer(self, transfer_id):
        url = self.api_url + '/transfer/{}'.format(transfer_id)
        method = 'GET'
        body = ''
        return url, method, body  

#USAGE Example
account_id = "YOUR_ACCOUNT_ID_HERE" #optional
api_key = "YOUR_API_KEY_HERE"
secret_key = "YOUR_SECRET_KEY_HERE"
api_version = "2"

#create Wyre MassPay API object
Wyre = MassPay_API(account_id, api_version, api_key, secret_key)

#get account info
http_code, account = Wyre.retrieve_account()
print(account)

#get exchange rate info
http_code, rate_result = Wyre.retrieve_exchange_rates()
print(rate_result)

#BTC to CNY rate
btc_cny = rate_result.get("BTCCNY")

#amount of source (withdrawal) BTC we want to sent to Euro
amount = 50

#calculate destination (deposit) amount in CNY
final_amount = amount * btc_cny

#example bank transfer
bank_transfer =   {
                "paymentMethodType":"INTERNATIONAL_TRANSFER",
                "country": "CN",
                "currency": "CNY",
                "nameOnAccount": "成龍",
                "accountNumber": "1234dinosaur",
                "bankName": "招商银行",
                "accountType": "金卡",
                "branchCode": "光华路支行",
                "accountHolderEmail": "banana@phone.com",
                "accountHolderPhoneNumber": "+14102239203",
                "swift": "DEUTUS00000",
                "beneficiaryType": "INDIVIDUAL",
                "priority":"HIGH"
                }

#don't actually run this unless you really want to give Sam pizza
http_code, transfer_result = Wyre.create_transfer(
                                amount, 
                                "BTC", 
                                None, #final_amount
                                "CNY", 
                                bank_transfer, #may also be an email or SRN
                                "sending Wyre developers pizza money",
                                False)
print(transfer_result)

tx_id = transfer_result['id']
http_code, status = Wyre.status_transfer('AWEvg0lZhq6qpXX')
print(status)
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.Integer;
import java.lang.String;
import java.lang.StringBuffer;
import java.net.HttpURLConnection;
import java.net.URL;

public class TestAuth {
  public static void main(String[] args) {
    String apiKey = "PUT YOUR API KEY HERE";
    String secretKey = "PUT YOUR SECRET KEY HERE";

    String url = "https://api.sendwyre.com/account";
    String method = "GET";
    String data = "";

    String result = executeWyreRequest(url, "", method, apiKey, secretKey);
    System.out.println(result);

    url = "https://api.sendwyre.com/transfers";
    method = "POST";
    data = "{" +
        "  \"dest\": \"sam@sendwyre.com\"," +
        "  \"destCurrency\": \"USD\"," +
        "  \"sourceCurrency\" : \"BTC\"," +
        "  \"sourceAmount\" : \"1\"," +
        "  \"message\": \"$1 worth of bitcoin!\"" +
        "}";
    result = executeWyreRequest(url, data, method, apiKey, secretKey);

    System.out.println(result);
  }

  public static String executeWyreRequest(String targetURL, String requestBody, String method, String apiKey, String secretKey) {
    URL url;
    HttpURLConnection connection = null;
    try {

      targetURL += ((targetURL.indexOf("?")>0)?"&":"?") + "timestamp=" + System.currentTimeMillis();

      //Create connection
      url = new URL(targetURL);
      connection = (HttpURLConnection)url.openConnection();
      connection.setRequestMethod(method);
      System.out.println(connection.getRequestMethod());

      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Content-Length", Integer.toString(requestBody.getBytes().length));

      //Specify API v2
      connection.setRequestProperty("X-Api-Version","2");

      // Provide API key and signature
      connection.setRequestProperty("X-Api-Key", apiKey);
      connection.setRequestProperty("X-Api-Signature",computeSignature(secretKey,targetURL,requestBody));

      //Send request
      if(method.equals("POST")) {
        connection.setDoOutput(true);
        connection.setRequestMethod(method);

        DataOutputStream wr = new DataOutputStream(
            connection.getOutputStream());

        wr.write(requestBody.getBytes("UTF-8"));
        wr.flush();
        wr.close();
      }

      //Get Response
      InputStream is;
      if (connection.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
        is = connection.getInputStream();
      } else {

        is = connection.getErrorStream();
      }

      BufferedReader rd = new BufferedReader(new InputStreamReader(is));
      String line;
      StringBuffer response = new StringBuffer();
      while((line = rd.readLine()) != null) {
        response.append(line);
        response.append('\r');
      }
      rd.close();
      return response.toString();

    } catch (Exception e) {

      e.printStackTrace();
      return null;

    } finally {

      if(connection != null) {
        connection.disconnect();
      }
    }
  }

  public static String computeSignature(String secretKey, String url, String reqData) {

    String data = url + reqData;

    System.out.println(data);

    try {
      Mac sha256Hmac = Mac.getInstance("HmacSHA256");
      SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
      sha256Hmac.init(key);

      byte[] macData = sha256Hmac.doFinal(data.getBytes("UTF-8"));

      String result = "";
      for (final byte element : macData){
        result += Integer.toString((element & 0xff) + 0x100, 16).substring(1);
      }
      return result;

    } catch (Exception e) {
      e.printStackTrace();
      return "";
    }
  }
}
```


```php
<?php
    function make_authenticated_request($endpoint, $method, $body) {
        $url = 'https://api.sendwyre.com';
        $api_key = "bh405n7stsuo5ut30iftrsl71b4iqjnv";
        $secret_key = "a19cvrchgja82urvn47kirrlrrb7stgg";

        $timestamp = floor(microtime(true)*1000);
        $request_url = $url . $endpoint;

        if(strpos($request_url,"?"))
            $request_url .= '&timestamp=' . $timestamp;
        else
            $request_url .= '?timestamp=' . $timestamp;

        if(!empty($body))
            $body = json_encode($body, JSON_FORCE_OBJECT);
        else
            $body = '';

        $headers = array(
            "Content-Type: application/json",
            "X-Api-Key: ". $api_key,
            "X-Api-Signature: ". calc_auth_sig_hash($secret_key, $request_url . $body),
            "X-Api-Version: 2"
        );
        $curl = curl_init();

        if($method=="POST"){
          $options = array(
            CURLOPT_URL             => $request_url,
            CURLOPT_POST            =>  true,
            CURLOPT_POSTFIELDS      => $body,
            CURLOPT_RETURNTRANSFER  => true);
        }else {
          $options = array(
            CURLOPT_URL             => $request_url,
            CURLOPT_RETURNTRANSFER  => true);
        }
        curl_setopt_array($curl, $options);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        $result = curl_exec($curl);
        curl_close($curl);
        var_dump($result);
        return json_decode($result, true);
    }

    function calc_auth_sig_hash($seckey, $val) {
        $hash = hash_hmac('sha256', $val, $seckey);
        return $hash;
    }

    echo make_authenticated_request("/account", "GET", array());
    $transfer = array(
      "sourceCurrency"=>"USD",
      "dest"=>"sam@sendwyre.com",
      "destAmount"=> 55.05,
      "destCurrency"=>"EUR",
      "message"=> "buy sam pizza"
      );
    echo make_authenticated_request("/transfers", "POST", $transfer);
?>
```








```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
namespace testauthwyre
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            WyreApi wyre = new WyreApi();
            Console.WriteLine(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            Console.WriteLine((long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds);
            HttpWebResponse accountResponse = wyre.Get("/account");
            Console.WriteLine(GetResponseBody(accountResponse));
            Dictionary<string, object> body = new Dictionary<string, object>();
            body.Add("sourceCurrency", "USD");
            body.Add("sourceAmount", "10");
            body.Add("dest", "test@sendwyre.com");
            HttpWebResponse transferResponse = wyre.Post("/transfers", body);
            Console.WriteLine(GetResponseBody(transferResponse));
        }
        private static string GetResponseBody(HttpWebResponse response)
        {
            return JObject.Parse(new StreamReader(response.GetResponseStream()).ReadToEnd()).ToString(Formatting.Indented);
        }
    }
    public class WyreApi
    {
        private const String domain = "https://api.sendwyre.com";
        private const String apiKey = "xxx";
        private const String secKey = "xxx";
        public HttpWebResponse Get(string path)
        {
            return Get(path, new Dictionary<string, object>());
        }
        public HttpWebResponse Get(string path, Dictionary<string, object> queryParams)
        {
            return Request("GET", path, queryParams);
        }
        public HttpWebResponse Post(string path, Dictionary<string, object> body)
        {
            return Request("POST", path, body);
        }
        private HttpWebResponse Request(string method, string path, Dictionary<string, object> body)
        {
            Dictionary<string, object> queryParams = new Dictionary<string, object>();
            if (method.Equals("GET"))
                queryParams = body;
            queryParams.Add("timestamp", GetTimestamp());
            string queryString = queryParams.Aggregate("", (previous, current) => previous + "&" + current.Key + "=" + current.Value).Remove(0, 1);
            string url = domain + path + "?" + queryString;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = method;
            request.ContentType = "application/json";
            request.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            if (!method.Equals("GET"))
            {
                url += JsonConvert.SerializeObject(body);
                using (StreamWriter writer = new StreamWriter(request.GetRequestStream()))
                    writer.Write(JsonConvert.SerializeObject(body));
            }
            request.Headers["X-Api-Key"] = apiKey;
            request.Headers["X-Api-Signature"] = CalcAuthSigHash(secKey, url);
            request.Headers["X-Api-Version"] = "2";
            try 
            {
                return (HttpWebResponse)request.GetResponse();
            }
            catch(WebException e) 
            {
                string msg = new StreamReader(e.Response.GetResponseStream()).ReadToEnd();
                Console.WriteLine(msg);
                throw new SystemException(msg);
            }
        }
        private byte[] GetBytes(string str)
        {
            return Encoding.UTF8.GetBytes(str);
        }
        private string GetString(byte[] bytes)
        {
            return BitConverter.ToString(bytes);
        }
        private long GetTimestamp()
        {
            // return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() // .NET 4.6
            return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
        }
        private String CalcAuthSigHash(string key, string value)
        {
            HMACSHA256 hmac = new HMACSHA256(GetBytes(key));
            string hash = GetString(hmac.ComputeHash(GetBytes(value))).Replace("-", "");
            return hash;
        }
    }
}
```

We use a handful of security mechanisms to ensure that your requests are secure. You can find information on how to make a secure authenticated request below.

In order to make an authenticated request you'll need to pass a couple of values through the HTTP headers with your request:

HTTP Header Field | Description 
--------- | -----------
X-Api-Key | Your Wyre API key. Your key can be found <a href="https://dash.sendwyre.com/settings/api-keys" target="_blank">here</a>
X-Api-Signature | A signature used to verify the request was sent by the account holder. See Calculating the request signature.

Additionally, you should include a `GET` parameter named timestamp which is the current time in **millisecond epoch format**. We use this timestamp to help protect against replay attacks.

**Calculating the request signature**


If you are sending a `GET` request you would sign the following (example):  *https://api.sendwyre.com/v2/rates?timestamp=1426252182534*<br>

If you are making a `POST` request you would sign the following (example): *https://api.sendwyre.com/v2/transfers?timestamp=1426252182534*<br>

Note for the `POST` request, you must append the request body to the string URL. Remember to send the request body exactly as you sign it, whitespace and all. The server calculates the signature based on exactly what's in the request body. <br>

Calculating the X-Api-Signature field is a two step process: <br>

1. Concatenate the request URL with the body of the HTTP request into a UTF-8 String. Use an empty string for the HTTP body in `GET` requests. <br>

2. Compute the signature using HMAC with SHA-256 and your API Secret Key. <br>


## SRNs

An SRN is a System Resource Name. It is a typed identifier that may reference any object within the Wyre platform. Many of our API calls and data schemas leverage SRNs in order to add flexibility and decouple services. All SRNs follow the same format: 

type | Identifier
--------- | -----------
contact | A contact id (e.g. contact:567a93fb)
paymentmethod | A payment method such as a credit card, bank account, etc.
email | An email address (e.g. email:dev@sendwyre.com)
cellphone | A cellphone number (e.g. cellphone:+15555555555)
bitcoin | Blockchain addresses
ethereum | Blockchain addresses
account | A Wyre account
wallet | A single wallet that can hold monies
transfer | A transfer (possibly including a conversion) of currency

## Fees

To understand how are fees are calculated and charged, please refer <a href="https://support.sendwyre.com/digital-currency-basics/bitcoin-payouts" target="_blank">here</a>.

## Error Table

Successful requests will be a HTTP 200 response after any successful call. The body of successful requests depend on the endpoint. <br>

Whenever a problem occurs, Wyre will respond to the client using a 4xx or 5xx status code. In this case, the body of the response will be an exception object which describes the problem. <br>

Exception | Description | HTTPs Status Code
--------- | ----------- | -----------
ValidationException | The action failed due to problems with the request. | 400
UnknownException | A problem with our services internally. This should rarely happen. | 500
InsufficientFundsException | You requested the use of more funds in the specified currency than were available. | 400
RateLimitException | Your requests have exceeded your usage restrictions. Please contact us if you need this increased. | 429
AccessDeniedException | You lack sufficient privilege to perform the requested action. | 401
TransferException | There was a problem completing your transfer request. | 400
NotFoundException | You requested something that couldn't be located. | 400
ValidationException | There was a problem validating the input you supplied. | 400
CustomerSupportException | Please contact us at support@sendwyre.com to resolve this! | 400
MFARequiredException | An MFA action is required to complete the request. In general you should not get this exception while using API keys. | 400

<br>
All exceptions will carry a subType parameter which exposes more information about the problem. Additionally, some ValidationException errors will carry with them two fields, problematicField and problematicValue, denoting the field which caused the failure.

A few typical ValidationException subtypes:
<br>

FIELD_REQUIRED <br>
INVALID_VALUE <br>
TRANSACTION_AMOUNT_TOO_SMALL <br>
UNSUPPORTED_SOURCE_CURRENCY <br>
SENDER_PROVIDED_ID_IN_USE <br>
CANNOT_SEND_SELF_FUNDS <br>
INVALID_PAYMENT_METHOD <br>
PAYMENT_METHOD_INACTIVE <br>
PAYMENT_METHOD_UNSUPPORTED_CHARGE_CURRENCY <br>
PAYMENT_METHOD_UNCHARGEABLE <br>
PAYMENT_METHOD_UNSUPPORTED_DEPOSIT_CURRENCY <br>
PAYMENT_METHOD_UNDEPOSITABLE <br>
PAYMENT_METHOD_DOESNT_SUPPORT_FOLLOWUPS <br>
PAYMENT_METHOD_DOESNT_SUPPORT_MICRODEPOSIT_VERIFICATION <br>

# Cookbooks

Wyre's powerful API provides the capability of sending international payments or bitcoin in a multitude of ways that best suits your business needs. Each cookbook will show you step by step how to send money whether you want to send mass payouts internationally or link Wyre to your brokerage engine.

## KYC Smart Contract

Everytime a user's KYC is verified or approved by Wyre compliance, an NFT token will be issued into that user's wallet of choice. Any DEX or dApp can reference the KYC smart contract and indicate whether or not that wallet contains an NFT issued by Wyre. 

### Step 1. User signs up for an account on Wyre

### Step 2. User inputs verification address

### Step 3. Wyre compliance reviews KYC

### Step 4. DEX/dApp will look up smart contract on Ropsten

### Step 5. Using the balanceOf function. <br>
`function balanceOf(address _owner) public view returns (uint256) { return ownedTokens[_owner].length; }` <br>
If it returns >=0, they know that we have issued a verification token to that address.

<pre class="center-column">
<-------- START ------->
let MyContract = web3.eth.contract(INSERT_219LineBlob_HERE); 
//its same ABI provided in snippet above that you asked about. Aka "blob to talk to //contract"...

let myContractInstance = MyContract.at('0x2d1c60c8ecb86faeb1c4d26cb744067866f356bd'); 
//This is the identity contract that we give to them.

let address = 'INSERT_METAMASK_ADDRESS_HERE'; //metamask chrome extension 
 myContractInstance.balanceOf.call(address, function (error, balance) {
   if (error) {
     console.log('err',error);
   }
   console.log('wei', web3.fromWei(balance.toNumber(), "ether" ) );
   console.log(' oooo--->', balance);
 });
<-------- FINISH ------->
// --> Developers add their code from their site here which says "If they don't have a token, then stay the same, if they DO have a token, then give them cool awesome features!!!
</pre>


## Money Transfer/Payouts

There are many ways to use the Wyre API to provide FX and payout services to your users. To help developers understand how it may be used, we’ve described a typical use-case below. <br>

This cookbook will show you an example of how a client platform may add CNY conversion and payouts via Wyre API.<br>

The client platform will maintain a USD float (prefund) on the Wyre platform, which will be topped up on a weekly basis according to weekly transaction volume.<br>

The client's users will obtain live rates from the Wyre API, and after confirming the rates, will make payments to the client's platform via the local payment network in that platform’s jurisdiction.<br>

After confirming payment from the user, the client's platform will make a payout call to the Wyre API to convert the corresponding amount of USD to CNY and deliver to the user’s recipient in China.<br>

In the example above, the fund flow will look something like the below:<p>
![masspayouts](masspayouts.png)


### Step 1. Check live exchange rates

`GET` https://api.sendwyre.com/v2/rates <br>

You can ping the [rates API](http://sendwyre.com/docs/#live-exchange-rates) to get the latest currency exchange rates which refreshes every 30 seconds. <br>

The mid market rate is calculated as MMR = (Buy rate + Sell Rate)/2. This rate is obtained from <a href="https://openexchangerates.org" target="_blank">open exchange rates</a>.

### Step 2. Check supported banks in China 

`GET` https://api.sendwyre.com/v2/bankinfo/CN <br>

When you create your payout on behalf of the user in the next step, make sure the Chinese bank you send to is one we support. The list of supported banks will be presented in Chinese characters. The same list can also be found  <a href="https://support.sendwyre.com/sending-money/send-money-to-china/list-of-supported-chinese-banks" target="_blank">here</a>.



### Step 3. Create a transfer

```json
{
  "dest": {
    "paymentMethodType":"INTERNATIONAL_TRANSFER",
    "country": "CN",
    "currency": "CNY",
    "beneficiaryType": "INDIVIDUAL",
    "paymentType" : "LOCAL_BANK_TRANSFER", // LOCAL_BANK_TRANSFER only
    "nameOnAccount": "张三",
    "accountNumber": "0000000000000000",
    "bankName": "中国工商银行",
    "branchName":"上海分行田林支行",
    "bankCity":"上海",
    "bankProvince": "上海"
  },
  "sourceCurrency": "USD",
  "destCurrency": "CNY",
  "destAmount": 10,
  "message": "CNY example", // optional - note
  "referenceNumber": "", // optional - reference number
  "customId": "", // optional - unique identifier you can assign
  "autoConfirm": "true", //optional - automatically confirm if true
  "amountIncludesFees": "true", // optional -  if true, the amount given (source, dest, equiv) will be treated as already including the fees and nothing in addition will be withdrew
  "callbackUrl": "" // optional - location where to receive callbacks
}
```
`POST` https://api.sendwyre.com/v2/transfers <br>

Next, create a transfer on behalf of the user to send the payout to the user's recipient in China. Keep in mind all of the [requirements for China's payouts](http://sendwyre.com/docs/#china). <br>

Note that _Chinese characters_ need to be passed for `nameOnAccount`, `bankName`, `branchName`, `bankCity` and `bankProvince`. 

When you perform the create transfer API call, you will receive a 200 response including `totalFees` which will break down all the Wyre fees. The transfer will not execute however until you confirm it. You can confirm simultaneously in the create transfer call by adding parameter `autoConfirm` and setting that to "true" (see example on right). Otherwise you can perform the [confirm transfer](http://sendwyre.com/docs/#confirm-transfer) API call within a 30 second window to lock in that rate.  <br>


### Step 3. Receive payment status

`GET` https://api.sendwyre.com/v2/transfer/:customId <br>

Periodically [check payment status](http://sendwyre.com/docs/#lookup-transfer) for all pending payments via API (every 15 minutes). When payment is detected as “Completed”, your platform can notify the user via their own system. 


## Bitcoin in a Box

**Building a bitcoin brokerage on Wyre’s API** 

There are many ways to use the Wyre API to provide different types of bitcoin trading and payout services. To help developers understand how it may be used, we’ve described a typical use-case below. <br>

This cookbook will show you an example of how an online platform may provide bitcoin buy/sell services to their users via the Wyre API. The platform will utilise the Wallet feature to segregate client funds in “sub-accounts”. <br>

Live rates will be provided to the users via the Wyre API, and when a user wishes to make a purchase, a rate will be locked in and the user given 30 seconds to confirm.<br>

A USD float (prefund) will be maintained on the Wyre platform, and topped up on a weekly basis according to transaction volume. The online platform will use their own bank account to receive USD from users for bitcoin buys.
BTC withdrawals will be disbursed by Wyre to users. USD withdrawals will be disbursed by the online platform via their local banking system.<br>

For a bitcoin purchase, the flow of funds will normally look something like this:<p>
![flow](flow.png)



### Step 1. A new user signs up on the client's platform

```cURL

curl -v -XPOST 'https://api.sendwyre.com/v2/wallets' \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}" \
  -d '{"type":"ENTERPRISE","name":"{your-unique-identifier}",
  "callbackUrl":"https://your.website.io/callback",
  "notes":"Notes about the sub account"}'
  ```
`POST` https://api.sendwyre.com/v2/wallets <br>

Once a new user registers on the client's platform (not Wyre), [create a wallet](http://sendwyre.com/docs/#create-wallet) on Wyre for that user. <br>

Each wallet will automatically be assigned a unique BTC address.

Take note of the `walletId` that gets generated in the response as this will be used later to create a money transfer.
 


### Step 2. User makes a deposit on client's platform

```json
{  
   "source":"account:accoundId",
   "sourceCurrency":"USD",
   "sourceAmount":"10000",
   "dest":"wallet:walletId",
   "destCurrency":"USD", 
   "autoConfirm": "true" 
}
```

`POST` https://api.sendwyre.com/v2/transfers <br>

Once the user deposits USD on the client's platform, [create a transfer](http://sendwyre.com/docs/#create-transfer) on Wyre by sending USD from the master account to that user's wallet from Step 1 and automatically Confirm Transfer. <br>

For `source`, put your Wyre account ID which can be found [here](https://www.sendwyre.com/settings/basic-info). 



### Step 3. Check live exchange rates

`GET` https://api.sendwyre.com/v2/rates <br>

You can ping the [rates API](http://sendwyre.com/docs/#live-exchange-rates) to check the buy and sell rates for BTC which refreshes every 30 seconds. <br>

The mid market rate is calculated as MMR = (Buy rate + Sell Rate)/2. This rate is obtained from [openexchangerates.org](https://openexchangerates.org)



### Step 4. Transfer USD from account to BTC to wallet 

```json
{ 
"source": "wallet:walletId" 
"dest": "wallet:walletId", 
"sourceCurrency": "USD", 
"destCurrency": "BTC", 
"destAmount": n1000, 
"autoConfirm": "true", 
"message":"USD Personal example" 
}
```
`POST` https://api.sendwyre.com/v2/transfers <br>

The user decides to buy BTC with a portion of their USD. <br>

Create a transfer, initiating a buy of BTC with the USD from that user's wallet to his/her wallet. 




### Step 5. Confirm the transfer 

`POST` https://api.sendwyre.com/v2/transfer/transferId:/confirm <br>

Confirm the transfer using `transferId` retrieved from Step 4. <br>

`GET` https://api.sendwyre.com/v2/wallet/{walletId} <br>

The next step is to [check the bitcoin balance](http://sendwyre.com/docs/#lookup-wallet) of your wallet. 




### Step 6. User withdraws some BTC

```json
{ 
"source": "wallet:walletId" 
"dest": "bitcoin: bitcoin address", 
"sourceCurrency": "BTC", 
"destCurrency": "BTC", 
"destAmount": 10, 
"autoConfirm":"true" 
}
```

`POST` https://api.sendwyre.com/v2/transfers <br>

Let's say the user wants to withdraw BTC from the client's platform. <br>

On Wyre, you can create a third transfer to send BTC from the user's wallet to their external bitcoin address. <br>

Set `autoConfirm` to "true" to automatically confirm the transfer. 



### Step 7. The user wants to cash out their remaining USD

```json
{ 
"source": "wallet:walletId" 
"dest": "account:accountId", 
"sourceCurrency": "USD", 
"destCurrency": "USD", 
"destAmount": 1000, 
"autoConfirm":"true" //automatically confirms transfer 
}
```

Let's say the user wants to withdraw their remaining USD balance from the client's platform. <br>

Create a transfer to send the remaining USD balance from the user's wallet to the master account.<br>

Automatically confirm transfer by setting `autoConfirm` to "true". <br>

Afterwards, the client's platform should deliver payout to the user from the client's bank account. 



### Step 8. Your platform wants to withdraw USD back to own account.

You can send a request to our payment operations team at `payops@sendwyre.com`.


# Rates

## Live Exchange Rates

We offer an exchange rates endpoint which provides the current Wyre brokering rate. Wyre uses the Mid Market Exchange Rate (MMR) which is the midpoint between the selling price and buying price of a given currency. This is approximately the exchange rate that will be used for any relatively small exchange through our platform (larger exchanges may give different rates depending on market depth). You can read more about how we use MMR [here](https://support.sendwyre.com/fees-and-rates/what-exchange-rates-do-you-use). 

**Definition** <br>
`GET`  https://api.sendwyre.com/v2/rates <br>

The ordering of the trade pair in the key represents the direction of an exchange. For example, `CADUSD` is the rate used for CAD into USD conversions (e.g. the sell rate). On the other hand, converting USD into CAD (the buy rate) would use the opposite rate under `USDCAD`.

You can also view the rates in different formats according to your preference:<br>

*https://api.sendwyre.com/v2/rates?as=divisor* - source amount / rate = destination amount (default)<br>

*https://api.sendwyre.com/v2/rates?as=multiplier* - source amount * rate = destination amount<br>

*https://api.sendwyre.com/v2/rates?as=priced* - shows both divisor and multiplier values side by side<br>

For example, if 1 BTC is selling at 9000 USD, `USDBTC` will be 9000 in the *divisor* view and (1/9000) in the *pretty* view. 


# Account

## Account Details

This endpoint retrieves all the information related to your account. All of the information displayed in the Wyre dashboard can be found here. <br>

**Definition** <br>

`GET` https://api.sendwyre.com/v2/account <br>

When checking your balance you should refer to the `availableBalance` object to see how much of a given currency you have available to transfer.

Field | Description
--------- | -----------
ID | An internal Wyre id corresponding to your account.
createdAt | Time at which the account was created.
updatedAt | The last time the account was updated.
loginAt | The last time the account was logged in to.
rank | The account's rank. Used for things like limits on the accounts option to purchase digital currencies.
profile | A set of fields that the user has permission to modify.
paymentMethods | A list of payment methods available on the account to make digital currency purchases.
identities | 	An array of identities (cellphone numbers, email addresses) associated with the account. Each identity includes information about when they were created and when they were verified.
depositAddresses | A map of digital currency deposit addresses for the account.
totalBalances | A map of the total amount of funds in the user's account. This is the sum of the pending balances and the available balances.
availableBalances | A map of the total amount of funds available to be withdrawn immediately from the account. If you are performing a check to see if the account has sufficient funds before making a withdrawal, you should check this balance.
email | The email tied to the account.
cellphone | The cellphone number tied to the account.

**Result Format** <br>

<pre class="center-column">
{
  "id": "121pd02kt0rnb24nclsg4bglanimurqp",
  "createdAt": 1404177262332,
  "updatedAt": 1404177262332,
  "loginAt": 1404177262332,
  "rank": 0,
  "profile": {
    "firstName": "",
    "lastName": "",
    "locale": "EN_us",
    "address": {
      "street1": null,
      "street2": null,
      "city": null,
      "state": null,
      "postalCode": null,
      "country": "USA"
    },
    "businessAccount": true,
    "taxId": null,
    "doingBusinessAs": null,
    "website": null,
    "dateOfBirth": 1404177262332,
    "notifyEmail": true,
    "notifyCellphone": true,
    "notifyApnsDevice": true,
    "mfaRequiredForPwChange": false,
    "mfaRequiredForDcPurchase": false,
    "mfaRequiredForSendingFunds": false,
    "authyPhoneNumber": null
  },
  "paymentMethods": [],
  "identities": [
    {
      "srn": "email:sam@doonstack.com",
      "createdAt": 1404177262332,
      "verifiedAt": 1404177262332
    }
  ],
  "depositAddresses": {
    "BTC": "1H9K67J9NcYtzmFGojR9cgM5ybxEddySwu"
  },
  "totalBalances": {
    "USD": 11.8934023,
    "BTC": 265.112
  },
  "availableBalances": {
    "USD": 10.8934023,
    "BTC": 250.112
  },
  "email": "sam@doonstack.com",
  "cellphone": "+15234897342"
}
</pre>

# Wallets

If you need to manage your account's balances into individual buckets, you may choose to use the Wallets API. You can send Bitcoin or Ethereum to the wallet which will be automatically assigned a unique bitcoin or ethereum deposit address. 

## Create Wallet
```cURL

curl -v -XPOST 'https://api.sendwyre.com/v2/wallets' \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}" \
  -d '{"type":"ENTERPRISE","name":"{your-unique-identifier}",
  "callbackUrl":"https://your.website.io/callback",
  "notes":"Notes about the sub account"}'
  
 ```
 
 ```java
 import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.Integer;
import java.lang.String;
import java.lang.StringBuffer;
import java.net.HttpURLConnection;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    String accountId = "k3f48j0rb2rp65c0sdog67vi43u80jas";
    String apiKey = "fll36l3t35udalcqlh4ng6bm4qpbgher";
    String secretKey = "tr3epinbk3maist0n3ijk18bm6dikrq6";

    String url = "https://api.sendwyre.com/v2/wallets";
    String method = "POST";
    String data = "";

    String result = excuteWyereRequest(url, "", method, apiKey, secretKey);
    System.out.println(result);

    data = "{" +
        "  \"type\":\"ENTERPRISE\"," +
        "  \"name\":\"{your-unique-identifier}\"," +
        "  \"callbackUrl\":\"https://your.website.io/callback\"," +
        "  \"notes\":\"Notes about the user\"," +
        "  \"verificationData\": {" +
        "      \"firstName\":\"{users-first-name}\"," +
        "      \"middleName\":\"{users-middle-name}\"," +
        "      \"lastName\":\"{users-last-name}\"," +
        "      \"ssn\":\"0000\"," +
        "      \"passport\":\"123456\"," +
        "      \"birthDay\":\"1\"," +
        "      \"birthMonth\":\"1\"," +
        "      \"birthYear\":\"1970\"," +
        "      \"phoneNumber\":\"+15555555555\"," +
        "      \"address\": {" +
        "          \"street1\":\"1 Market Street\"," +
        "          \"street2\":\"Suit 420\"," +
        "          \"city\":\"San Francisco\"," +
        "          \"state\":\"CA\"," +
        "          \"postalCode\":\"94105\"," +
        "          \"country\":\"US\"" +
        "      }" +
        "  }" +
        "}";
    result = excuteWyreRequest(url, data, method, apiKey, secretKey);

    System.out.println(result);
  }

  public static String excuteWyreRequest(String targetURL, String requestBody, String method, String apiKey, String secretKey) {
    URL url;
    HttpURLConnection connection = null;
    try {

      targetURL += ((targetURL.indexOf("?")>0)?"&":"?") + "timestamp=" + System.currentTimeMillis();

      //Create connection
      url = new URL(targetURL);
      connection = (HttpURLConnection)url.openConnection();
      connection.setRequestMethod(method);
      System.out.println(connection.getRequestMethod());

      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Content-Length", Integer.toString(requestBody.getBytes().length));

      //Specify API v2
      connection.setRequestProperty("X-Api-Version","2");

      // Provide API key and signature
      connection.setRequestProperty("X-Api-Key", apiKey);
      connection.setRequestProperty("X-Api-Signature",computeSignature(secretKey,targetURL,requestBody));

      //Send request
      if(method.equals("POST")) {
        connection.setDoOutput(true);
        connection.setRequestMethod(method);

        DataOutputStream wr = new DataOutputStream(
            connection.getOutputStream());

        wr.writeBytes(requestBody);
        wr.flush();
        wr.close();
      }

      //Get Response
      InputStream is = connection.getInputStream();
      BufferedReader rd = new BufferedReader(new InputStreamReader(is));
      String line;
      StringBuffer response = new StringBuffer();
      while((line = rd.readLine()) != null) {
        response.append(line);
        response.append('\r');
      }
      rd.close();
      return response.toString();

    } catch (Exception e) {

      e.printStackTrace();
      return null;

    } finally {

      if(connection != null) {
        connection.disconnect();
      }
    }
  }

  public static String computeSignature(String secretKey, String url, String reqData) {

    String data = url + reqData;

    System.out.println(data);

    try {
      Mac sha256Hmac = Mac.getInstance("HmacSHA256");
      SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
      sha256Hmac.init(key);

      byte[] macData = sha256Hmac.doFinal(data.getBytes());

      String result = "";
      for (final byte element : macData){
        result += Integer.toString((element & 0xff) + 0x100, 16).substring(1);
      }
      return result;

    } catch (Exception e) {
      e.printStackTrace();
      return "";
    }
  }
}
```

```python
#dependencies:
#python3
#pip3 install requests

import json
import hmac
import time
from requests import request

class MassPay_API(object):
    def __init__(self, account_id, api_version, api_key, api_secret):
        self.account_id = account_id
        self.api_url = 'https://api.sendwyre.com/{}'.format(api_version)
        self.api_version = api_version
        self.api_key = api_key
        self.api_secret = api_secret

    #authentication decorator. May raise ValueError if no json content is returned
    def authenticate_request(func):
        def wrap(self, *args, **kwargs):
            url, method, body = func(self, *args, **kwargs)
            params = {}
            timestamp = int(time.time() * 1000)
            url += '?timestamp={}'.format(timestamp)
            bodyJson = json.dumps(body) if body != '' else ''
            headers = {}
            headers['Content-Type'] = 'application/json'
            headers['X-Api-Version'] = self.api_version
            headers['X-Api-Key'] = self.api_key
            headers['X-Api-Signature'] = hmac.new(self.api_secret.encode('utf-8'), (url + bodyJson).encode('utf-8'), 'SHA256').hexdigest()
            print(headers['X-Api-Signature'])
            resp = request(method=method, url=url, params=params, data=(json.dumps(body) if body != '' else None), json=None, headers=headers)
            if resp.text is not None: #Wyre will always try to give an err body
                return resp.status_code, resp.json()
            return 404, {}
        return wrap

    @authenticate_request
    def create_user(self, name, callbackUrl, notes, verificationData):
        url = self.api_url + '/wallets'
        method = 'POST'
        body = {'name':name,
                'verificationData':verificationData,
                'type':'ENTERPRISE'}
        if callbackUrl:
            body["callbackUrl"] = callbackUrl
        if notes:
            body['notes'] = notes
        return url, method, body 

#USAGE Example
account_id = "YOUR_ACCOUNT_ID_HERE" #optional
api_key = "YOUR_API_KEY_HERE"
secret_key = "YOUR_SECRET_KEY_HERE"
api_version = "2"

#create Wyre MassPay API object
Wyre = MassPay_API(account_id, api_version, api_key, secret_key)

#create user and print result
http_code, result = Wyre.create_user(
                                "{your-unique-identifier}", 
                                "https://your.website.io/callback", 
                                None, #notes
                                {
                                  "firstName": "{users-first-name}",
                                  "middleName": "{users-middle-name}",
                                  "lastName": "{users-last-name}",
                                  "ssn": "0000",
                                  "passport": "123456",
                                  "birthDay": "1",
                                  "birthMonth": "1",
                                  "birthYear": "1970",
                                  "phoneNumber": "+15555555555",
                                  "address": {
                                    "street1":"1 Market Street",
                                    "street2":"Suite 420",
                                    "city":"San Francisco",
                                    "state":"CA",
                                    "postalCode":"94105",
                                    "country":"US"
                                  }
                                })
print(result)
users_srn = result['srn'] #grab our srn identifier for the user
'''

'''php
<?php
    function make_authenticated_request($endpoint, $method, $body) {
        $url = 'https://api.sendwyre.com';
        $api_key = "bh405n7stsuo5ut30iftrsl71b4iqjnv";
        $secret_key = "a19cvrchgja82urvn47kirrlrrb7stgg";

        $timestamp = floor(microtime(true)*1000);
        $request_url = $url . $endpoint;

        if(strpos($request_url,"?"))
            $request_url .= '&timestamp=' . $timestamp;
        else
            $request_url .= '?timestamp=' . $timestamp;

        if(!empty($body))
            $body = json_encode($body, JSON_FORCE_OBJECT);
        else
            $body = '';

        $headers = array(
            "Content-Type: application/json",
            "X-Api-Key: ". $api_key,
            "X-Api-Signature: ". calc_auth_sig_hash($secret_key, $request_url . $body),
            "X-Api-Version: 2"
        );
        $curl = curl_init();

        if($method=="POST"){
          $options = array(
            CURLOPT_URL             => $request_url,
            CURLOPT_POST            =>  true,
            CURLOPT_POSTFIELDS      => $body,
            CURLOPT_RETURNTRANSFER  => true);
        }else {
          $options = array(
            CURLOPT_URL             => $request_url,
            CURLOPT_RETURNTRANSFER  => true);
        }
        curl_setopt_array($curl, $options);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        $result = curl_exec($curl);
        curl_close($curl);
        var_dump($result);
        return json_decode($result, true);
    }

    function calc_auth_sig_hash($seckey, $val) {
        $hash = hash_hmac('sha256', $val, $seckey);
        return $hash;
    }

    $userData = array(
      "type"=>"ENTERPRISE",
      "name"=>"{your-unique-identifier}",
      "callbackUrl"=>"https://your.website.io/callback",
      "notes"=> "Notes about the user",
      "verificationData"=> array(
          "firstName"=> "{users-first-name}",
          "middleName"=> "{users-middle-name}",
          "lastName"=> "{users-last-name}",
          "ssn"=> "0000",
          "passport"=> "12345",
          "birthDay"=> "1",
          "birthMonth"=> "1",
          "birthYear"=> "1970",
          "phoneNumber"=> "+15555555555",
          "address"=> array(
            "street1":"1 Market Street",
            "street2":"Suite 420",
            "city":"San Francisco",
            "state":"CA",
            "postalCode":"94105",
            "country":"US"
          )
        )
      );
    echo make_authenticated_request("/wallets", "POST", $userData);
?>
```

This endpoint creates a child wallet for a user and assigns a unique Bitcoin or Ethereum address to that child wallet. <br>

**Definition** <br>

`POST` https://api.sendwyre.com/v2/wallets <br>

**Parameters**

Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
name | string | Unique identifier for the user | yes
callbackUrl | string | Callback url we will make HTTP postbacks to on wallet updates | no
type | string | The type of wallet you are creating; defaults to `DEFAULT` | no
notes | string | Notes about the user | no

**Result Format**


<pre class="center-column">
{
  "name" : "{your-unique-identifier}",
  "id" : "WA-AYBNA3lBiWAM4l3",
  "depositAddresses" : {
    "BTC" : "2ShL7kzSNNxedit6hC2fjSQhVcAucTeS1m7"
  },
  "totalBalances" : {
    "BTC" : 0
  },
  "availableBalances" : {
    "BTC" : 0
  },
  "srn" : "wallet:AYBNA3lBiWAM4l3",
  "balances" : {
    "BTC" : 0
  },
  "callbackUrl" : "https://your.website.io/callback",
  "notes" : "Notes about the user"
}
</pre>

## Create Mulitple Wallets

```cURL

curl -XPOST 'https://api.sendwyre.com/v2/wallets/batch?pretty' \
-H 'Content-Type:application/json' \
-d '{
  "wallets":[
    {"name":"walletOne"},
    {"name":"walletTwo"},
    {"name":"walletThree"}
  ]
}'
```

This endpoint allows you to creates a batch of child wallets (1 child wallet/user) in one request. <br>

**Definition** <br>

`POST` https://api.sendwyre.com/v2/wallets/batch <br>

**Parameters**

Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
wallets | array | array of wallet creation objects | yes

**Result Format**



<pre class="center-column">
{
  "name" : "walletOne",
  "id" : "AxVA57edP0H33x3",
  "notes" : null,
  "srn" : "wallet:AxVA57edP0H33x3",
  "callbackUrl" : null,
  "verificationData" : null,
  "depositAddresses" : {
    "BTC" : "2ShKKFb9gEP5uvRXtMbs7ykJAMPgoSSnSWB"
  },
  "totalBalances" : {
    "BTC" : 0
  },
  "availableBalances" : {
    "BTC" : 0
  },
  "balances" : {
    "BTC" : 0
  }
}, {
  "name" : "walletTwo",
  "id" : "AtEhoXje3C1V5zq",
  "notes" : null,
  "srn" : "wallet:AtEhoXje3C1V5zq",
  "callbackUrl" : null,
  "verificationData" : null,
  "depositAddresses" : {
    "BTC" : "2ShKndBJNHvzABhBzLxvfzzD2vt64C36dPc"
  },
  "totalBalances" : {
    "BTC" : 0
  },
  "availableBalances" : {
    "BTC" : 0
  },
  "balances" : {
    "BTC" : 0
  }
}, {
  "name" : "walletThree",
  "id" : "U07tSKMvofeMmx0",
  "notes" : null,
  "srn" : "wallet:U07tSKMvofeMmx0",
  "callbackUrl" : null,
  "verificationData" : null,
  "depositAddresses" : {
    "BTC" : "2ShJsBPUb4HrNtgaNZk3YQSi2ynpZ5YY7sT"
  },
  "totalBalances" : {
    "BTC" : 0

  },
  "availableBalances" : {
    "BTC" : 0
  },
  "balances" : {
    "BTC" : 0
  }
} 

</pre>

## Lookup Wallet
```cURL

Lookup by user ID:

curl -v -XGET 'https://api.sendwyre.com/v2/wallet/{wallet-id}' \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}" \
  
  
  
Lookup by user name: 
curl -v -XGET 'https://api.sendwyre.com/v2/wallet' \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}" \
  -d name={your-identifier}

```

This endpoint allows you to look up the balance of a child wallet by ID or name. <br>

**Definition** <br>

`GET` https://api.sendwyre.com/v2/wallet/{walletId} <br>

**Parameters** <br>

Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
walletId | string | ID of the wallet | yes


**Definition** <br>

`GET` https://api.sendwyre.com/v2/wallet/ <br>

**Parameters** <br>

Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
name | string | name of the wallet | yes

**Results Format**<br>
<pre class="center-column">
{
   “owner”: “account:[account-ID]“,
   “callbackUrl”: null,
   “depositAddresses”: {
       “BTC”: “1FNAkNVt3gXdS3PZ1tDvetbcafKPsJPQTG”
   },
   “totalBalances”: {
       “USD”: 4.96
   },
   “availableBalances”: {
       “USD”: 4.96
   },
   “verificationData”: null,
   “balances”: {
       “USD”: 4.96
   },
   “srn”: “wallet:[Wallet-ID]“,
   “createdAt”: 1497861843000,
   “notes”: “test1”,
   “name”: “richard”,
   “id”: “[Wallet-ID]”
}
</pre>


## Edit Wallet
```cURL

curl -v -XPOST 'https://api.sendwyre.com/v2/wallet/{wallet-id}/update' \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}" \
  -d '{"name":"{your-unique-identifier}","notes":"Updated notes about the sub account"}'
```

```python

#dependencies:
#python3
#pip3 install requests

import json
import hmac
import time
from requests import request

class MassPay_API(object):
    def __init__(self, account_id, api_version, api_key, api_secret):
        self.account_id = account_id
        self.api_url = 'https://api.sendwyre.com/{}'.format(api_version)
        self.api_version = api_version
        self.api_key = api_key
        self.api_secret = api_secret

    #authentication decorator. May raise ValueError if no json content is returned
    def authenticate_request(func):
        def wrap(self, *args, **kwargs):
            url, method, body = func(self, *args, **kwargs)
            params = {}
            timestamp = int(time.time() * 1000)
            url += '?timestamp={}'.format(timestamp)
            bodyJson = json.dumps(body) if body != '' else ''
            headers = {}
            headers['Content-Type'] = 'application/json'
            headers['X-Api-Version'] = self.api_version
            headers['X-Api-Key'] = self.api_key
            headers['X-Api-Signature'] = hmac.new(self.api_secret.encode('utf-8'), (url + bodyJson).encode('utf-8'), 'SHA256').hexdigest()
            print(headers['X-Api-Signature'])
            resp = request(method=method, url=url, params=params, data=(json.dumps(body) if body != '' else None), json=None, headers=headers)
            if resp.text is not None: #Wyre will always try to give an err body
                return resp.status_code, resp.json()
            return 404, {}
        return wrap

    @authenticate_request
    def update_user(self, walletId, name, callbackUrl, notes, verificationData):
        url = self.api_url + '/wallet/' + walletId + '/update
        method = 'POST'
        body = {'name':name}
        if callbackUrl:
            body["callbackUrl"] = callbackUrl
        if notes:
            body['notes'] = notes
        if verificationData:
            body['verificationData'] = verificationData
        return url, method, body 

#USAGE Example
account_id = "YOUR_ACCOUNT_ID_HERE" #optional
api_key = "YOUR_API_KEY_HERE"
secret_key = "YOUR_SECRET_KEY_HERE"
api_version = "2"

#create Wyre MassPay API object
Wyre = MassPay_API(account_id, api_version, api_key, secret_key)

#create user and print result
http_code, result = Wyre.update_user(
                                "{wallet-id}",
                                "{your-unique-identifier}", 
                                None, #callbackUrl
                                "Updated notes for user",
                                None #verification data
                                )
print(result)
users_srn = result['srn'] #grab our srn identifier for the user


```

```java

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.Integer;
import java.lang.String;
import java.lang.StringBuffer;
import java.net.HttpURLConnection;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    String accountId = "k3f48j0rb2rp65c0sdog67vi43u80jas";
    String apiKey = "fll36l3t35udalcqlh4ng6bm4qpbgher";
    String secretKey = "tr3epinbk3maist0n3ijk18bm6dikrq6";
  
    String walletId = "{wallet-id}";
    
    String url = "https://api.sendwyre.com/v2/wallet/"+ walletId +"/update";
    String method = "POST";
    String data = "";

    String result = excuteWyreRequest(url, "", method, apiKey, secretKey);
    System.out.println(result);

    data = "{" +
        "  \"name\":\"{your-unique-identifier}\"," +
        "  \"notes\":\"Updated notes about the user\"" +
        "}";
    result = excuteWyreRequest(url, data, method, apiKey, secretKey);

    System.out.println(result);
  }

  public static String excuteWyreRequest(String targetURL, String requestBody, String method, String apiKey, String secretKey) {
    URL url;
    HttpURLConnection connection = null;
    try {

      targetURL += ((targetURL.indexOf("?")>0)?"&":"?") + "timestamp=" + System.currentTimeMillis();

      //Create connection
      url = new URL(targetURL);
      connection = (HttpURLConnection)url.openConnection();
      connection.setRequestMethod(method);
      System.out.println(connection.getRequestMethod());

      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("Content-Length", Integer.toString(requestBody.getBytes().length));

      //Specify API v2
      connection.setRequestProperty("X-Api-Version","2");

      // Provide API key and signature
      connection.setRequestProperty("X-Api-Key", apiKey);
      connection.setRequestProperty("X-Api-Signature",computeSignature(secretKey,targetURL,requestBody));

      //Send request
      if(method.equals("POST")) {
        connection.setDoOutput(true);
        connection.setRequestMethod(method);

        DataOutputStream wr = new DataOutputStream(
            connection.getOutputStream());

        wr.writeBytes(requestBody);
        wr.flush();
        wr.close();
      }

      //Get Response
      InputStream is = connection.getInputStream();
      BufferedReader rd = new BufferedReader(new InputStreamReader(is));
      String line;
      StringBuffer response = new StringBuffer();
      while((line = rd.readLine()) != null) {
        response.append(line);
        response.append('\r');
      }
      rd.close();
      return response.toString();

    } catch (Exception e) {

      e.printStackTrace();
      return null;

    } finally {

      if(connection != null) {
        connection.disconnect();
      }
    }
  }

  public static String computeSignature(String secretKey, String url, String reqData) {

    String data = url + reqData;

    System.out.println(data);

    try {
      Mac sha256Hmac = Mac.getInstance("HmacSHA256");
      SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
      sha256Hmac.init(key);

      byte[] macData = sha256Hmac.doFinal(data.getBytes());

      String result = "";
      for (final byte element : macData){
        result += Integer.toString((element & 0xff) + 0x100, 16).substring(1);
      }
      return result;

    } catch (Exception e) {
      e.printStackTrace();
      return "";
    }
  }
}

```


This endpoint updates the information for a accounts child wallet. <br>

**Definition** <br>

`UPDATE` https://api.sendwyre.com/v2/wallet/{walletId} <br>

**Parameters**

Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
walletId | string | ID of the wallet | yes
name | string | Updated identifier for the user | no
callbackUrl | string | Updated callback | no
notes | string | Updated notes | no


## Delete Wallet
```cURL

curl -v -XDELETE 'https://api.sendwyre.com/v2/wallet/{wallet-id}' \
  -H "X-Api-Key: {api-key}" \
  -H "X-Api-Signature: {signature}"


```


This endpoint removes the account's child wallet from your account. <br>

**Definition** <br>

`DELETE` https://api.sendwyre.com/v2/wallet/{walletId} <br>

**Parameters**

Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
walletId | string | ID of the wallet | yes

## List Wallets


This endpoint will return all the child wallets you have created. <br>

**Definition** <BR>

`GET` https://api.sendwyre.com/v2/wallets <BR>
  
**Parameters**

Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
limit | string | The number of results returned | yes
offset | string | The number of records to skip | yes


**Result Format**

<pre class="center-column">

{
  "data": {
      "owner": "account:XAV3CRAC94P",
      "balances": {},
      "srn": "wallet:WA-XM4L3JMUQGF",
      "createdAt": 1508433396000,
      "callbackUrl": "https://shake.webscript.io/callback",
      "depositAddresses": {
        "BTC": "1Q9TqsVwuZf6bYqtxxjqdataXx81x3Q1h7"
      },
      "totalBalances": {},
      "availableBalances": {},
      "notes": "nope",
      "name": "Person A",
      "id": "WA-XM4L3JMUQGF"
    },
    {
      "owner": "account:XAV3CRAC94P",
      "balances": {},
      "srn": "wallet:WA-VXRYUHW6JPX",
      "createdAt": 1508203688000,
      "callbackUrl": null,
      "depositAddresses": {
        "BTC": "13UtPuSaHCTsqRkwYjMbypSnPGkcyrni3r"
      },
      "totalBalances": {},
      "availableBalances": {},
      "notes": null,
      "name": "123456",
      "id": "WA-VXRYUHW6JPX"
    }
}
</pre>

## Callbacks

We provide a series of HTTP callbacks that allow you to notify users when funds have been deposited and when they become available.

**When callbacks are sent** <br>
Callbacks are sent whenever a transactional event occurs that will affect the wallet's balance. Examples include:

* Incoming pending transaction
* Pending transaction confirmed
* Outgoing transaction 
<br>

You may receive two callbacks for a single transaction. This is especially true for transactions on the blockchain. In these cases, you would receive one callback when the transaction is first observed and one callback once the transaction is confirmed.

**Callback Acceptance and Retries** <br>
Your system should respond to the callback request with a 200 response. We only attempt to send the request once, but we may introduce automatic retries in the future. We can manually resend callbacks upon request.

**Result Format** <br>

<pre class="center-column">
{
     "id": "4vofvbjjvo4g5cn03ibcosja5mks3o22opskgmicdh",
     "source": "bitcoin:EXTERNAL",
     "dest": "wallet:2ef8mls9v9ovvqimiv2jmn0d33nf30dt",
     "currency": "BTC",
     "amount": 0.0001,
     "status": "CONFIRMED",
     "createdAt": 1436996049910,
     "confirmedAt": 1436996049910,
     "invalidatedAt": null,
     "message": "One Banana nut muffin please!",
     "equivalencies": {
     "EUR": 0.03,
     "BRL": 0.1,
     "AUD": 0.04,
     "USD": 0.03,
     "GBP": 0.02
},
     "senderId": null,
     "senderProvidedId": null,
     "reversedBy": null,
     "relatedTx": null,
     "blockchainTx": null,
      "rates": null,
      "sourceName": "EXTERNAL",
      "sourceIcon": null,
      "destName": "muffinTop@sendwyre.com",
      "destIcon": null
</pre>

The callback payload will be a JSON representation of the transaction that has caused the callback to trigger. 

# Transfers

## Introduction

Transfers represent the building blocks of our API. Our Transfer API is an incredibly versatile way of moving funds not only externally but internally as well, whether it's through internal account management or internal exchanges.  Additionally, you can specify differing source and destination currencies and the funds will automatically exchanged into the appropriate currency in our backend. For example, a common use case is to move funds from a USD Wyre balance into a Chinese CNY bank account.
<br><br>
Anytime you want to move funds around on the Wyre platform you will create a Transfer. The Transfer will go through a number of states as funds are moved to the destination of your choice.<BR>
  
Please refer [here](http://sendwyre.com/docs/#country-currency-requirements) for each country's individual requirements when conducting international transfers. 


## List of Supported Banks

This list will return the latest set of supported banks for either `China` or `Brazil`.

**Definition** <br>

`GET` https://api.sendwyre.com/v2/bankinfo/:country <br>

**Parameters**

Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
country | string | The country you want to get bank info from. Currently the only supported values are CN and BR | yes

* List of supported banks in Brazil also located <a href="https://support.sendwyre.com/sending-money/send-money-to-brazil/supported-banks-in-brazil" target="_blank">here</a>.
* List of supported banks in China also located <a href="https://support.sendwyre.com/sending-money/send-money-to-china/list-of-supported-chinese-banks" target="_blank">here</a>.


## Quote Transfer
```json
{  
   "source":"account:i6rgs8mjdmmu7cnf7a5bgl0r0vudsfe5",
   "sourceCurrency":"USD",
   "sourceAmount":"5",
   "dest":"email:sam@sendwyre.com",
   "destCurrency":"CNY", 
   "preview": "true",
   "amountIncludesFees": "true",
   "message": "" //optional
}
```

Create a transfer to your client's bank account with all the required information. <br>

Set parameter `preview` to "true" and `amountIncludesFees` to "true" to not execute a real transfer and view the fee breakdown. <br>

If `amountIncludesFees` is "true", the amount you consider in `sourceAmount` and `destAmount` will be inclusive of fees. <br> 

The JSON response will return object `totalFees` which will include all Wyre fees and BTC miner fees (if applicable). 

**Definition** <br>
`POST` https://api.sendwyre.com/v2/transfer/<br>

Param | Type | Description | required
--------- | ----------- | ----------- | -----------
source | string | An SRN representing an account that the funds will be retrieved from. | no
sourceAmount | double | The amount to withdrawal from the source, in units of `sourceCurrency`. Only include `sourceAmount` OR `destAmount`, not both. | yes
sourceCurrency | string | The currency to withdrawal from the source wallet. | yes
dest | string | An email address, cellphone number, digital currency address, payment method, wallet to send the digital currency to. For BTC address use "bitcoin:[address]" and for ETH, use "ethereum:[address]". Note: cellphone numbers are assumed to be a US number, for international numbers include a '+' and the country code as the prefix. | yes
destAmount | double | Specifies the total amount of currency to deposit (as defined in depositCurrency). Only include `sourceAmount` OR `destAmount`, not both. | yes
destCurrency | string | The currency to deposit. If not provided, the deposit will be the same as the withdrawal currency (no exchange performed). | yes 
customId | string | An optional tag that must be unique for each transaction if used or transaction will fail. | no
amountIncludesFees | boolean | Optional- if true, the amount given (source, dest, equiv) will be treated as already including the fees and nothing in addition will be withdrew. | no
preview | boolean | If true, creates a quote transfer object, but does not execute a real transfer. | no


## Create Transfer
```json
{  
   "source":"account:i6rgs8mjdmmu7cnf7a5bgl0r0vudsfe5",
   "sourceCurrency":"USD",
   "sourceAmount":"5",
   "dest":"email:sam@sendwyre.com",
   "destCurrency":"CNY", 
   "message": "" //optional
}
```

This endpoint creates a new money transfer. <br>

**Definition** <br>
`POST` https://api.sendwyre.com/v2/transfers <br>

Param | Type | Description | required
--------- | ----------- | ----------- | -----------
source | string | An SRN representing an account that the funds will be retrieved from. | no
sourceAmount | double | The amount to withdrawal from the source, in units of `sourceCurrency`. Only include `sourceAmount` OR `destAmount`, not both. | yes
sourceCurrency | string | An ISO 3166-1 alpha-3 currency code that will be deducted from your account. | yes
dest | string | An email address, cellphone number, digital currency address, payment method, wallet to send the digital currency to. For BTC address use "bitcoin:[address]" and for ETH, use "ethereum:[address]". Note: cellphone numbers are assumed to be a US number, for international numbers include a '+' and the country code as the prefix. | yes
destAmount | double | Specifies the total amount of currency to deposit (as defined in depositCurrency). Only include `sourceAmount` OR `destAmount`, not both. | yes
destCurrency | string | An ISO 3166-1 alpha-3 currency code that matches the dest type. The destCurrency can be the same or different from the sourceCurrency. If they are different an exchange will automatically occur. | yes 
message | string | An optional user visible message to be sent with the transaction. | no
callbackUrl | string | An optional url that Wyre will POST a status callback to. | no
autoConfirm | boolean | An optional parameter to automatically confirm the transfer order. | no
customId | string | An optional tag that must be unique for each transaction if used or transaction will fail. | no
amountIncludesFees | boolean | Optional- if true, the amount given (source, dest, equiv) will be treated as already including the fees and nothing in addition will be withdrew. | no
muteMessages | boolean | When true, disables outbound emails/messages to the destination. | no


Once you've created the transfer it will be in an UNCONFIRMED state. You will have 30 seconds to review the transfer and [confirm it](http://sendwyre.com/docs/#confirm-transfer) before the quote expires. If the quote expires you'll have to reissue the transfer request and confirm the new transfer. However you can CONFIRM the transfer AUTOMATICALLY by setting `autoConfirm` to `true`. <br>

When reviewing the transfer the main things you'll want to check out are the following: <br>

`exchangeRate` - The quoted exchange rate for the transfer <br>
`totalFees` - The total fees will always be represented in the source currency. To convert totalFees to the destination currency, multiply totalFees by the exchange rate. Note that this object includes all Wyre fees and miner fees if applicable.<br>
`sourceAmount/destAmount` - Depending on the request you made, you'll want to double check these fields at this stage and make sure that you're either sending or receiving the amount you expected. Note the values for these fields depend on the `amountIncludesFees` parameter. 

**Result Format**

<pre class="center-column">
{
    "id": "TF-VWGF3WW6JU4",
    "status": "PENDING",
    "failureReason": null,
    "language": "en",
    "createdAt": 1525196883000,
    "updatedAt": 1525196883000,
    "completedAt": 1525196884000,
    "cancelledAt": null,
    "expiresAt": 1525456083000,
    "owner": "account:AC-PJZEFT7JP6J",
    "source": "service:Fiat Credits",
    "dest": "wallet:WA-AFFGZJJ7X82",
    "sourceCurrency": "USD",
    "sourceAmount": 10,
    "destCurrency": "USD",
    "destAmount": 10,
    "exchangeRate": null,
    "message": null,
    "totalFees": 0,
    "fees": {
        "USD": 0
    },
    "customId": null,
    "reversingSubStatus": null,
    "reversalReason": null,
    "pendingSubStatus": null,
    "destName": "amandawallet",
    "sourceName": "Wyre",
    "blockchainTx": null,
    "statusHistories": [
        {
            "id": "HNUBAMZ4YQQ",
            "createdAt": 1525196884000,
            "statusDetail": "Initiating Transfer",
            "state": "INITIATED",
            "failedState": null
        },
        {
            "id": "V8L2MJNPF6D",
            "createdAt": 1525196884000,
            "statusDetail": "Transfer Pending",
            "state": "PENDING",
            "failedState": null
        }
    ]
}
</pre>


## Confirm Transfer

This endpoint confirms a money transfer. Once you've created the transfer and receive a 200 response, you will have 30 seconds to confirm the transfer. Note the `transferId` after you create the transfer. If you want to automatically confirm the transfer without making an additional API call, set parameter `autoConfirm` to "true" in your [Create Transfer](http://sendwyre.com/docs/#create-transfer) request. <br>

**Definition** <br>
`POST` https://api.sendwyre.com/v2/transfer/transferId:/confirm <br>

Param | Type | Description
--------- | ----------- | -----------
transferId | string | ID of the transfer to confirm

**Result Format** <br>

<pre class="center-column">
{
    "id": "TF-VWGF3WW6JU4",
    "status": "COMPLETED",
    "failureReason": null,
    "language": "en",
    "createdAt": 1525196883000,
    "updatedAt": 1525196883000,
    "completedAt": 1525196884000,
    "cancelledAt": null,
    "expiresAt": 1525456083000,
    "owner": "account:AC-PJZEFT7JP6J",
    "source": "service:Fiat Credits",
    "dest": "wallet:WA-AFFGZJJ7X82",
    "sourceCurrency": "USD",
    "sourceAmount": 10,
    "destCurrency": "USD",
    "destAmount": 10,
    "exchangeRate": null,
    "message": null,
    "totalFees": 0,
    "fees": {
        "USD": 0
    },
    "customId": null,
    "reversingSubStatus": null,
    "reversalReason": null,
    "pendingSubStatus": null,
    "destName": "amandawallet",
    "sourceName": "Wyre",
    "blockchainTx": null,
    "statusHistories": [
        {
            "id": "HNUBAMZ4YQQ",
            "createdAt": 1525196884000,
            "statusDetail": "Initiating Transfer",
            "state": "INITIATED",
            "failedState": null
        },
        {
            "id": "V8L2MJNPF6D",
            "createdAt": 1525196884000,
            "statusDetail": "Transfer Completed",
            "state": "COMPLETED",
            "failedState": null
        }
    ]
}
</pre>

## Lookup Transfer

This endpoint allows you to look up information related to a transfer you already created. 

**Definition** <br>
`GET` https://api.sendwyre.com/v2/transfer?customId=

Param | Type | Description
--------- | ----------- | -----------
customId | string | The custom id you provided when creating the transfer

**Result Format** <br>

<pre class="center-column">
{
    "id": "TF-VWGF3WW6JU4",
    "status": "COMPLETED",
    "failureReason": null,
    "language": "en",
    "createdAt": 1525196883000,
    "updatedAt": 1525196883000,
    "completedAt": 1525196884000,
    "cancelledAt": null,
    "expiresAt": 1525456083000,
    "owner": "account:AC-PJZEFT7JP6J",
    "source": "service:Fiat Credits",
    "dest": "wallet:WA-AFFGZJJ7X82",
    "sourceCurrency": "USD",
    "sourceAmount": 10,
    "destCurrency": "USD",
    "destAmount": 10,
    "exchangeRate": null,
    "message": null,
    "totalFees": 0,
    "fees": {
        "USD": 0
    },
    "customId": null,
    "reversingSubStatus": null,
    "reversalReason": null,
    "pendingSubStatus": null,
    "destName": "amandawallet",
    "sourceName": "Wyre",
    "blockchainTx": null,
    "statusHistories": [
        {
            "id": "HNUBAMZ4YQQ",
            "createdAt": 1525196884000,
            "statusDetail": "Initiating Transfer",
            "state": "INITIATED",
            "failedState": null
        },
        {
            "id": "V8L2MJNPF6D",
            "createdAt": 1525196884000,
            "statusDetail": "Transfer Completed",
            "state": "COMPLETED",
            "failedState": null
        }
    ]
}
</pre>

## Transfer Status

**Definition** <br>
`GET` https://api.sendwyre.com/v2/transfer/:transferId

Param | Type | Description
--------- | ----------- | -----------
transferId | string | Wyre generated transferId

**Result Format** <br>

<pre class="center-column">
{
    "id": "TF-VWGF3WW6JU4",
    "status": "COMPLETED",
    "failureReason": null,
    "language": "en",
    "createdAt": 1525196883000,
    "updatedAt": 1525196883000,
    "completedAt": 1525196884000,
    "cancelledAt": null,
    "expiresAt": 1525456083000,
    "owner": "account:AC-PJZEFT7JP6J",
    "source": "service:Fiat Credits",
    "dest": "wallet:WA-AFFGZJJ7X82",
    "sourceCurrency": "USD",
    "sourceAmount": 10,
    "destCurrency": "USD",
    "destAmount": 10,
    "exchangeRate": null,
    "message": null,
    "totalFees": 0,
    "fees": {
        "USD": 0
    },
    "customId": null,
    "reversingSubStatus": null,
    "reversalReason": null,
    "pendingSubStatus": null,
    "destName": "amandawallet",
    "sourceName": "Wyre",
    "blockchainTx": null,
    "statusHistories": [
        {
            "id": "HNUBAMZ4YQQ",
            "createdAt": 1525196884000,
            "statusDetail": "Initiating Transfer",
            "state": "INITIATED",
            "failedState": null
        },
        {
            "id": "V8L2MJNPF6D",
            "createdAt": 1525196884000,
            "statusDetail": "Transfer Completed",
            "state": "COMPLETED",
            "failedState": null
        }
    ]
}
</pre>

Once a Transfer enters the PENDING state we will start moving money to the destination account. At some point the Transfer will either move to a COMPLETED status or a FAILED status asynchronously from any API call.

## Callbacks

We provide a series of HTTP callbacks that allow you to notify users when funds have been deposited and when they become available.

**When callbacks are sent** <br>
Callbacks are sent whenever a transactional event occurs that will affect the account's balance. Examples include:

* Incoming pending transaction
* Pending transaction confirmed
* Outgoing transaction 
<br>

You may receive two callbacks for a single transaction. This is especially true for transactions on the blockchain. In these cases, you would receive one callback when the transaction is first observed and one callback once the transaction is confirmed.

**Callback Acceptance and Retries** <br>
Your system should respond to the callback request with a 200 response. We only attempt to send the request once, but we may introduce automatic retries in the future. We can manually resend callbacks upon request.

**Result Format** <br>

<pre class="center-column">
{
    "id": "TF-VWGF3WW6JU4",
    "status": "COMPLETED",
    "failureReason": null,
    "language": "en",
    "createdAt": 1525196883000,
    "updatedAt": 1525196883000,
    "completedAt": 1525196884000,
    "cancelledAt": null,
    "expiresAt": 1525456083000,
    "owner": "account:AC-PJZEFT7JP6J",
    "source": "service:Fiat Credits",
    "dest": "wallet:WA-AFFGZJJ7X82",
    "sourceCurrency": "USD",
    "sourceAmount": 10,
    "destCurrency": "USD",
    "destAmount": 10,
    "exchangeRate": null,
    "message": null,
    "totalFees": 0,
    "fees": {
        "USD": 0
    },
    "customId": null,
    "reversingSubStatus": null,
    "reversalReason": null,
    "pendingSubStatus": null,
    "destName": "amandawallet",
    "sourceName": "Wyre",
    "blockchainTx": null,
    "statusHistories": [
        {
            "id": "HNUBAMZ4YQQ",
            "createdAt": 1525196884000,
            "statusDetail": "Initiating Transfer",
            "state": "INITIATED",
            "failedState": null
        },
        {
            "id": "V8L2MJNPF6D",
            "createdAt": 1525196884000,
            "statusDetail": "Transfer Completed",
            "state": "COMPLETED",
            "failedState": null
        }
    ]
}
</pre>
The callback payload will be a JSON representation of the transaction that has caused the callback to trigger. 


# Payment Methods


## Create Payment Method

```json

// This is going to be your user's bank information.
We take this as a way to validate that they're the sender of the payment. 
It allows us to know where to expect the payment to be coming from.
{
    "paymentMethodType":"INTERNATIONAL_TRANSFER",
    "country": "US",
    "currency": "USD",
    "beneficiaryType": "INDIVIDUAL",
    "beneficiaryAddress": "112 Brannan St",
    "beneficiaryAddress2": "", //Optional
    "beneficiaryCity": "San Francisco",
    "beneficiaryState": "CA",
    "beneficiaryPostal": "94108",
    "beneficiaryPhoneNumber": "+14102239203",
    "beneficiaryDobDay": "15",
    "beneficiaryDobMonth":"12",
    "beneficiaryDobYear":"1989",
    "paymentType" : "LOCAL_BANK_WIRE", // LOCAL_BANK_WIRE
    "firstNameOnAccount": "Billy-Bob",
    "lastNameOnAccount":"Jones",
    "accountNumber": "0000000000000",
    "routingNumber": "0000000000",
    "accountType": "CHECKING", //CHECKING or SAVINGS
    "chargeablePM": "true"
}

// This is going to be your corporation's bank information. 
We take this as a way to validate that they're the sender of the payment. 
It allows us to know where to expect the payment to be coming from.

{
    "paymentMethodType":"INTERNATIONAL_TRANSFER",
    "country": "US",
    "currency": "USD",
    "beneficiaryType": "CORPORATE",
    "beneficiaryCompanyName":"",
    "beneficiaryAddress": "112 Brannan St",
    "beneficiaryAddress2": "", //Optional
    "beneficiaryCity": "San Francisco",
    "beneficiaryState": "CA",
    "beneficiaryPostal": "94108",
    "beneficiaryLandlineNumber":"+123464542947",
    "beneficiaryEmailAddress":"tes@sendwyre.com",
    "beneficiaryEinTin":"00000000",
    "beneficiaryDobDay": "15", //Date of Incorporation
    "beneficiaryDobMonth":"12", //Date of Incorporation
    "beneficiaryDobYear":"1989", //Date of Incorporation
    "paymentType" : "LOCAL_BANK_WIRE", // LOCAL_BANK_WIRE
    "accountType": "CHECKING", //CHECKING or SAVINGS
    "accountNumber": "0000000000000",
    "routingNumber": "0000000000",
    "chargeablePM": "true"
  }

```
This endpoint creates a bank account. <br>

**Definition**<br>
`POST` https://api.sendwyre.com/v2/paymentMethods <br>

**Parameters**

Param | Type | Description | Required
--------- | ----------- | ----------- | -----------
owner | string | Wallet ID (e.g. wallet:12345) | no
paymentMethodType | string | `INTERNATIONAL_TRANSFER` | yes
paymentType | string | `LOCAL_BANK_WIRE` | yes
currency | string | 3 letter currency code | yes
country | string | Alpha-2 country code | yes
beneficiaryType | string | `INDIVIDUAL` or `CORPORATE` | yes
nameOnAccount | string | Name of beneficiary on account | no
firstNameOnAccount | string | Required for individual | yes
lastNameOnAccount | string | Required for individual | yes 
beneficiaryCompanyName | string | Required for business | yes
beneficiaryEinTin | string | Required for business | yes
beneficiaryAddress | string | Beneficiary's address | no
beneficiaryAddress2 | string | Beneficiary's address | no
beneficiaryCity | string | Beneficiary's city | no
beneficiaryPostal | string | Beneficiary's zip code | no 
beneficiaryPhoneNumber | string | Required for individual | yes
beneficiaryLandlineNumber | string | Required for business | yes
beneficiaryState | string | Beneficiary's state | no
beneficiaryEmailAddress | string | Required for business | yes
beneficiaryDobDay | integer | Beneficiary's birth day | no
beneficiaryDobMonth | integer | Beneficiary's birth month | no
beneficiaryDobYear | integer | Beneficiary's birth year | no
accountNumber | string | Required | yes
routingNumber | string | Required | yes
accountType | string | `CHECKING` or `SAVINGS` | no
chargeablePM | boolean | Set to true | yes

**Result Format**
<pre class="center-column">
{
 id: //the id is also an SRN of the format paymentmethod,
 name:<name>,
 status:"AWAITING_FOLLOWUP | AWAITING_DEPOSIT_VERIFICATION | ACTIVE | REJECTED |  DISABLED | PENDING",
 chargeableCurrencies:["USD"],
 depositableCurrencies:["USD"],
 chargeFeeSchedule:[...],
 depositFeeSchedule:[...],
 minCharge:0.0,
 maxCharge:0.0,
 minDeposit:0.0,
 maxDeposit:0.0
}
 </pre>

## Lookup Payment Method

This endpoint looks up the bank details associated with a payment method you created.<br>

**Definition** <br>
`GET` https://api.sendwyre.com/v2/paymentMethod/:paymentMethodId

**Result Format**
<pre class="center-column">

{
    "id": "TestPaymentMethod",
    "owner": "account:ABCDEFG",
    "createdAt": 1230940800000,
    "name": "TEST PAYMENT METHOD",
    "defaultCurrency": "USD",
    "status": "ACTIVE",
    "statusMessage": null,
    "waitingPrompts": [],
    "linkType": "TEST",
    "supportsDeposit": true,
    "nameOnMethod": null,
    "last4Digits": null,
    "brand": null,
    "expirationDisplay": null,
    "countryCode": null,
    "nickname": null,
    "rejectionMessage": null,
    "disabled": false,
    "supportsPayment": true,
    "chargeableCurrencies": [
        "GBP",
        "MXN",
        "HKD",
        "USD",
        "CNY",
        "BRL",
        "EUR",
    ],
    "depositableCurrencies": [
        "USD"
    ],
    "chargeFeeSchedule": null,
    "depositFeeSchedule": null,
    "minCharge": null,
    "maxCharge": null,
    "minDeposit": null,
    "maxDeposit": null,
    "documents": [],
    "srn": "paymentmethod:TestPaymentMethod"
}

</pre>




# Country/Currency Requirements

Banks in different countries have a unique set of financial requirements that need to be passed to conduct a successful transfer. 

## China

Please note that the minimum amount to transfer CNY is 200 CNY. <br>

**Definition**<br>
`POST` https://api.sendwyre.com/v2/transfers <br><br>

```json
{
  "dest": {
    "paymentMethodType":"INTERNATIONAL_TRANSFER",
    "country": "CN",
    "currency": "CNY",
    "beneficiaryType": "INDIVIDUAL",
    "paymentType" : "LOCAL_BANK_TRANSFER", // LOCAL_BANK_TRANSFER only
    "nameOnAccount": "张三",
    "accountNumber": "0000000000000000",
    "bankName": "中国工商银行",
    "branchName":"上海分行田林支行",
    "bankCity":"上海",
    "bankProvince": "上海"
  },
  "sourceCurrency": "USD",
  "destCurrency": "CNY",
  "destAmount": 10,
  "message": "CNY example", // optional - note
  "referenceNumber": "", // optional - reference number
  "autoConfirm": "true", // optional - automatically confirms transfer
  "callbackUrl": "" // optional - location where to receive callbacks
}
```

**Transfer Requirements** <br>

Parameter | Description 
--------- | ----------- 
dest | object
dest.paymentMethodType | `INTERNATIONAL_TRANSFER`
dest.country | CN
dest.currency | CNY
dest.beneficiaryType | `INDIVIDUAL` or `CORPORATE`
dest.paymentType | `LOCAL_BANK_TRANSFER`
dest.nameOnAccount | As it appears on bank account - Chinese characters for Chinese nationals
dest.accountNumber | Same as bank card number
dest.bankName | Beneficiary bank name in Chinese characters
dest.branchName | Beneficiary branch name in Chinese characters
dest.bankCity | Beneficiary bank city in Chinese characters
dest.bankProvince | Beneficiary bank province in Chinese characters
sourceCurrency | Currency to be debited from your account
destCurrency | Currency to be deposited to the dest. If destCurrency doesn't match the sourceCurrency an exchange will be performed
destAmount | Amount to be deposited to the dest - the amount debited from your account will be calculated automatically from the exchange rate/fees.

**INDIVIDUALS**<br>

* Payments to individuals take a maximum of 6 hours, 24/7.
* Payments over CNY 50,000 will be split into smaller payments to ensure no clearing delays.<br>

**CORPORATES**<br>

* Payments to corporates take a maximum of 6 hours, during normal business banking hours (9:00 - 17:00, Monday - Friday).

**Supported Banks**<br>

* The list of supported banks are located <a href="https://support.sendwyre.com/sending-money/send-money-to-china/list-of-supported-chinese-banks" target="_blank">here</a>.

## Brazil

Please note that the minimum amount to transfer BRL is 10 BRL (Banco do Brasil, Bradesco, Caixa) or 50 BRL (Other banks). <br>

**Definition**<br>
`POST` https://api.sendwyre.com/v2/transfers <br><br>

```json
{
  "dest": {
    "paymentMethodType":"INTERNATIONAL_TRANSFER",
    "bankCode":"341",
    "bankName":"ITAU",
    "branchCode":"6199",
    "nameOnAccount":"Steve McQueen",
    "accountNumber":"4444-5",
    "accountType":"corrente",
    "cpfCnpj":"00000000000",
    "currency":"BRL",
    "country":"BR",
    "accountHolderPhoneNumber":"+559936210617"
  },
  "sourceCurrency": "BRL",
  "destCurrency": "BRL",
  "destAmount": 10,
  "message":"Transfer message"
}
```

**Brazil Requirements** <br>

Parameter | Description 
--------- | ----------- 
dest | object
dest.paymentMethodType | `INTERNATIONAL_TRANSFER`
dest.bankCode | [Supported bank codes](https://api.sendwyre.com/v2/bankinfo/BR)
dest.bankName | [Supported bank names](https://api.sendwyre.com/v2/bankinfo/BR)
dest.branchCode | For bank code 001 and bank code 104: "####-#" - where the first 4 digits are the branch number and the final digit is the branch check digit. Example: "3325-1". For all other banks: "####" - a 4 digit branch number. Example "3325"
dest.accountNumber | Account number needs to follow "22652-1" format 
dest.nameOnAccount | Beneficiary name
dest.accountType | `corrente`
dest.cpfCnpj | Brazilian tax in "25343734391" format
dest.currency | BRL
dest.country | BR
dest.accountHolderPhoneNumber | Beneficiary phone number in format "+559936210716"
sourceCurrency | Currency to be debited from your account
destCurrency | Currency to be deposited to the dest. If destCurrency doesn't match the sourceCurrency an exchange will be performed
destAmount | Amount to be deposited to the dest - the amount debited from your account will be calculated automatically from the exchange rate/fees.

**Supported Banks**<br>

* The list of supported banks are located <a href="https://support.sendwyre.com/sending-money/send-money-to-brazil/supported-banks-in-brazil" target="_blank">here</a>.

**Delivery Times**

Caixa Economica Federal, Bradesco, & Banco do Brasil: <br>

* 1 business day to affiliate the account
* 30 minutes to 24 hours to complete the transactions<br>

All other banks: <br>

* 1 business day to affiliate the account
* 30 minutes to 24 hours to complete the transaction if sent before 3pm and above R$ 250, (otherwise next day)

## Mexico

SPEI - SPEI is Mexico’s lightning fast and inexpensive inter-bank transfer system (akin to SEPA in Europe, and vastly superior to ACH). All bank accounts in Mexico can be identified by their special 18-digit SPEI account number, otherwise known as a ‘CLABE’. Transfers executed via SPEI are typically concluded within a few seconds (within banking hours).<Br>

Please note that the minimum amount to transfer MXN is 50 MXN. <br>

**Definition**<br>
`POST` https://api.sendwyre.com/v2/transfers <br><br>

```json
{
    "source":"account:AC-0000000000",
    "dest":
    {
    "paymentMethodType":"INTERNATIONAL_TRANSFER",
    "paymentType":"LOCAL_BANK_TRANSFER",
    "firstNameOnAccount":"Veronica",
    "lastNameOnAccount":"UB",
    "accountNumber":"0000000000",
    "clabe":"0000000000",
    "currency":"MXN",
    "country":"MX",
    "beneficiaryType":"INDIVIDUAL",    
    "nameOnAccount":"personal account"
    },
    "destAmount": 721.10,
    "destCurrency": "MXN",
    "sourceCurrency": "USD",
    "autoConfirm": true,
    "message": "MXN example"
}
```


**Mexico Requirements** <br>


Parameter | Description 
--------- | ----------- 
dest | object
dest.paymentMethodType | `INTERNATIONAL_TRANSFER`
dest.paymentType | `LOCAL_BANK_TRANSFER`
dest.beneficiaryType | `INDIVIDUAL` or `CORPORATE`
dest.firstNameOnAccount | Required for Individual
dest.lastNameOnAccount | Required for Individual
dest.beneficiaryName | Required for Business
dest.accountNumber | Beneficiary account number
dest.clabe | 18-digit SPEI account number
dest.currency | MXN
dest.country | MX
dest.nameOnAccount | Beneficiary name
destAmount | Amount to be deposited to the dest - the amount debited from your account will be calculated automatically from the exchange rate/fees.
destCurrency | Currency to be deposited to the dest. If destCurrency doesn't match the sourceCurrency an exchange will be preformed
sourceCurrency | Currency to be debited from your account

**Delivery Times**

Triggers a SPEI + DEBIT CARD withdrawal from your account. These withdrawals are immediate during banking hours for some banks (M-F 9:00AM - 5:00PM Mexico City Time), 24 hours for others.

## USA

USD payouts are initiated from one of our banks that corresponds to the country delivered. Please note that the minimum amount to transfer USD is $5.00. 

**Definition**<br>
`POST` https://api.sendwyre.com/v2/transfers <br> <br>

```json
{
  "dest": {
    "paymentMethodType":"INTERNATIONAL_TRANSFER",
    "country": "US",
    "currency": "USD",
    "beneficiaryType": "INDIVIDUAL",
    "beneficiaryAddress": "112 Brannan St",
    "beneficiaryAddress2": "", //Optional
    "beneficiaryCity": "San Francisco",
    "beneficiaryState": "CA",
    "beneficiaryPostal": "94108",
    "beneficiaryPhoneNumber": "+14102239203",
    "beneficiaryDobDay": "15",
    "beneficiaryDobMonth":"12",
    "beneficiaryDobYear":"1989",
    "paymentType" : "LOCAL_BANK_WIRE",
    "firstNameOnAccount": "Billy-Bob",
    "lastNameOnAccount":"Jones",
    "accountNumber": "0000000000000",
    "routingNumber": "0000000000",
    "accountType": "CHECKING", // CHECKING or SAVINGS
    "bankName": "Bank of America"
  },
  "sourceCurrency": "BRL",
  "destCurrency": "USD",
  "destAmount": 10,
  "message":"USD Personal example"
}
```

**US Requirements**


Parameter | Description 
--------- | ----------- 
dest | object
dest.paymentMethodType | `INTERNATIONAL_TRANSFER`
dest.country | US
dest.currency | USD
dest.beneficiaryType | `INDIVIDUAL` or `CORPORATE`
dest.beneficiaryPhoneNumber | Required for Individual
dest.beneficiaryLandlineNumber | Required for Business
dest.beneficiaryEinTin | Required for Business
dest.beneficiaryEmailAddress | Required for Business
dest.beneficiaryCompanyName | Required for Business
dest.firstNameOnAccount | Beneficiary's first name
dest.lastNameOnAccount | Beneficiary's last name
dest.accountNumber | Beneficiary account number
dest.routingNumber | Beneficiary routing number
dest.accountType | `CHECKING` or `SAVINGS`
destAmount | Amount to be deposited to the dest - the amount debited from your account will be calculated automatically from the exchange rate/fees.
destCurrency | Currency to be deposited to the dest. If destCurrency doesn't match the sourceCurrency an exchange will be performed
sourceCurrency | Currency to be debited from your account

**Delivery Times** <br>
Bank cut-off time is 12PM PST<br>
If we receive the payment instruction on the day before 12PM, the payment will be credited to beneficiary the next business day.-If we receive the payment instruction after 12PM, it will be credited to beneficiary next business day +1.<br>


