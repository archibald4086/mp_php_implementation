<?php
  require_once __DIR__ . '/vendor/autoload.php';

  use Gamegos\JWS\Util\Json;
  use Gamegos\JWS\Util\Base64Url;
  use Gamegos\JWS\Algorithm\RSA_SSA_PKCSv15;

  /**
   * @param string $endpoint requested endpoint of the MobilePay API
   * @param string $requestBody JSON encoded request body or empty string if no request body is provided
   * @param string $privateKey your merchant private key
   *
   * @return string token string with signature to send via AuthenticationSignature header
   */
  function createTokenString($endpoint, $requestBody, $privateKey)
  {
    $payload = utf8_encode($endpoint . $requestBody);
    $payload = sha1($payload, true);
    $payload = base64_encode($payload);

    $headers = ['alg' => 'RS256', 'typ' => 'JWT'];
    $headerComponent  = Base64Url::encode(Json::encode($headers));
    $payloadComponent = Base64Url::encode($payload);
    $inputToSign = $headerComponent . '.' . $payloadComponent;

    $algorithm = new RSA_SSA_PKCSv15(OPENSSL_ALGO_SHA256);
    $signature = $algorithm->sign($privateKey, $inputToSign);
    return $inputToSign . '.' . Base64Url::encode($signature);
  }

  /**
   * Extracts private key from an .pfx file
   * @param string $pathToPfxFile path to the .pfx file
   * @param string $passPhrase pass phrase to read the key (if needed)
   *
   * @return string extracted private key
   * @throws Exception errors while trying to read the key
   */
  function extractPrivateKeyFromPfxFile($pathToPfxFile, $passPhrase = '')
  {
    if(!file_exists($pathToPfxFile))
    {
      throw new Exception('file "' . $pathToPfxFile . '" not found');
    }

    /** load contents from .pfx */
    $keyData = file_get_contents($pathToPfxFile);

    /**
     * extracting certificate components and save them in $certs
     */
    if(!openssl_pkcs12_read($keyData, $certs, $passPhrase) || !isset($certs['pkey']))
    {
      throw new Exception('could not parse key data from "' . $pathToPfxFile . '. Is it a real PFX file or is a pass phrase missing ?');
    }

    return $certs['pkey'];
  }

  /**
   * example for payment status request
   * @see https://github.com/MobilePayDev/MobilePay-AppSwitch-API/blob/master/REST%20APIs/v1/payment%20status%20interface%20description.md
   */
  $endpoint = 'https://api.mobeco.dk/appswitch/api/v1/merchants/<your_merchant_id>/orders/<your_order_id>';
  $requestBody = '';
  $privateKey = extractPrivateKeyFromPfxFile('path_to_your_merchant_private_key.pfx');
  $tokenString = createTokenString($endpoint, $requestBody, $privateKey);

  echo $tokenString . "\n\n";
