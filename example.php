<?php
  require_once __DIR__ . '/vendor/autoload.php';

  use Firebase\JWT\JWT;

  $certs = array();

  /** load contents from .pfx */
  $keyData = file_get_contents('path_to_my_private_key.pfx');

 /**
  * extracting certificate components and save them in $certs
  * if passphrase is needed, provide it as 3rd parameter
  */
  openssl_pkcs12_read($keyData, $certs, '');
  $privateKey = $certs['pkey'];

  $endpoint = 'https://api.mobeco.dk/appswitch/api/v1/merchants/my_merchant_id/orders/my_order_id';
  $requestBody = '';
  $payload = utf8_encode($endpoint . $requestBody);
  $payload = sha1($payload);
  $payload = base64_encode($payload);

  $signature = JWT::encode([$payload], $privateKey, 'RS256');
