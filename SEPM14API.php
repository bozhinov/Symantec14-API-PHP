<?php

class SEPM14APIv1 {

	private $token = NULL;
	private $token_expiration = 0;
	private $client_secret;
	private $client_id;
	private $refresh_token;
	private $ip;
	private $api_server;
	private $counter;

	function __construct($ip = "127.0.0.1")
	{
		if (!filter_var($ip, FILTER_VALIDATE_IP) === false) {
			$this->api_server =  "https://".$ip.":8446/sepm/api/v1";
			$this->ip = $ip;
		} else {
			die("API error: invalid IP address for server");
		}
		$this->counter = 0;
	}

	public function call($api_method, $http_method = "GET", $data = NULL)
	{
		# C:\Program Files (x86)\Symantec\Symantec Endpoint Protection Manager\tomcat\etc\conf.properties
		# scm.web.service.rest.throttle.threshold=50
		# scm.web.service.rest.throttle.window.mins=1
		
		# Changing these should help bypass that limit and the need for that counter
		# Problem is I run 14.2.1031 (latest as of March 2019) and it does not work for me

		if ($this->counter == 49){
			$this->counter = 0;
			$timeNow = time();
			if (($this->token_expiration - $timeNow)  < 160) {
				echo "Token expired. Refreshing ..\r\n";
				$this->refreshToken();
			}
			echo "Waiting for 61 seconds..\r\n";
			sleep(61);
		} else {
			$this->counter++;
		}

		$header_array = ["Content-Type: application/json"];
		if ($this->token != NULL){
			$header_array[] = "Authorization: Bearer ".$this->token;
		}

		$ch = curl_init();

		switch ($http_method) {
			case "POST":
				curl_setopt($ch, CURLOPT_POST, true);
				curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
				break;
			case "PATCH":
				curl_setopt($ch, CURLOPT_HEADER,true);
				curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PATCH");
				curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
				break;
		}

		curl_setopt($ch, CURLOPT_URL, $this->api_server.$api_method);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); 
		curl_setopt($ch, CURLOPT_USERAGENT, "REST-API-CLIENT 1.0");
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $header_array);
		curl_setopt($ch, CURLOPT_VERBOSE, false);

		$response = curl_exec($ch);

		if(!curl_errno($ch))
		{
			$info = curl_getinfo($ch);
			# 207 - Multi-status - I get that when I PATCH/move machines
			if (!in_array($info["http_code"],[200,207])){
				$api_error_msg = $api_method." failed with code ".$info["http_code"];
			}
		} else {
			$http_error_msg = curl_error($ch);
		}

		curl_close($ch);

		if (isset($http_error_msg)){
			die('HTTP error: '.$http_error_msg);
		}

		if (isset($api_error_msg)){
			die('API error: '.$api_error_msg);
		}

		return json_decode($response, 1);
	}

	public function refreshToken()
	{
		$this->api_server_backup = $this->api_server;
		$this->api_server = "https://".$this->ip.":8446/sepm";

		$data = ["client_id" => $this->client_id, "client_secret" => $this->client_secret, "refresh_token" => $this->refresh_token];
		$auth_info = $this->call("/oauth/token?grant_type=refresh_token&client_id=".$this->client_id."&client_secret=".$this->client_secret."&refresh_token=".$this->refresh_token, "POST", $data);
		$this->refresh_token = $auth_info['refresh_token'];
		$this->token = $auth_info['access_token'];

		$this->api_server = $this->api_server_backup;
	}

	public function authenticate($user, $pass, $domain = "")
	{
		$this->counter = 0;
		$this->token = NULL;
		$auth_info = $this->call("/identity/authenticate", "POST", ["username"=>$user,"password"=>$pass,"domain"=>$domain]);
		$this->client_secret = $auth_info['clientSecret'];
		$this->client_id = $auth_info['clientId'];
		$this->refresh_token = $auth_info['refreshToken'];
		$this->token = $auth_info['token'];
		echo "Token: ".$this->token."\r\n";
		echo "Expires in: ".$auth_info['tokenExpiration']." seconds\r\n";
		$timeNow = time();
		$this->token_expiration = $timeNow + intval($auth_info['tokenExpiration']);
	}

}

?>