<?php

class SEPM14API {

	private $token = NULL;
	private $token_expiration = 0;
	private $auth = [];
	private $ip;
	private $port;
	private $api_server;
	private $counter = 0;

	public $throttle_enabled = true;
	public $throttle_threshold = 50;
	public $throttle_window = 1;

	function __construct($ip = "127.0.0.1", $port = "8446")
	{
		if (!filter_var($ip, FILTER_VALIDATE_IP) === false) {
			$this->api_server = "https://".$ip.":".$port."/sepm/api/v1";
			$this->ip = $ip;
			$this->port = $port;
		} else {
			die("API error: invalid IP address for server");
		}
	}

	function log($msg)
	{
		echo $msg."\r\n";
	}

	function wait()
	{
		if ($this->throttle_enabled){
			$this->log("Waiting for ".strval(($this->throttle_window * 60) + 1)." seconds..");
			sleep(($this->throttle_window * 60) + 1);
		}
	}

	public function call($api_method, $http_method = "GET", $data = NULL)
	{
		if ($this->counter == $this->throttle_threshold - 1){
			$this->counter = 0;
			$this->wait();
		} else {
			$this->counter++;
		}

		$timeNow = time();
		if (($this->token_expiration - $timeNow)  < 160) {
			$this->log("Token expired. Refreshing ..");
			$this->refreshToken();
			$this->wait();
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
			# 204 - Logout returns nothing
			if (!in_array($info["http_code"],[200,204,207])){
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
		$this->api_server = "https://".$this->ip.":".$this->port."/sepm";

		$data = ["client_id" => $this->auth['clientId'], "client_secret" => $this->auth['clientSecret'], "refresh_token" => $this->auth['refreshToken']];
		$refresh = $this->call("/oauth/token?grant_type=refresh_token&client_id=".$this->auth['clientId']."&client_secret=".$this->auth['clientSecret']."&refresh_token=".$this->auth['refreshToken'], "POST", $data);

		$timeNow = time();
		$this->token = $refresh['access_token'];
		$this->token_expiration = $timeNow + intval($refresh['tokenExpiration']);
		$this->log("Token: ".$this->token);
		$this->log("Expires in: ".$refresh['tokenExpiration']." seconds");	

		$this->api_server = $this->api_server_backup;
	}

	public function authenticate($user, $pass, $domain = "")
	{
		$this->counter = 0;
		$this->token = NULL;
		$this->auth = $this->call("/identity/authenticate", "POST", ["username" => $user, "password" => $pass, "domain" => $domain]);

		$timeNow = time();
		$this->token = $this->auth['token'];
		$this->token_expiration = $timeNow + intval($this->auth['tokenExpiration']);
		$this->log("Token: ".$this->token);
		$this->log("Expires in: ".$this->auth['tokenExpiration']." seconds");
	}

	public function logOut()
	{
		$this->call("/identity/logout", "POST", ["adminId" => $this->auth['adminId'], "token" => $this->token]);
	}

	/* cmd/php.exe would need to be elevated for this to work */
	public function autoConfig()
	{
		# is PHP x86 ?
		if (PHP_INT_SIZE === 4){
			$this->log("Autoconfig requires a x64 version of PHP");
			return;
		}

		try {
			$sepm_path = (new COM('WScript.Shell'))->regRead('HKEY_LOCAL_MACHINE\SOFTWARE\Symantec\InstalledApps\Reporting');
		} catch (com_exception $e){
			$this->log("Failed to obtain SEPM path from the registry");
			return;
		}

		$sepm_config = $sepm_path."\\tomcat\\etc\\conf.properties";

		if (!is_readable($sepm_config)){
			$this->log("conf.properties does not exist or is not readable");
			return;
		}

		$config = file($sepm_config, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

		$this->throttle_enabled = false;

		foreach($config as $line){

			list($cfg, $val) = explode("=", $line);

			switch($cfg){
				case "scm.web.service.rest.throttle.enabled":
					if (strtoupper($val) == "TRUE"){
						$this->log("Throttling is enabled");
						$this->throttle_enabled = true;
					}
					break;
				case "scm.web.service.rest.throttle.threshold":
					$this->log("Throttling threshold is: ".$val);
					$this->throttle_threshold = intval($val);
					break;
				case "scm.web.service.rest.throttle.window.mins":
					$this->log("Throttling window is: ".$val);
					$this->throttle_window = intval($val);
					break;
				case "scm.server.version":
					# API updates separatelly but anyway
					$this->log("SEPM version is: ".$val);
					if (version_compare($val, "14.2") >= 0){
						$this->log("SEPM version > 14.2 - OK. Good!");
					} else {
						$this->log("SEPM version < 14.2 - Not tested!");
					}
					break;
				case "scm.rmmwebservices.port":
					$this->log("REST service port is: ".$val);
					$this->port = $val;
					break;
			}
		}
	}

}

?>