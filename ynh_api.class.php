<?php
/*
	PHP class to interact with YunoHost API.
	YunoHost: https://yunohost.org/
	The code was inspired by CpuID's Proxmox 2.0 API Client for PHP: https://github.com/CpuID/pve2-api-php-client

	Copyright (c) 2016 scith https://github.com/scith
	Licensed under the GNU AFFERO General Public License. See LICENCE file.
*/

class YNH_Exception extends RuntimeException {}

class YNH_API {
	protected $host;
	protected $admin_password;
	protected $verify_ssl;
	protected $login_cookie = null;

	public function __construct ($host, $admin_password, $verify_ssl = false) {
		if (empty($host) || empty($admin_password)) {
			throw new YNH_Exception("Host/Admin Password required for YNH_API object constructor.", 1);
		}
		// Check hostname resolves.
		/*if (gethostbyname($host) == $host && !filter_var($host, FILTER_VALIDATE_IP)) {
			throw new YNH_Exception("Cannot resolve {$host}.", 2);
		}*/
		
		// Check that verify_ssl is boolean.
		if (!is_bool($verify_ssl)) {
			throw new YNH_Exception("verify_ssl must be boolean.", 7);
		}

		$this->host   			= $host;
		$this->admin_password   = $admin_password;
		$this->verify_ssl = $verify_ssl;
	}

	/*
	 * bool login ()
	 * Performs login to YNH Server using JSON API, and obtains Access Cookie.
	 */
	public function login () {

		// Perform login request.
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->verify_ssl); // Accepts all CAs (verify=false) or not
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->verify_ssl);
		curl_setopt($ch, CURLOPT_URL, 'https://'.$this->host.'/yunohost/api/login');
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
		curl_setopt($ch, CURLOPT_POSTFIELDS, 'password='.$this->admin_password);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_HEADER, true);
		
		$login = curl_exec($ch);
		$login_info = curl_getinfo($ch);
		
		curl_close($ch);
		unset($ch);
		
		preg_match_all('|Set-Cookie: (.*);|U', $login, $matches);   
		$cookies = implode('; ', $matches[1]);

		if (!$cookies) {
			throw new YNH_Exception("Failed to log into YunoHost.", 3);
			return false;
		}
		else {
			$this->login_cookie = $cookies;
			return true;
		}
	}
	
	/*
	 * object action (string action_path, string http_method[, array put_post_parameters])
	 * This method is responsible for the general cURL requests to the JSON API,
	 * and sits behind the abstraction layer methods get/put/post/delete etc.
	 */
	private function action ($action_path, $http_method, $put_post_parameters = null) {
		// Check if we have a prefixed / on the path, if not add one.
		if (substr($action_path, 0, 1) != "/") {
			$action_path = "/".$action_path;
		}

		// Check if logged in if action is not postinstall
		if (!$this->login_cookie && $action_path != '/postinstall') {
			throw new YNH_Exception("Not logged into YunoHost. No Login cookie found or cookie expired.", 3);
		}

		// Prepare cURL resource.
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, "https://{$this->host}/yunohost/api{$action_path}");
		
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->verify_ssl); // Accepts all CAs (verify=false) or not
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->verify_ssl);
		if ($action_path != '/postinstall') {
			curl_setopt($ch, CURLOPT_COOKIE, $this->login_cookie);
		}
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_HEADER, true); // Or true?

		// Lets decide what type of action we are taking...
		switch ($http_method) {
			case "GET":
				curl_setopt($ch, CURLOPT_HTTPGET, true);
				break;
			case "PUT":
				curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");

				// Set "POST" data.
				$action_postfields_string = http_build_query($put_post_parameters);
				curl_setopt($ch, CURLOPT_POSTFIELDS, $action_postfields_string);
				unset($action_postfields_string);
				break;
			case "POST":
				curl_setopt($ch, CURLOPT_POST, true);

				// Set POST data.
				//$action_postfields_string = http_build_query($put_post_parameters);
				curl_setopt($ch, CURLOPT_POSTFIELDS, $put_post_parameters);
				//unset($action_postfields_string);
				break;
			case "DELETE":
				curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
				// No "POST" data required, the delete destination is specified in the URL.
				break;
			default:
				throw new YNH_Exception("Error - Invalid HTTP Method specified.", 5);	
				return false;
		}

		$action_response = curl_exec($ch);
		$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
		
		curl_close($ch);
		unset($ch);

		$header_response = substr($action_response, 0, $header_size);
		$body_response = substr($action_response, $header_size);
		$action_response_array = json_decode($body_response, true);
		
		// Full Log
		/* $action_response_export = var_export($action_response_array, true);
		error_log("------" .
			"Headers:{$header_response} -----" .
			"Data:{$body_response} " .
			"------");

		unset($action_response);
		unset($action_response_export);*/

		// Parse response, confirm HTTP response code etc.
		if (substr($header_response, 0, 9) == "HTTP/1.1 ") {
			$http_response_line = explode(" ", $header_response);
			// If successful response, return response
			if ($http_response_line[1] == "200" OR $http_response_line[3] == "201") {
				if ($http_method == "PUT") {
					return true;
				} else {
					return $action_response_array;
				}
			} else {
				// Failed response
				error_log("API Request Failed: {$body_response}" .
					" / Request - {$header_response}");
				return $body_response; // Return error message
			}
		} else {
			error_log("Error - Invalid HTTP Response" . $header_response);
			return false;
		}
		
		if (!empty($action_response_array)) {
			return $action_response_array;
		} else {
			error_log("\$action_response_array is empty. Returning false.\n" . 
				var_export($action_response_array, true));
			return false;
		}
	}

	/*
	 * object/array? get (string action_path)
	 */
	public function get ($action_path) {
		return $this->action($action_path, "GET");
	}

	/*
	 * bool put (string action_path, array parameters)
	 */
	public function put ($action_path, $parameters) {
		return $this->action($action_path, "PUT", $parameters);
	}

	/*
	 * bool post (string action_path, array parameters)
	 */
	public function post ($action_path, $parameters) {
		return $this->action($action_path, "POST", $parameters);
	}

	/*
	 * bool delete (string action_path)
	 */
	public function delete ($action_path) {
		return $this->action($action_path, "DELETE");
	}

	// Logout not required? Cookie lifetime?
	
	/* Functions
		https://github.com/YunoHost/yunohost/blob/1ceb1259bc5f65cc94ce7447aa71117f9ad33dd2/data/actionsmap/yunohost.yml
		
	    domain              Manage domains
		monitor             Monitoring functions
		firewall            Manage firewall rules
		backup              Manage backups
		app                 Manage apps
		hook                Manage hooks
		dyndns              Subscribe and Update DynDNS Hosts
		user                Manage users
		tools               Specific tools
	*/
	
	/* User functions
		List users:				GET /users
		Create user:			POST /users    				array(username, firstname, lastname, mail, password, mailbox-quota)
		Delete user:			DELETE /users/<username>	array(username)
		Update user:			PUT /users/<username>		array(username, firstname, lastname, mail, change-password, add-mailforward, remove-mailforward, add-mailalias, remove-mailalias, mailbox-quota)
		Get user info:			GET /users/<username>		array(username)
	*/
	
	/* Domain functions
		List domains:			GET /domains
		Add domain:				POST /domains				array(domain, bool(dyndns))
		Remove domain:			DELETE /domains/<domain>	array(domain)
	*/
	
	/* App functions
		Installable apps:		GET /apps					array(limit, offset, filter, raw)		// Filter is app_id or app_name
		Installed apps:			GET /appsmap				array(app, raw, user)
		Install app:			POST /apps					array(app, label, http_build_query(array(APP ARGUMENTS) )
		Remove app:				DELETE /apps/<app>			array(app)
		Upgrade app(s):			PUT /upgrade/apps			array(app, url, file)
		Add access to app:		PUT /access					array(apps, users)
		Remove access to app:	DELETE /access				array(apps, users)
		Rest app access:		POST /access				array(apps)
	*/
	
	/* Administrator tools functions
		Change admin pass:		PUT /adminpw				array(new-password)
		Change main domain:		PUT /domains/main			array(old-domain, new-domain)
		Postinstall:			POST /postinstall			array(domain, password, bool(ignore-dyndns))		// No need to login
		Update YunoHost:		PUT /update					array(bool(ignore-apps), bool(ignore-packages))
		Upgrade YunoHost:		PUT /upgrade				array(bool(ignore-apps), bool(ignore-packages))
	*/
	
	/* Monitoring functions 
		Disk space and use:		GET /monitor/disk			array(filesystem, io, mountpoint, human-readable)
		Network interfaces:		GET /monitor/network		array(usage, infos, check, human-readable)
		System info:			GET /monitor/system			array(memory, cpu, process, uptime, infos, human-readable)
		Monitoring?
	*/
}
?>
