This class allows to interact with a YunoHost server in PHP using the API.

For the full list of functions available in the API, see [this list of functions](https://github.com/YunoHost/yunohost/blob/1ceb1259bc5f65cc94ce7447aa71117f9ad33dd2/data/actionsmap/yunohost.yml)

The code was inspired by [CpuID's Proxmox 2.0 API Client for PHP](https://github.com/CpuID/pve2-api-php-client)

## Requirements: ##

PHP 5 with cURL (including SSL) support.

## Usage: ##

Example - Return the list of users

    require("ynh_api.class.php");
	$ynh = new YNH_API("YunoHost server IP or hostname", "admin password");

    if ($ynh->login()) {
        $users = $ynh->get("/users");
		print_r($users);
    } else {
        print("Login to YunoHost failed.\n");
        exit;
    }

Example - Create a new user in the first domain found

    require("ynh_api.class.php");
	$ynh = new YNH_API("YunoHost server IP or hostname", "admin password");

    if ($ynh->login()) {
		$domains = $ynh->get("/domains");
		$first_domain = $domains['domains'][0];
	
		$arguments = array(
			'username' => 'test',
			'password' => 'yunohost', 
			'firstname' => 'Firstname',
			'lastname' => 'Lastname',
			'mail' => 'test@'.$first_domain,
			'mailbox_quota' => '500M'
		);
		
		$user_add = $ynh->post("/users", $arguments);
		print_r($user_add);
		
    } else {
        print("Login to YunoHost failed.\n");
        exit;
    }
	
Example - Install the Roundcube app in the first domain found.

    require("ynh_api.class.php");
	$ynh = new YNH_API("YunoHost server IP or hostname", "admin password");

    if ($ynh->login()) {
		$domains = $ynh->get("/domains");
		$first_domain = $domains['domains'][0];
	
		$arguments = array(
			'app' => 'roundcube',
			'label' => 'Mail', 
			'args' => http_build_query(array(
				'domain' => $first_domain,
				'path' => '/mail'
				))
		);
		$app_add = $ynh->post("/apps", $arguments);
		print_r($app_add);
		
    } else {
        print("Login to YunoHost failed.\n");
        exit;
    }

**The errors are sent directly to Apache error.log file.**
	
Licensed under the GNU AFFERO General Public License.
See LICENSE file.
