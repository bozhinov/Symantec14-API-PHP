<?php 

# Save few clicks when having to add multiple admin accounts

include("SEPM14API.php");

# AUTH
$api = new SEPM14APIv1("127.0.0.1");
$api->authenticate("admin", 'XXXX');

# ADMINS
$admins = [
	# Names, E-Mail Address, User name
	["Admin Name 1", "admin1@email.com", "ADMIN1"],
	["Admin Name 2", "admin2@email.com", "ADMIN2"]
];

# ADD
foreach($admins as $admin){
	
	$params = [
		"fullName" => $admin[0],
		"emailAddress" => $admin[1],
		"loginAttemptThreshold" => 5,
		"lockTimeThreshold" => 15,
		"loginName" => $admin[2],
		"password" => "XXXXX",
		"adminType" => 3,
		"authenticationMethod" => 2
	];

	$api->call("/sepm/api/v1/admin-users", "POST", $params);

}

?>