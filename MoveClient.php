<?php 

# Requires SEPM version 14.0.2349.0100 or newer

include("SEPM14API.php");

# AUTH
$api = new SEPM14APIv1("127.0.0.1");
$api->authenticate("admin", 'XXXX');

# MOVE
$hwkeys = explode("\r\n", file_get_contents("hardwareKeys_of_machines_to_be_moved.txt"));

foreach($hwkeys as $hwkey){

	$api->call("/computers", "PATCH", [[
		"group" => ["id" => "HEXHEXHEXHEXHEXHEXHEX"], # Select the group -> right click -> Properties
		"hardwareKey" => $hwkey
	]]);

}

?>